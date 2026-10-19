// SPDX-License-Identifier: Apache-2.0

//! Disposable OpenSSH check for saved-style SOCKS5 and HTTP CONNECT routes.

use std::{
    env, fs,
    io::{self, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::Duration,
};

use scoplen_client_core::connection::{
    ConnectionPlan, ConnectionRoute, CredentialMaterial, HostKeyPresentation, HostKeyTrust,
    SshConnection, SshConnectionError, probe_host_key,
};
use scoplen_crypto::SecretVec;
use scoplen_ssh::{
    ClientError, HostKey, HostKeyVerificationError, ProxyError, ProxyTransportError,
};
use uuid::Uuid;

#[derive(Clone, Copy)]
enum ProxyKind {
    Socks5,
    HttpConnect,
}

#[derive(Clone, Copy)]
enum ProxyBehavior {
    Forward,
    Reject,
    Stall,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 || !["direct", "all"].contains(&args[1].as_str()) {
        return Err(
            "usage: ssh_proxy_route_smoke <direct|all> <OpenSSH-port> <user> <key-file>".into()
        );
    }
    let port = args[2].parse::<u16>()?;
    let key = fs::read(&args[4])?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        let direct = plan("127.0.0.1", port, &args[3], &key, ConnectionRoute::Direct);
        authenticated_command(&direct).await?;
        if args[1] == "all" {
            for kind in [ProxyKind::Socks5, ProxyKind::HttpConnect] {
                proxy_case(kind, ProxyBehavior::Forward, port, &args[3], &key).await?;
                proxy_case(kind, ProxyBehavior::Reject, port, &args[3], &key).await?;
                proxy_case(kind, ProxyBehavior::Stall, port, &args[3], &key).await?;
                untrusted_case(kind, port, &args[3], &key).await?;
            }
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    println!("direct and selected proxy route checks passed");
    Ok(())
}

fn plan(
    address: &str,
    port: u16,
    username: &str,
    key: &[u8],
    route: ConnectionRoute,
) -> ConnectionPlan {
    ConnectionPlan {
        profile_id: Uuid::nil(),
        host_id: Uuid::nil(),
        address: address.into(),
        port,
        username: username.into(),
        route,
        credential: CredentialMaterial::PrivateKey(SecretVec::new(key.to_vec())),
    }
}

async fn authenticated_command(plan: &ConnectionPlan) -> Result<(), Box<dyn std::error::Error>> {
    let expected = probe_host_key(plan).await?;
    let trust: HostKeyTrust = Arc::new(move |_: &str, key: &HostKey| {
        if HostKeyPresentation::from_host_key(key) == expected {
            Ok(())
        } else {
            Err(HostKeyVerificationError::Rejected("target host key changed".into()))
        }
    });
    let mut connection = SshConnection::connect(plan, Some(trust)).await?;
    connection.authenticate().await?;
    let mut session = connection.open_session().await?;
    let output = session.exec(b"printf scoplen-proxy-ok", None).await?;
    if output.stdout != b"scoplen-proxy-ok" || output.exit_status != Some(0) {
        return Err("proxied SSH command returned unexpected output".into());
    }
    connection.close().await?;
    Ok(())
}

async fn proxy_case(
    kind: ProxyKind,
    behavior: ProxyBehavior,
    target_port: u16,
    user: &str,
    key: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let (route, server) = start_proxy(
        kind,
        behavior,
        target_port,
        if matches!(behavior, ProxyBehavior::Forward) { 2 } else { 1 },
    )?;
    let plan = plan("target.example", target_port, user, key, route);
    if matches!(behavior, ProxyBehavior::Forward) {
        authenticated_command(&plan).await?;
    } else {
        let error = probe_host_key(&plan).await.err().ok_or("proxy failure accepted")?;
        let expected = match behavior {
            ProxyBehavior::Reject => matches!(
                error,
                SshConnectionError::Engine(ClientError::Proxy(ProxyTransportError::Proxy(
                    ProxyError::Rejected { .. }
                )))
            ),
            ProxyBehavior::Stall => matches!(
                error,
                SshConnectionError::Engine(ClientError::Proxy(ProxyTransportError::Proxy(
                    ProxyError::Io { kind: io::ErrorKind::TimedOut, .. }
                )))
            ),
            ProxyBehavior::Forward => unreachable!(),
        };
        if !expected {
            return Err(format!("unexpected proxy failure: {error}").into());
        }
    }
    server.join().map_err(|_| "proxy fixture thread panicked")??;
    Ok(())
}

async fn untrusted_case(
    kind: ProxyKind,
    target_port: u16,
    user: &str,
    key: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let (route, server) = start_proxy(kind, ProxyBehavior::Forward, target_port, 2)?;
    let plan = plan("target.example", target_port, user, key, route);
    let mut expected = probe_host_key(&plan).await?;
    expected.fingerprint.push('x');
    let trust: HostKeyTrust = Arc::new(move |_: &str, key: &HostKey| {
        if HostKeyPresentation::from_host_key(key) == expected {
            Ok(())
        } else {
            Err(HostKeyVerificationError::Rejected("target host key mismatch".into()))
        }
    });
    let error = SshConnection::connect(&plan, Some(trust))
        .await
        .err()
        .ok_or("mismatched host key accepted")?;
    if !matches!(error, SshConnectionError::Engine(ClientError::HostKey(_))) {
        return Err(format!("unexpected target trust failure: {error}").into());
    }
    server.join().map_err(|_| "proxy fixture thread panicked")??;
    Ok(())
}

type ProxyServer = thread::JoinHandle<io::Result<()>>;

fn start_proxy(
    kind: ProxyKind,
    behavior: ProxyBehavior,
    target_port: u16,
    connections: usize,
) -> io::Result<(ConnectionRoute, ProxyServer)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = format!("127.0.0.1:{}", listener.local_addr()?.port());
    let route = match kind {
        ProxyKind::Socks5 => ConnectionRoute::Socks5 { proxy: endpoint, credential: None },
        ProxyKind::HttpConnect => {
            ConnectionRoute::HttpConnect { proxy: endpoint, credential: None }
        }
    };
    let server = thread::spawn(move || {
        for _ in 0..connections {
            let (mut client, _) = listener.accept()?;
            client.set_read_timeout(Some(Duration::from_secs(15)))?;
            match kind {
                ProxyKind::Socks5 => socks_handshake(&mut client, target_port, behavior)?,
                ProxyKind::HttpConnect => http_handshake(&mut client, target_port, behavior)?,
            }
            match behavior {
                ProxyBehavior::Forward => relay(client, target_port)?,
                ProxyBehavior::Reject => {}
                ProxyBehavior::Stall => {
                    let mut byte = [0];
                    if client.read(&mut byte)? != 0 {
                        return Err(io::Error::other("stalled proxy was not disconnected"));
                    }
                }
            }
        }
        Ok(())
    });
    Ok((route, server))
}

fn socks_handshake(
    client: &mut TcpStream,
    target_port: u16,
    behavior: ProxyBehavior,
) -> io::Result<()> {
    let mut greeting = [0; 3];
    client.read_exact(&mut greeting)?;
    if greeting != [5, 1, 0] {
        return Err(io::Error::other("unexpected SOCKS greeting"));
    }
    client.write_all(&[5, 0])?;
    let mut request = [0; 5];
    client.read_exact(&mut request)?;
    if request[..4] != [5, 1, 0, 3] {
        return Err(io::Error::other("unexpected SOCKS request"));
    }
    let mut target = vec![0; usize::from(request[4]) + 2];
    client.read_exact(&mut target)?;
    if &target[..target.len() - 2] != b"target.example"
        || u16::from_be_bytes([target[target.len() - 2], target[target.len() - 1]]) != target_port
    {
        return Err(io::Error::other("SOCKS target changed"));
    }
    if matches!(behavior, ProxyBehavior::Reject) {
        client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])?;
    } else if matches!(behavior, ProxyBehavior::Forward) {
        client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
    }
    Ok(())
}

fn http_handshake(
    client: &mut TcpStream,
    target_port: u16,
    behavior: ProxyBehavior,
) -> io::Result<()> {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") && request.len() < 8192 {
        let mut byte = [0];
        client.read_exact(&mut byte)?;
        request.push(byte[0]);
    }
    let expected = format!("CONNECT target.example:{target_port} HTTP/1.1\r\n");
    if !request.starts_with(expected.as_bytes()) || !request.ends_with(b"\r\n\r\n") {
        return Err(io::Error::other("unexpected HTTP CONNECT target"));
    }
    if matches!(behavior, ProxyBehavior::Reject) {
        client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")?;
    } else if matches!(behavior, ProxyBehavior::Forward) {
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    }
    Ok(())
}

fn relay(client: TcpStream, target_port: u16) -> io::Result<()> {
    let target = TcpStream::connect(("127.0.0.1", target_port))?;
    client.set_read_timeout(None)?;
    let mut client_read = client.try_clone()?;
    let mut target_write = target.try_clone()?;
    let upstream = thread::spawn(move || {
        let result = io::copy(&mut client_read, &mut target_write);
        let _ = target_write.shutdown(Shutdown::Write);
        result
    });
    let mut target_read = target;
    let mut client_write = client;
    let downstream = io::copy(&mut target_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Write);
    upstream.join().map_err(|_| io::Error::other("proxy relay thread panicked"))??;
    downstream?;
    Ok(())
}
