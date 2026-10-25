// SPDX-License-Identifier: Apache-2.0

use super::*;
use scoplen_ssh::{SocksAddress, SocksBindAddress, SocksHandshake};
use tokio::time::Instant;

pub(super) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

pub(super) struct NegotiatedPeer {
    lease: PeerLease,
    socket: TcpStream,
    origin: SocketAddr,
    handshake: SocksHandshake,
    target: String,
    port: u16,
    trailing: Vec<u8>,
}

pub(super) async fn negotiate(
    lease: PeerLease,
    mut socket: TcpStream,
    origin: SocketAddr,
    deadline: Instant,
) -> Result<NegotiatedPeer, ForwardIssue> {
    // Negotiation owns no SSH reference: the run can still observe an idle transport loss.
    tokio::time::timeout_at(deadline, async {
        let mut handshake = SocksHandshake::new();
        let mut buffer = vec![0; COPY_BUFFER];
        loop {
            let read = socket.read(&mut buffer).await.map_err(|_| ForwardIssue::PeerIo)?;
            if read == 0 {
                return Err(ForwardIssue::HandshakeRejected);
            }
            let progress =
                handshake.feed(&buffer[..read]).map_err(|_| ForwardIssue::HandshakeRejected)?;
            socket.write_all(&progress.response).await.map_err(|_| ForwardIssue::PeerIo)?;
            if progress.done {
                return Err(ForwardIssue::HandshakeRejected);
            }
            let Some(request) = progress.request else { continue };
            let target = match request.address {
                SocksAddress::Ipv4(address) => Some(std::net::Ipv4Addr::from(address).to_string()),
                SocksAddress::Ipv6(address) => Some(std::net::Ipv6Addr::from(address).to_string()),
                SocksAddress::Domain(domain) => String::from_utf8(domain).ok(),
            };
            if let Some(target) = target
                && request.port != 0
            {
                return Ok(NegotiatedPeer {
                    lease,
                    socket,
                    origin,
                    handshake,
                    target,
                    port: request.port,
                    trailing: progress.trailing,
                });
            }
            let response = handshake
                .reject(SocksReply::ConnectionNotAllowed)
                .map_err(|_| ForwardIssue::HandshakeRejected)?;
            socket.write_all(&response).await.map_err(|_| ForwardIssue::PeerIo)?;
            return Err(ForwardIssue::HandshakeRejected);
        }
    })
    .await
    .map_err(|_| ForwardIssue::HandshakeTimedOut)?
}

pub(super) async fn forward(
    peer: NegotiatedPeer,
    connection: Arc<SshConnection>,
) -> Result<(), ForwardIssue> {
    let NegotiatedPeer { lease, mut socket, origin, mut handshake, target, port, trailing } = peer;
    let run = &lease.0;
    if *run.stop.borrow() {
        return Ok(());
    }
    let opened = open_channel(&connection, &target, port, origin).await;
    drop(connection);
    if *run.stop.borrow() {
        return Ok(());
    }
    let channel = match opened {
        Ok(channel) => channel,
        Err(failure) => {
            if failure.issue == ForwardIssue::ConnectionLost {
                return Err(failure.issue);
            }
            let response =
                handshake.reject(failure.reply).map_err(|_| ForwardIssue::HandshakeRejected)?;
            write_response(&mut socket, &response).await?;
            return Err(failure.issue);
        }
    };
    let bound = SocksBindAddress::new(SocksAddress::Ipv4([0; 4]), 0)
        .map_err(|_| ForwardIssue::HandshakeRejected)?;
    let response = handshake.accept(&bound).map_err(|_| ForwardIssue::HandshakeRejected)?;
    write_response(&mut socket, &response).await?;
    copy_peer(run, socket, channel, trailing).await
}

async fn write_response(socket: &mut TcpStream, response: &[u8]) -> Result<(), ForwardIssue> {
    tokio::time::timeout(RESPONSE_TIMEOUT, socket.write_all(response))
        .await
        .map_err(|_| ForwardIssue::PeerIo)?
        .map_err(|_| ForwardIssue::PeerIo)
}
