// SPDX-License-Identifier: Apache-2.0

//! Platform-protected device Credentials against disposable real OpenSSH.

use scoplen_client_core::{
    connection::{
        ConnectionPlanError, SshConnectionError,
        preparation::{
            PreparationControl, PreparationEvent, PreparationResponse, prepare_connection,
        },
        resolve_connection_plan,
    },
    inventory::{CredentialBindingInput, CredentialInput, CredentialKindInput, Inventory},
    repository::{
        AccessProfile, AccessProfileChange, Credential, Edit, Host, HostChange, Repository, Route,
        RouteChange, RouteChoice, RouteKind,
    },
    session_files::{SessionDownloadStatus, SessionUploadStatus},
    session_manager::{SessionEvent, SessionManager},
    store::Store,
};
use scoplen_crypto::LocalDatabaseKey;
use scoplen_ssh::ClientError;
use std::{collections::BTreeMap, fs, path::Path, sync::Arc, time::Duration};
use tokio::sync::mpsc;
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 3 {
        return Err("usage: ssh_device_key_smoke <create|direct|jump|refuse|rejected|missing|cleanup> <store> [direct-port jump-port internal-port]".into());
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()?
        .block_on(run(&args))
}

async fn run(args: &[String]) -> Result<()> {
    // This wrapping key belongs only to the disposable acceptance database.
    let store = Arc::new(Store::open(Path::new(&args[2]), &LocalDatabaseKey::new([73; 32]))?);
    match args[1].as_str() {
        "create" if args.len() == 6 => {
            create(&store, args[3].parse()?, args[4].parse()?, args[5].parse()?)
        }
        "direct" | "jump" => {
            let name = if args[1] == "jump" { "Device Jump target" } else { "Device Direct" };
            let profile = profile(&store, name)?;
            tokio::time::timeout(Duration::from_secs(40), session(store, profile)).await??;
            println!(
                "device key {}: reopened saved Login, shell, binary SFTP and reconnect passed",
                args[1]
            );
            Ok(())
        }
        "refuse" | "rejected" => {
            let profile = profile(&store, "Device Direct")?;
            let control = PreparationControl::default();
            let result = tokio::time::timeout(
                Duration::from_secs(15),
                prepare_connection(&store, profile, &control, |event| {
                    match event {
                        PreparationEvent::Trust { .. } if args[1] == "refuse" => {
                            control.cancel();
                        }
                        PreparationEvent::Trust { prompt_id, .. } => {
                            control.respond(&prompt_id, PreparationResponse::AcceptHostKey)?
                        }
                        PreparationEvent::Passphrase { .. } => {
                            return Err("device key requested a passphrase".into());
                        }
                        _ => {}
                    }
                    Ok(())
                }),
            )
            .await?;
            let expected = if args[1] == "refuse" {
                control.is_cancelled() && result.is_err()
            } else {
                matches!(
                    result,
                    Err(
                        scoplen_client_core::connection::preparation::PreparationError::Connection(
                            SshConnectionError::Engine(ClientError::AuthenticationRejected { .. })
                        )
                    )
                )
            };
            if expected {
                println!("device key {}: refused without a replacement credential", args[1]);
                Ok(())
            } else {
                Err("expected device-key refusal was not observed".into())
            }
        }
        "missing" => {
            let profile = profile(&store, "Device Direct")?;
            let credential =
                Repository::<AccessProfile>::new(&store).get(profile)?.unwrap().credential.unwrap();
            let local = store.device_credential(credential)?.ok_or("device credential missing")?;
            scoplen_client_platform::credentials::delete_device_key(
                store.data_dir(),
                credential,
                local.keystore_handle.as_deref().ok_or("platform handle missing")?,
            )?;
            assert_eq!(
                resolve_connection_plan(&store, profile),
                Err(ConnectionPlanError::CredentialUnavailable)
            );
            println!("device key missing: unavailable platform slot rejected during planning");
            Ok(())
        }
        "cleanup" => {
            for route in Repository::<Route>::new(&store).list()? {
                Repository::<Route>::new(&store).delete(route.meta.id)?;
            }
            for profile in Repository::<AccessProfile>::new(&store).list()? {
                Repository::<AccessProfile>::new(&store).delete(profile.meta.id)?;
            }
            let inventory = Inventory::new(store.clone());
            for credential in Repository::<Credential>::new(&store).list()? {
                inventory.delete_credential(credential.meta.id.to_string())?;
            }
            println!("owned device key slots removed");
            Ok(())
        }
        _ => Err("unsupported device-key acceptance mode".into()),
    }
}

fn create(store: &Arc<Store>, direct: u16, jump: u16, internal: u16) -> Result<()> {
    if !Repository::<Host>::new(store).list()?.is_empty() {
        return Err("device-key acceptance store is already initialized".into());
    }
    let inventory = Inventory::new(store.clone());
    let mut credentials = Vec::new();
    for name in ["Device target key", "Device Jump key"] {
        let credential = inventory.create_credential(CredentialInput {
            name: Some(name.into()),
            kind: CredentialKindInput::DeviceKey,
            binding: CredentialBindingInput::Device,
            secret: None,
            device_secret: None,
            public_key: None,
            provider: BTreeMap::new(),
            certificate_scope: None,
        })?;
        println!("{}", credential.public_key.as_deref().ok_or("device public key missing")?);
        credentials.push(Uuid::parse_str(&credential.id)?);
    }
    let hop = login(store, "Device Jump", jump, credentials[1])?;
    login(store, "Device Direct", direct, credentials[0])?;
    let target = login(store, "Device Jump target", internal, credentials[0])?;
    let route = Repository::<Route>::new(store).create(RouteChange {
        name: Some("Device Jump route".into()),
        kind: Some(RouteKind::Jump { hops: vec![hop] }),
    })?;
    Repository::<AccessProfile>::new(store).update(
        target,
        AccessProfileChange {
            route: Some(RouteChoice::Route(route.meta.id)),
            ..Default::default()
        },
    )?;
    Ok(())
}

fn login(store: &Store, name: &str, port: u16, credential: Uuid) -> Result<Uuid> {
    let host = Repository::<Host>::new(store).create(HostChange {
        name: Some(name.into()),
        address: Some("127.0.0.1".into()),
        port: Edit::Set(port),
        ..Default::default()
    })?;
    Ok(Repository::<AccessProfile>::new(store)
        .create(AccessProfileChange {
            host: Some(host.meta.id),
            username: Some("smoke".into()),
            credential: Edit::Set(credential),
            ..Default::default()
        })?
        .meta
        .id)
}

fn profile(store: &Store, name: &str) -> Result<Uuid> {
    let host = Repository::<Host>::new(store)
        .list()?
        .into_iter()
        .find(|host| host.name == name)
        .ok_or("saved Host missing")?;
    Ok(Repository::<AccessProfile>::new(store)
        .list()?
        .into_iter()
        .find(|profile| profile.host == host.meta.id)
        .ok_or("saved Login missing")?
        .meta
        .id)
}

async fn ready(events: &mut mpsc::UnboundedReceiver<SessionEvent>) -> Result<String> {
    loop {
        match events.recv().await.ok_or("session events ended")? {
            SessionEvent::Ready { transport_id } => return Ok(transport_id),
            SessionEvent::Failed { error, .. } => return Err(error.into()),
            _ => {}
        }
    }
}

async fn session(store: Arc<Store>, profile: Uuid) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let manager = SessionManager::default();
    manager.reserve("terminal", true)?;
    let (send, mut events) = mpsc::unbounded_channel();
    let (output, mut chunks) = mpsc::unbounded_channel();
    let profile = profile.to_string();
    let terminal = Box::pin(manager.run(
        "terminal",
        &profile,
        None,
        true,
        store,
        |event| {
            if let SessionEvent::Preparation { transport_id, event } = &event {
                match event.as_ref() {
                    PreparationEvent::Trust { prompt_id, .. } => manager.respond(
                        "terminal",
                        transport_id,
                        prompt_id,
                        PreparationResponse::AcceptHostKey,
                    )?,
                    PreparationEvent::Passphrase { .. } => {
                        return Err("device key requested a passphrase".into());
                    }
                    _ => {}
                }
            }
            send.send(event).map_err(|_| "session event receiver ended".into())
        },
        |_, bytes| output.send(bytes).map_err(|_| "output receiver ended".into()),
        |_, _| {},
    ));
    let exercise = async {
        let first = ready(&mut events).await?;
        shell(&manager, &first, &mut chunks).await?;
        files(&manager, &first, directory.path()).await?;
        manager.stop("terminal")?;
        loop {
            if matches!(events.recv().await.ok_or("session events ended")?, SessionEvent::Closed) {
                break;
            }
        }
        assert!(manager.input("terminal", &first, b"stale".to_vec()).is_err());
        manager.retry("terminal")?;
        let next = ready(&mut events).await?;
        assert_ne!(first, next);
        shell(&manager, &next, &mut chunks).await?;
        manager.close_all()?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    let (terminal, exercise) = tokio::join!(terminal, exercise);
    exercise?;
    terminal?;
    Ok(())
}

async fn shell(
    manager: &SessionManager,
    transport: &str,
    chunks: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<()> {
    while chunks.try_recv().is_ok() {}
    manager.input("terminal", transport, b"printf '\\nscoplen-device-%s\\n' key-ok\n".to_vec())?;
    let mut output = Vec::new();
    loop {
        output.extend(chunks.recv().await.ok_or("terminal output ended")?);
        if output
            .windows(b"scoplen-device-key-ok".len())
            .any(|value| value == b"scoplen-device-key-ok")
        {
            return Ok(());
        }
        if output.len() > 64 * 1024 {
            return Err("terminal output exceeded acceptance bound".into());
        }
    }
}

async fn files(manager: &SessionManager, transport: &str, directory: &Path) -> Result<()> {
    let source = directory.join(format!("device-{}.bin", Uuid::now_v7()));
    let expected: Vec<u8> = (0..=255).cycle().take(8192).collect();
    fs::write(&source, &expected)?;
    let upload = manager
        .upload_file_with_picker(
            "terminal",
            transport,
            &Uuid::now_v7().to_string(),
            b".".to_vec(),
            || async { Ok(Some(source.clone())) },
            |_| async { Err("fresh fixture must not overwrite".into()) },
            |_| {},
        )
        .await?;
    assert_eq!(upload.status, SessionUploadStatus::Saved);
    let remote = manager
        .list_files("terminal", transport, &Uuid::now_v7().to_string(), b".".to_vec())
        .await?
        .entries
        .into_iter()
        .find(|entry| entry.name == source.file_name().unwrap().to_str().unwrap())
        .ok_or("uploaded binary missing")?
        .path;
    let destination = directory.join("download.bin");
    let download = manager
        .download_file_with_picker(
            "terminal",
            transport,
            &Uuid::now_v7().to_string(),
            remote,
            || async { Ok(Some(destination.clone())) },
            |_| {},
        )
        .await?;
    assert_eq!(download.status, SessionDownloadStatus::Saved);
    assert_eq!(fs::read(destination)?, expected);
    Ok(())
}
