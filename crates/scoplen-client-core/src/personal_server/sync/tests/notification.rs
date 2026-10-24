// SPDX-License-Identifier: Apache-2.0
//! Public native runtime against an independent TLS 1.3/H2/WebSocket peer.

use std::collections::VecDeque;

use futures_util::{SinkExt as _, StreamExt as _};
use scoplen_api::sync::{
    SyncNotification, SyncNotificationAuth, SyncNotificationContext, SyncNotificationMethod,
    SyncNotificationReady,
};
use tokio::sync::broadcast;
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message,
        protocol::{
            CloseFrame, Role,
            frame::{
                Frame,
                coding::{CloseCode, Data, OpCode},
            },
        },
    },
};

use super::*;
use crate::{
    personal_inventory::PersonalInventorySettings,
    personal_server::{
        PersonalBackgroundStatus, PersonalSyncRuntime, notification::stream::H2Stream,
    },
    store::LocalWrite,
};
use scoplen_model::{FieldPath, ObjectType, cbor::Value};

#[derive(Clone, Debug)]
enum Action {
    Event(SyncNotification),
    Binary(Vec<u8>),
    Text(String),
    Frame(Frame),
    Close,
}

enum Opening {
    Healthy,
    Fragmented,
    Context(Vec<u8>),
    Ready(Vec<u8>),
    Silent,
}

pub(super) struct NotificationPeer {
    actions: broadcast::Sender<Action>,
    openings: VecDeque<Opening>,
    connections: usize,
    authenticated: usize,
    closes: Vec<u16>,
}

impl Default for NotificationPeer {
    fn default() -> Self {
        Self {
            actions: broadcast::channel(32).0,
            openings: VecDeque::new(),
            connections: 0,
            authenticated: 0,
            closes: vec![],
        }
    }
}

pub(super) async fn answer(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    state: &StdMutex<PeerState>,
    origin: &str,
) -> Result<(), String> {
    let (opening, mut actions) = {
        let mut state = state.lock().unwrap();
        let Some(peer) = &mut state.notification else {
            respond
                .send_response(http::Response::builder().status(404).body(()).unwrap(), true)
                .map_err(|_| "404 response")?;
            return Ok(());
        };
        peer.connections += 1;
        (peer.openings.pop_front().unwrap_or(Opening::Healthy), peer.actions.subscribe())
    };
    if request.method() != http::Method::CONNECT
        || request.version() != http::Version::HTTP_2
        || request.uri().query().is_some()
        || request.extensions().get::<h2::ext::Protocol>().map(|p| p.as_str()) != Some("websocket")
        || ["authorization", "dpop", "cookie", "origin", "sec-websocket-key"]
            .iter()
            .any(|name| request.headers().contains_key(*name))
    {
        return Err("invalid notification opening or leaked credential".into());
    }
    let send = respond
        .send_response(http::Response::builder().status(200).body(()).unwrap(), false)
        .map_err(|_| "upgrade response")?;
    let mut socket = WebSocketStream::from_raw_socket(
        H2Stream::new(request.into_body(), send),
        Role::Server,
        None,
    )
    .await;
    let context = match &opening {
        Opening::Context(body) => body.clone(),
        _ => SyncNotificationContext { htm: SyncNotificationMethod::Connect }.to_cbor().unwrap(),
    };
    if matches!(opening, Opening::Silent) {
        if let Some(Ok(Message::Close(Some(close)))) = socket.next().await {
            state.lock().unwrap().notification.as_mut().unwrap().closes.push(close.code.into());
        }
        return Ok(());
    }
    if matches!(opening, Opening::Fragmented) {
        socket
            .send(Message::Frame(Frame::message(
                context[..1].to_vec(),
                OpCode::Data(Data::Binary),
                false,
            )))
            .await
            .map_err(|_| "context fragment")?;
        socket.send(Message::Ping(vec![1].into())).await.map_err(|_| "context ping")?;
        socket
            .send(Message::Frame(Frame::message(
                context[1..].to_vec(),
                OpCode::Data(Data::Continue),
                true,
            )))
            .await
            .map_err(|_| "context continuation")?;
    } else {
        let _ = socket.send(Message::Binary(context.into())).await;
    }
    let auth = loop {
        match socket.next().await {
            Some(Ok(Message::Binary(body))) => {
                break SyncNotificationAuth::from_cbor(&body)
                    .map_err(|_| "invalid notification auth")?;
            }
            Some(Ok(Message::Pong(_))) => {}
            Some(Ok(Message::Close(close))) => {
                if let Some(close) = close {
                    state
                        .lock()
                        .unwrap()
                        .notification
                        .as_mut()
                        .unwrap()
                        .closes
                        .push(close.code.into());
                }
                return Ok(());
            }
            _ => return Ok(()),
        }
    };
    {
        let mut state = state.lock().unwrap();
        let expected = state.expected.as_ref().ok_or("missing notification identity")?;
        if auth.access_token != expected.token.as_str() {
            return Err("wrong notification token".into());
        }
        let target = DpopTarget::new("CONNECT", origin, "/sync/v1/notify").unwrap();
        let proof = DpopProof::parse(&auth.dpop_proof)
            .map_err(|_| "invalid notification proof")?
            .verify(
                &target,
                DpopToken::Protected(&auth.access_token),
                &expected.jkt,
                now().unwrap(),
                None,
            )
            .map_err(|_| "wrong notification proof binding")?;
        if !state.proofs.insert(proof.jti) {
            return Err("replayed notification proof".into());
        }
        state.notification.as_mut().unwrap().authenticated += 1;
    }
    let ready = match opening {
        Opening::Ready(body) => body,
        _ => SyncNotificationReady.to_cbor().unwrap(),
    };
    if socket.send(Message::Binary(ready.into())).await.is_err() {
        return Ok(());
    }
    loop {
        tokio::select! {
            action = actions.recv() => {
                let message = match action {
                    Ok(Action::Event(event)) => Message::Binary(event.to_cbor().unwrap().into()),
                    Ok(Action::Binary(body)) => Message::Binary(body.into()),
                    Ok(Action::Text(body)) => Message::Text(body.into()),
                    Ok(Action::Frame(frame)) => Message::Frame(frame),
                    Ok(Action::Close) => Message::Close(Some(CloseFrame { code: CloseCode::Policy, reason: "".into() })),
                    Err(_) => return Ok(()),
                };
                if socket.send(message).await.is_err() { return Ok(()); }
            }
            message = socket.next() => match message {
                Some(Ok(Message::Ping(_))) => { let _ = socket.flush().await; }
                Some(Ok(Message::Close(close))) => {
                    if let Some(close) = close { state.lock().unwrap().notification.as_mut().unwrap().closes.push(close.code.into()); }
                    return Ok(());
                }
                Some(Ok(Message::Pong(_))) => {},
                Some(Ok(_)) => return Err("unexpected second application message".into()),
                _ => return Ok(()),
            }
        }
    }
}

struct Running {
    runtime: Arc<PersonalSyncRuntime>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.runtime.shutdown();
        self.task.abort();
    }
}

fn start(manager: PersonalServer, store: Arc<Store>) -> Running {
    start_shared(Arc::new(manager), store)
}

fn start_shared(manager: Arc<PersonalServer>, store: Arc<Store>) -> Running {
    let runtime = Arc::new(PersonalSyncRuntime::default());
    runtime.set_store(Some(store));
    let owner = runtime.clone();
    let task = tokio::spawn(async move { owner.run(&manager).await });
    Running { runtime, task }
}

async fn wait(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("bounded background progress");
}

fn send(peer: &Peer, action: Action) {
    peer.state.lock().unwrap().notification.as_ref().unwrap().actions.send(action).unwrap();
}
fn count(peer: &Peer) -> usize {
    peer.state.lock().unwrap().inventory.as_ref().unwrap().queries.len()
}

async fn prepare(peer: &Peer, store: &Arc<Store>) -> PersonalServer {
    let manager = peer.prepare(store).await;
    peer.state.lock().unwrap().inventory = Some(InventoryPeer::default());
    peer.state.lock().unwrap().notification = Some(NotificationPeer::default());
    manager.bootstrap_sync(store.clone()).await.unwrap();
    manager
}

#[tokio::test]
async fn runtime_starts_without_settings_catches_up_and_syncs_only_adopted_edits() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = prepare(&peer, &store).await;
    let settings = PersonalInventorySettings::default();
    let host = inventory::make_host(&store);
    let preview = settings.preview(&store, vec![host.id.to_string()]).unwrap();
    // A queued confirmed review survives a background operation at the shared boundary.
    {
        let lock = manager.operation.lock().await;
        let synchronize = settings.synchronize(&manager, store.clone(), preview.token);
        tokio::pin!(synchronize);
        assert!(tokio::time::timeout(Duration::from_millis(10), &mut synchronize).await.is_err());
        drop(lock);
        synchronize.await.unwrap();
    }
    let unrelated = inventory::make_host(&store);
    let before_start = count(&peer);
    let running = start(manager, store.clone());
    wait(|| {
        running.runtime.status() == PersonalBackgroundStatus::Connected
            && count(&peer) > before_start
    })
    .await;
    let baseline = count(&peer);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(count(&peer), baseline, "own bootstrap and store signals settle");
    assert_eq!(peer.state.lock().unwrap().notification.as_ref().unwrap().connections, 1);
    let vault = record(&store).unwrap().personal_vault_id;
    send(
        &peer,
        Action::Event(SyncNotification::VaultAdvanced {
            vault: scoplen_model::new_uuid_v7().unwrap(),
            seq: 100,
        }),
    );
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(count(&peer), baseline, "foreign vault hints do not schedule work");
    let mut remote = host.clone();
    remote.id = scoplen_model::new_uuid_v7().unwrap();
    let change = inventory::change(&store, &remote, 9);
    {
        let mut state = peer.state.lock().unwrap();
        let inventory = state.inventory.as_mut().unwrap();
        inventory.seq = 9;
        inventory.objects.insert(remote.id, change);
    }
    for _ in 0..20 {
        send(&peer, Action::Event(SyncNotification::VaultAdvanced { vault, seq: 9 }));
    }
    wait(|| count(&peer) > baseline).await;
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(count(&peer), baseline + 1, "identical hints coalesce");
    assert_eq!(store.get(remote.id).unwrap(), Some(remote));
    assert_eq!(store.personal_sync_cursor(vault).unwrap(), 9);
    store
        .write(LocalWrite {
            id: Some(host.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(1), Value::Text("Background edit".into()))],
        })
        .unwrap();
    wait(|| store.pending_personal_objects(vault, 1).unwrap().is_empty()).await;
    assert_eq!(peer.state.lock().unwrap().inventory.as_ref().unwrap().writes, 2);
    assert!(
        settings
            .status(&store)
            .unwrap()
            .objects
            .iter()
            .any(|object| object.id == unrelated.id.to_string() && !object.personal)
    );
    peer.assert_healthy();
}

#[tokio::test]
async fn renewal_closes_old_socket_refreshes_once_and_reauthenticates_with_fresh_proof() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = prepare(&peer, &store).await;
    let running = start(manager, store.clone());
    wait(|| running.runtime.status() == PersonalBackgroundStatus::Connected && count(&peer) > 0)
        .await;
    tokio::time::sleep(Duration::from_millis(350)).await;
    let before = record(&store).unwrap();
    let baseline = count(&peer);
    super::refresh::install(&peer, &store, vec![]);
    // Cached expiry emits no store watch: only the existing socket renewal timer wakes it.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(541)).await;
    tokio::time::resume();
    wait(|| {
        peer.state.lock().unwrap().notification.as_ref().unwrap().authenticated == 2
            && count(&peer) > baseline
    })
    .await;
    let after = record(&store).unwrap();
    assert!(after.auth_generation > before.auth_generation);
    assert_eq!(after.refresh_expires_at, before.refresh_expires_at);
    assert_eq!(super::refresh::calls(&peer), 1);
    assert!(peer.state.lock().unwrap().notification.as_ref().unwrap().closes.contains(&1000));
    peer.assert_healthy();
}

#[tokio::test]
async fn replacement_and_shutdown_cancel_inflight_write_without_settling_old_outbox() {
    for shutdown in [false, true] {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        let manager = prepare(&peer, &store).await;
        let vault = record(&store).unwrap().personal_vault_id;
        let host = inventory::make_host(&store);
        store.adopt_personal_objects(vault, &[host.id]).unwrap();
        let reached = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        peer.state.lock().unwrap().pause =
            Some((format!("/sync/v1/vaults/{vault}/objects"), reached.clone(), resume.clone()));
        let running = start(manager, store.clone());
        tokio::time::timeout(Duration::from_secs(5), reached.notified()).await.unwrap();
        let replacement_dir = tempfile::tempdir().unwrap();
        let replacement = local(&replacement_dir);
        if shutdown {
            running.runtime.shutdown();
        } else {
            running.runtime.set_store(Some(replacement.clone()));
        }
        resume.notify_one();
        wait(|| running.runtime.status() == PersonalBackgroundStatus::Inactive).await;
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert_eq!(store.pending_personal_objects(vault, 1).unwrap().len(), 1);
        assert_eq!(store.personal_sync_cursor(vault).unwrap(), 7);
        assert!(replacement.list(ObjectType::HOST).unwrap().is_empty());
        let paths = peer.state.lock().unwrap().paths.clone();
        store.personal_changed();
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert_eq!(peer.state.lock().unwrap().paths, paths);
        if !shutdown {
            running.runtime.set_store(Some(store.clone()));
            wait(|| store.pending_personal_objects(vault, 1).unwrap().is_empty()).await;
            assert_eq!(
                peer.state.lock().unwrap().inventory.as_ref().unwrap().writes,
                1,
                "new run pulls committed outcome before writing"
            );
        }
        peer.assert_healthy();
    }
}

#[tokio::test]
async fn confirmed_adoption_and_hints_wait_for_actual_background_cycle() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = Arc::new(prepare(&peer, &store).await);
    let vault = record(&store).unwrap().personal_vault_id;
    let reached = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    peer.state.lock().unwrap().pause =
        Some((format!("/sync/v1/vaults/{vault}/changes"), reached.clone(), resume.clone()));
    let running = start_shared(manager.clone(), store.clone());
    tokio::time::timeout(Duration::from_secs(5), reached.notified()).await.unwrap();
    let host = inventory::make_host(&store);
    let settings = PersonalInventorySettings::default();
    let review = settings.preview(&store, vec![host.id.to_string()]).unwrap();
    let synchronize = settings.synchronize(&manager, store.clone(), review.token);
    tokio::pin!(synchronize);
    assert!(tokio::time::timeout(Duration::from_millis(20), &mut synchronize).await.is_err());
    send(&peer, Action::Event(SyncNotification::VaultAdvanced { vault, seq: 8 }));
    resume.notify_one();
    assert_eq!(synchronize.await.unwrap().uploaded, 1);
    wait(|| count(&peer) >= 3).await;
    assert!(
        settings
            .status(&store)
            .unwrap()
            .objects
            .iter()
            .any(|object| object.id == host.id.to_string() && object.personal)
    );
    drop(running);
    peer.assert_healthy();
}

#[tokio::test]
async fn rotation_during_pull_fences_next_ack_retrieves_keys_and_pauses_without_storm() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = prepare(&peer, &store).await;
    let vault = record(&store).unwrap().personal_vault_id;
    let reached = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    peer.state.lock().unwrap().pause =
        Some((format!("/sync/v1/vaults/{vault}/changes"), reached.clone(), resume.clone()));
    let running = start(manager, store.clone());
    tokio::time::timeout(Duration::from_secs(5), reached.notified()).await.unwrap();
    wait(|| running.runtime.status() == PersonalBackgroundStatus::Connected).await;
    {
        let mut state = peer.state.lock().unwrap();
        let reply = state.replies.get_mut("/sync/v1/session").unwrap();
        let mut session = SyncSessionResponse::from_cbor(&reply.body).unwrap();
        session.vaults.iter_mut().find(|value| value.id == vault).unwrap().rotation_pending = true;
        reply.body = session.to_cbor().unwrap();
    }
    send(&peer, Action::Event(SyncNotification::RotationPending { vault }));
    wait(|| store.personal_rotation() > 0).await;
    resume.notify_one();
    wait(|| running.runtime.status() == PersonalBackgroundStatus::RotationRequired).await;
    let paths = peer.state.lock().unwrap().paths.clone();
    let pull = paths.iter().position(|path| path.ends_with("/changes")).unwrap();
    assert_eq!(paths[pull + 1], "/.well-known/jwks.json");
    assert!(paths[pull + 1..].iter().any(|path| path == "/sync/v1/keys"));
    assert!(
        !paths[pull + 1..].iter().any(|path| path.ends_with("/ack") || path.ends_with("/objects"))
    );
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(peer.state.lock().unwrap().paths, paths, "unsupported rotation remains paused");
    peer.assert_healthy();
}

#[tokio::test]
async fn reconnect_uses_fresh_proof_and_catches_up_without_revoking_on_1008() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = prepare(&peer, &store).await;
    let running = start(manager, store.clone());
    wait(|| running.runtime.status() == PersonalBackgroundStatus::Connected && count(&peer) > 0)
        .await;
    let generation = record(&store).unwrap().auth_generation;
    let baseline = count(&peer);
    send(&peer, Action::Close);
    wait(|| {
        peer.state.lock().unwrap().notification.as_ref().unwrap().authenticated >= 2
            && count(&peer) > baseline
    })
    .await;
    assert_eq!(record(&store).unwrap().auth_generation, generation);
    assert!(
        peer.state.lock().unwrap().notification.as_ref().unwrap().closes.contains(&1008),
        "peer Close is echoed before tunnel disposal"
    );
    assert!(store.personal_access_token(now().unwrap()).unwrap().is_some());
    peer.assert_healthy();
}

#[tokio::test]
async fn unavailable_socket_polls_at_60_seconds_and_store_detach_stops_work() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = prepare(&peer, &store).await;
    peer.state.lock().unwrap().notification = None;
    let running = start(manager, store.clone());
    wait(|| count(&peer) > 0).await;
    tokio::time::sleep(Duration::from_millis(350)).await;
    let baseline = count(&peer);
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(58)).await;
    assert_eq!(count(&peer), baseline);
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::time::resume();
    wait(|| count(&peer) > baseline).await;
    running.runtime.set_store(None);
    wait(|| running.runtime.status() == PersonalBackgroundStatus::Inactive).await;
    let detached = count(&peer);
    store.personal_changed();
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(count(&peer), detached);
    running.runtime.shutdown();
    wait(|| running.task.is_finished()).await;
    peer.assert_healthy();
}

#[tokio::test]
async fn typed_revocation_stops_current_session_but_stale_cas_keeps_replacement() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = prepare(&peer, &store).await;
    let running = start(manager, store.clone());
    wait(|| running.runtime.status() == PersonalBackgroundStatus::Connected && count(&peer) > 0)
        .await;
    let captured = record(&store).unwrap();
    let access = store.personal_access_token(now().unwrap()).unwrap().unwrap();
    send(&peer, Action::Event(SyncNotification::DeviceRevoked));
    wait(|| running.runtime.status() == PersonalBackgroundStatus::AuthenticationRequired).await;
    assert!(store.personal_access_token(now().unwrap()).unwrap().is_none());
    peer.install_token(&store, |_| {}, None);
    store.invalidate_personal_session(&captured, &access).unwrap();
    assert!(store.personal_access_token(now().unwrap()).unwrap().is_some());
    wait(|| running.runtime.status() == PersonalBackgroundStatus::Connected).await;
    peer.assert_healthy();
}

#[tokio::test]
async fn protocol_reassembles_fragments_and_rejects_bad_order_type_and_complete_size() {
    let mut malformed = Frame::message(vec![0], OpCode::Data(Data::Binary), true);
    malformed.header_mut().rsv1 = true;
    for (opening, action, expected_close, expected_auth) in [
        (Opening::Fragmented, Some(Action::Text("unexpected".into())), 1003, 1),
        (Opening::Healthy, Some(Action::Binary(vec![0; 16_385])), 1009, 1),
        (Opening::Healthy, Some(Action::Binary(vec![0xff])), 1008, 1),
        (Opening::Healthy, Some(Action::Frame(malformed)), 1002, 1),
        (
            Opening::Healthy,
            Some(Action::Frame(Frame::message(vec![0xff], OpCode::Data(Data::Text), true))),
            1007,
            1,
        ),
        (Opening::Context(SyncNotificationReady.to_cbor().unwrap()), None, 1008, 0),
        (
            Opening::Context(
                SyncNotificationContext { htm: SyncNotificationMethod::Get }.to_cbor().unwrap(),
            ),
            None,
            1008,
            0,
        ),
        (Opening::Ready(SyncNotification::DeviceRevoked.to_cbor().unwrap()), None, 1008, 1),
    ] {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        let manager = prepare(&peer, &store).await;
        peer.state.lock().unwrap().notification.as_mut().unwrap().openings.push_back(opening);
        let running = start(manager, store.clone());
        if let Some(action) = action {
            wait(|| running.runtime.status() == PersonalBackgroundStatus::Connected).await;
            send(&peer, action);
        }
        wait(|| !peer.state.lock().unwrap().notification.as_ref().unwrap().closes.is_empty()).await;
        let state = peer.state.lock().unwrap();
        let notification = state.notification.as_ref().unwrap();
        assert_eq!(notification.closes[0], expected_close);
        assert_eq!(notification.authenticated, expected_auth);
        assert!(store.personal_access_token(now().unwrap()).unwrap().is_some());
        assert!(state.errors.is_empty());
    }
}

#[tokio::test]
async fn context_deadline_is_bounded_and_prebootstrap_start_does_no_network_work() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    peer.state.lock().unwrap().notification = Some(NotificationPeer::default());
    peer.state.lock().unwrap().inventory = Some(InventoryPeer::default());
    let running = start(manager, store.clone());
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(peer.state.lock().unwrap().notification.as_ref().unwrap().connections, 0);
    assert_eq!(count(&peer), 0);
    peer.state.lock().unwrap().notification.as_mut().unwrap().openings.push_back(Opening::Silent);
    peer.manager().bootstrap_sync(store.clone()).await.unwrap();
    wait(|| peer.state.lock().unwrap().notification.as_ref().unwrap().connections == 1).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::time::resume();
    wait(|| !peer.state.lock().unwrap().notification.as_ref().unwrap().closes.is_empty()).await;
    assert!(store.personal_access_token(now().unwrap()).unwrap().is_some());
    peer.assert_healthy();
    drop(running);
}
