// SPDX-License-Identifier: Apache-2.0
//! Native D-75 connection. Messages are hints, never replicated state.

use std::{sync::Arc, time::Duration};

use futures_util::{SinkExt as _, StreamExt as _};
use scoplen_api::sync::{
    MAX_SYNC_NOTIFICATION_BODY_BYTES, SYNC_NOTIFICATION_AUTH_DEADLINE_SECS, SyncNotification,
    SyncNotificationAuth, SyncNotificationContext, SyncNotificationMethod, SyncNotificationReady,
};
use scoplen_crypto::{
    DeviceAccessToken, DpopProof, DpopTarget, DpopToken, P256SigningKey, SecretVec,
    dpop_jwk_thumbprint,
};
use tokio::{
    sync::watch,
    time::{Instant, sleep, timeout},
};
use tokio_tungstenite::tungstenite::{
    Error as WebSocketError, Message,
    protocol::{CloseFrame, frame::coding::CloseCode},
};
use zeroize::Zeroize as _;

use super::{
    PersonalServer, PersonalServerError, identity, now, record, storage, trusted_token_keys,
};
use crate::store::{Store, personal::PersonalRecord};

pub(crate) mod stream;
const LIMIT: usize = MAX_SYNC_NOTIFICATION_BODY_BYTES;
const IO_DEADLINE: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Default)]
pub(super) struct Hints {
    pub connected: bool,
    pub connection: u64,
    pub sequence: u64,
}

struct Session {
    identity: PersonalRecord,
    access: SecretVec,
    signing: P256SigningKey,
    expires: u64,
}

impl Session {
    fn current(&self, store: &Store) -> bool {
        now().ok().is_some_and(|now| {
            store.personal_session_current(&self.identity, &self.access, now).unwrap_or(false)
        })
    }
}

impl PersonalServer {
    async fn notification_session(
        &self,
        store: &Store,
        run: &Arc<super::background::Run>,
    ) -> Result<Session, PersonalServerError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        self.refresh_for_run(store, Some(run)).await?;
        let identity = record(store)?;
        let access = store
            .personal_access_token(now()?)
            .map_err(storage)?
            .ok_or(PersonalServerError::AuthenticationRequired)?;
        let token = std::str::from_utf8(access.as_bytes())
            .map_err(|_| PersonalServerError::AuthenticationRequired)?;
        let secrets = identity::Secrets::parse(&identity.private_material)?;
        let signing = P256SigningKey::from_bytes(secrets.signing())
            .map_err(|_| PersonalServerError::Identity)?;
        let trusted =
            trusted_token_keys(self.transport.as_ref().map_err(|error| *error)?, &identity.origin)
                .await?;
        let verified = DeviceAccessToken::parse(token)
            .and_then(|token| token.verify(&trusted, now().unwrap_or(0)));
        let verified = match verified {
            Ok(verified)
                if verified.claims().sub == identity.account_id
                    && verified.claims().did == store.device_id()
                    && dpop_jwk_thumbprint(&signing.public_key_sec1()).ok().as_ref()
                        == Some(&verified.claims().cnf_jkt) =>
            {
                verified
            }
            _ => {
                let _active = run.guard()?;
                store.invalidate_personal_session(&identity, &access).map_err(storage)?;
                return Err(PersonalServerError::AuthenticationRequired);
            }
        };
        if !verified.claims().scope.split(' ').any(|scope| scope == "sync:read") {
            return Err(PersonalServerError::PermissionDenied);
        }
        let session = Session { identity, access, signing, expires: verified.expires_at() };
        if !session.current(store) {
            return Err(PersonalServerError::AuthenticationRequired);
        }
        Ok(session)
    }
}

pub(super) async fn run(
    server: &PersonalServer,
    store: &Arc<Store>,
    hints: watch::Sender<Hints>,
    run: &Arc<super::background::Run>,
) {
    let mut changes = store.personal_changes();
    let mut failures = 0_u32;
    loop {
        let result = server.notification_session(store, run).await;
        let (delay, dormant) = match result {
            Ok(session) => {
                let started = Instant::now();
                let _ = connection(server, store, &session, &hints, &mut changes, run).await;
                if started.elapsed() >= Duration::from_secs(30) {
                    failures = 0;
                }
                (Duration::from_secs((1_u64 << failures.min(6)).min(60)), false)
            }
            Err(PersonalServerError::Busy) => (Duration::from_millis(250), false),
            Err(
                PersonalServerError::AuthenticationRequired
                | PersonalServerError::NotConfigured
                | PersonalServerError::PermissionDenied
                | PersonalServerError::Identity,
            ) => (Duration::from_secs(60), true),
            Err(_) => (Duration::from_secs((1_u64 << failures.min(6)).min(60)), false),
        };
        hints.send_modify(|state| state.connected = false);
        if dormant {
            if changes.changed().await.is_err() {
                return;
            }
        } else {
            failures = failures.saturating_add(1);
            tokio::select! { _ = sleep(delay) => {}, _ = changes.changed() => {} }
        }
    }
}

async fn connection(
    server: &PersonalServer,
    store: &Store,
    session: &Session,
    hints: &watch::Sender<Hints>,
    changes: &mut watch::Receiver<u64>,
    run: &Arc<super::background::Run>,
) -> Result<(), PersonalServerError> {
    let tls = server.transport.as_ref().map_err(|error| *error)?.notification_tls.clone();
    let mut socket = timeout(IO_DEADLINE, stream::open(&session.identity.origin, tls))
        .await
        .map_err(|_| PersonalServerError::Network)??;
    let handshake = async {
        let context = SyncNotificationContext::from_cbor(&binary(&mut socket).await?)
            .map_err(|_| PersonalServerError::InvalidResponse)?;
        if context.htm != SyncNotificationMethod::Connect || !session.current(store) {
            return Err(PersonalServerError::InvalidResponse);
        }
        let token = std::str::from_utf8(session.access.as_bytes())
            .map_err(|_| PersonalServerError::AuthenticationRequired)?;
        let target =
            DpopTarget::new(context.htm.as_str(), &session.identity.origin, "/sync/v1/notify")
                .map_err(|_| PersonalServerError::Identity)?;
        let proof = DpopProof::sign(
            &session.signing,
            &session.signing.public_key_sec1(),
            &target,
            DpopToken::Protected(token),
            now()?,
            None,
        )
        .map_err(|_| PersonalServerError::Identity)?;
        let mut auth =
            SyncNotificationAuth { access_token: token.into(), dpop_proof: proof.as_str().into() };
        let encoded = auth.to_cbor();
        auth.access_token.zeroize();
        auth.dpop_proof.zeroize();
        socket
            .send(Message::Binary(encoded.map_err(|_| PersonalServerError::Identity)?.into()))
            .await
            .map_err(|_| PersonalServerError::Network)?;
        SyncNotificationReady::from_cbor(&binary(&mut socket).await?)
            .map_err(|_| PersonalServerError::InvalidResponse)?;
        if !session.current(store) {
            return Err(PersonalServerError::AuthenticationRequired);
        }
        Ok(())
    };
    if !matches!(
        timeout(Duration::from_secs(SYNC_NOTIFICATION_AUTH_DEADLINE_SECS), handshake).await,
        Ok(Ok(()))
    ) {
        close(&mut socket, CloseCode::Policy).await;
        return Err(PersonalServerError::InvalidResponse);
    }
    hints.send_modify(|state| {
        state.connected = true;
        state.connection = state.connection.wrapping_add(1);
    });
    let refresh_after = session.expires.saturating_sub(now()?).saturating_sub(60).max(1);
    let refresh = sleep(Duration::from_secs(refresh_after));
    tokio::pin!(refresh);
    let mut heartbeat =
        tokio::time::interval_at(Instant::now() + Duration::from_secs(30), Duration::from_secs(30));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut ping_pending = false;
    loop {
        tokio::select! {
            biased;
            _ = changes.changed() => {
                if !session.current(store) { close(&mut socket, CloseCode::Normal).await; return Ok(()); }
            }
            _ = &mut refresh => { close(&mut socket, CloseCode::Normal).await; return Ok(()); }
            _ = heartbeat.tick() => {
                if ping_pending { return Err(PersonalServerError::Network); }
                timeout(IO_DEADLINE, socket.send(Message::Ping(Vec::new().into()))).await
                    .map_err(|_| PersonalServerError::Network)?.map_err(|_| PersonalServerError::Network)?;
                ping_pending = true;
            }
            message = socket.next() => {
                let message = message.ok_or(PersonalServerError::Network)?;
                match message {
                    Ok(Message::Binary(body)) => {
                        let event = match SyncNotification::from_cbor(&body) {
                            Ok(event) => event,
                            Err(_) => { close(&mut socket, CloseCode::Policy).await; return Err(PersonalServerError::InvalidResponse); }
                        };
                        if !session.current(store) { return Ok(()); }
                        let revoked = {
                        let _active = run.guard()?;
                        match event {
                            SyncNotification::VaultAdvanced { vault, seq } if vault == session.identity.personal_vault_id => {
                                hints.send_modify(|state| state.sequence = state.sequence.max(seq));
                            }
                            SyncNotification::RotationPending { vault } if vault == session.identity.personal_vault_id => store.require_personal_keys(),
                            SyncNotification::DeviceRevoked => {
                                store.invalidate_personal_session(&session.identity, &session.access).map_err(storage)?;
                            }
                            _ => {}
                        }
                        matches!(event, SyncNotification::DeviceRevoked)
                        };
                        if revoked { close(&mut socket, CloseCode::Normal).await; return Ok(()); }
                    }
                    Ok(Message::Ping(_)) => {
                        timeout(IO_DEADLINE, socket.flush()).await.map_err(|_| PersonalServerError::Network)?.map_err(|_| PersonalServerError::Network)?;
                    }
                    Ok(Message::Pong(_)) => ping_pending = false,
                    Ok(Message::Close(_)) => { close(&mut socket, CloseCode::Normal).await; return Ok(()); }
                    Ok(Message::Text(_)) => { close(&mut socket, CloseCode::Unsupported).await; return Err(PersonalServerError::InvalidResponse); }
                    Err(error) => {
                        if let Some(code) = error_close(&error) { close(&mut socket, code).await; return Err(PersonalServerError::InvalidResponse); }
                        return Err(PersonalServerError::Network);
                    }
                    _ => return Err(PersonalServerError::Network),
                }
            }
        }
    }
}

async fn binary(socket: &mut stream::Socket) -> Result<Vec<u8>, PersonalServerError> {
    loop {
        match socket.next().await {
            Some(Ok(Message::Binary(body))) => return Ok(body.to_vec()),
            Some(Ok(Message::Ping(_))) => {
                socket.flush().await.map_err(|_| PersonalServerError::Network)?
            }
            Some(Ok(Message::Pong(_))) => {}
            Some(Ok(Message::Text(_))) => {
                close(socket, CloseCode::Unsupported).await;
                return Err(PersonalServerError::InvalidResponse);
            }
            Some(Err(error)) => {
                if let Some(code) = error_close(&error) {
                    close(socket, code).await;
                }
                return Err(PersonalServerError::InvalidResponse);
            }
            _ => return Err(PersonalServerError::Network),
        }
    }
}

fn error_close(error: &WebSocketError) -> Option<CloseCode> {
    match error {
        WebSocketError::Capacity(_) => Some(CloseCode::Size),
        WebSocketError::Protocol(_) => Some(CloseCode::Protocol),
        WebSocketError::Utf8(_) => Some(CloseCode::Invalid),
        _ => None,
    }
}

async fn close(socket: &mut stream::Socket, code: CloseCode) {
    let _ = timeout(Duration::from_millis(250), async {
        let _ = socket.close(Some(CloseFrame { code, reason: "".into() })).await;
        // A received Close has already queued its echo and rejects a new send.
        let _ = socket.flush().await;
        // Keep driving the H2 tunnel until the peer responds, or the bounded grace
        // expires. Dropping its driver immediately can discard the queued Close.
        loop {
            match socket.next().await {
                Some(Ok(Message::Close(_))) => break,
                // A framing failure can recur before the queued Close is drained.
                // Keep its driver alive for the remaining bounded grace period.
                None | Some(Err(_)) => std::future::pending::<()>().await,
                _ => {}
            }
        }
        Ok::<_, WebSocketError>(())
    })
    .await;
}
