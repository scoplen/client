// SPDX-License-Identifier: Apache-2.0
//! Explicit native second-device pairing; secret state never enters a normal snapshot.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use reqwest::Method;
use scoplen_api::pairing::{
    PairingClaimRequest, PairingClaimResponse, PairingCompleteRequest,
    PairingContext as RelayContext, PairingCreateRequest, PairingCreateResponse, PairingMessageAck,
    PairingMessageRequest, PairingReceipt, PairingSnapshot, PairingState as RelayState,
    PairingStep,
};
use scoplen_api::sync::{SyncAccountDeviceWrap, SyncAccountKeyBundleUpdate, SyncVaultKeysResponse};
use scoplen_crypto::{
    AccountKemKeyWrap, AccountSigningKeyWrap, DeviceAccessToken, DeviceArkWrap, DeviceCertificate,
    DeviceKemKeyPair, DpopProof, DpopTarget, DpopToken, Ed25519SigningKey, P256SigningKey,
    PairingApplicationContext, PairingCode, PairingCompletionContext,
    PairingContext as CryptoContext, PairingHandoff, PairingInitiator, PairingKeyProjection,
    PairingLink, PairingNewDevice, PairingQrPayload, PairingResponder, PairingSession,
    PersonalVaultKeyWrap, SymmetricKey, dpop_jwk_thumbprint, generate_device_keys,
    pairing_key_anchor, validate_server_origin,
};
use scoplen_model::cbor::{self, Value};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use specta::Type;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    PersonalServer, PersonalServerError, identity, now, record,
    retained::RetainedAccount,
    storage,
    transport::{PairingCredential, Response},
    trusted_token_keys,
};
use crate::store::{
    Store,
    personal::{PairingDeviceRecord, PairingRecord, PersonalRecord},
};
use scoplen_crypto::SecretVec;

pub(super) mod qr;
pub use qr::PairingQrDisplay;

pub(super) struct ActivePairing {
    store_device: Uuid,
    pairing_id: Uuid,
    deadline: Instant,
    next_poll: Instant,
    code: Option<PairingCode>,
    initiator: Option<PairingInitiator>,
    channel: Option<PairingSession>,
    peer: Option<PairingNewDevice>,
    qr: Option<PairingQrPayload>,
}

impl ActivePairing {
    // Status remains accurate while an owned crypto operation waits on bounded I/O.
    fn public_marker(&self) -> Self {
        Self {
            store_device: self.store_device,
            pairing_id: self.pairing_id,
            deadline: self.deadline,
            next_poll: self.next_poll,
            code: None,
            initiator: None,
            channel: None,
            qr: None,
            peer: self.peer.as_ref().map(|peer| PairingNewDevice {
                context: peer.context.clone(),
                signing_public_key: peer.signing_public_key.clone(),
                kem_public_key: peer.kem_public_key.clone(),
                display_name: peer.display_name.clone(),
                platform: peer.platform.clone(),
                created_at: peer.created_at,
            }),
        }
    }
}

/// This installation's fixed role in a ceremony.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum PairingSide {
    /// Existing authenticated account device.
    OldDevice,
    /// New device receiving the existing account.
    NewDevice,
}

/// Safe local ceremony progress; no phase alone establishes an authenticated account.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum PairingPhase {
    /// No retained ceremony.
    Idle,
    /// New device is waiting for an existing device to claim the public locator.
    Waiting,
    /// The single password-authenticated attempt is running.
    Exchanging,
    /// Confirm the authenticated new-device claims before issuing its certificate.
    ConfirmDevice,
    /// The exact old-device plan is retained while waiting for possession acceptance.
    WaitingAcceptance,
    /// Admission may have committed; recover with the retained identity and exact plan.
    AdmissionUnconfirmed,
    /// New side verified authentication/keys; old side confirmed its exact admission receipt.
    Completed,
    /// A fresh explicitly requested ceremony and password are required.
    RestartRequired,
    /// This installation terminated the ceremony.
    Cancelled,
}

/// Public pairing metadata; never carries a password, capability, key, or decrypted package.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct PairingStatus {
    /// Current safe next action.
    pub phase: PairingPhase,
    /// Retained role, if a session exists.
    pub side: Option<PairingSide>,
    /// Exact selected canonical HTTPS origin.
    pub origin: Option<String>,
    /// Public-only session locator, suitable for an explicit Copy action.
    pub public_link: Option<String>,
    /// Local installation's selected name.
    pub device_name: Option<String>,
    /// Authenticated new device name, only for old-device confirmation.
    pub peer_name: Option<String>,
    /// Authenticated new device platform claim, only for old-device confirmation.
    pub peer_platform: Option<String>,
}

/// One-shot result for the dedicated transient password-display boundary.
/// The password is never repeated by `pairing_status` or persisted.
pub struct PairingStarted {
    /// Safe ordinary progress.
    pub status: PairingStatus,
    /// Volatile eight-character secret, cleared when the dedicated UI closes.
    pub password: SecretVec,
    /// One-time QR rendering, or `None` when manual link/password pairing remains available.
    pub qr: Option<PairingQrDisplay>,
}

impl std::fmt::Debug for PairingStarted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingStarted([REDACTED])")
    }
}

/// Localized, non-sensitive failures preserve retained device identity and checkpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum PairingError {
    /// Existing account/transport/store boundary failure.
    #[error(transparent)]
    Personal(#[from] PersonalServerError),
    /// Origin, public locator, name or eight-character password was invalid.
    #[error("Check the server, pairing link, device name and eight-character password.")]
    InvalidInput,
    /// A selected file was not one bounded static PNG with exactly one valid pairing QR.
    #[error("Choose a PNG screenshot containing one pairing QR. No pairing request was sent.")]
    QrImage,
    /// The QR could not be rendered; the existing public link and password remain usable.
    #[error("The QR could not be displayed. Use the pairing link and separate password.")]
    QrUnavailable,
    /// The response, transcript, key material or cryptographic binding was invalid.
    #[error("Pairing verification failed. Check the retained pairing state before continuing.")]
    InvalidResponse,
    /// The earlier local/session five-minute deadline has passed.
    #[error("Pairing expired. Check admission before starting a fresh ceremony.")]
    Expired,
    /// Volatile state was lost before a recoverable checkpoint.
    #[error("Start a fresh pairing ceremony. This device's existing keys were retained.")]
    RestartRequired,
    /// No pending ceremony accepts this operation.
    #[error("Start a pairing ceremony before continuing.")]
    NotActive,
    /// A competing state change prevents replaying this retained plan.
    #[error("Pairing state changed. Check admission before starting another ceremony.")]
    Conflict,
    /// The selected existing device needs a valid native device session.
    #[error("Authenticate the existing device before pairing another device.")]
    AuthenticationRequired,
}

fn invalid(_: impl std::fmt::Debug) -> PairingError {
    PairingError::InvalidResponse
}
fn stored(error: crate::store::StoreError) -> PairingError {
    storage(error).into()
}

fn phase(value: &str) -> Result<PairingPhase, PairingError> {
    Ok(match value {
        "waiting" => PairingPhase::Waiting,
        "exchanging" => PairingPhase::Exchanging,
        "confirm_device" => PairingPhase::ConfirmDevice,
        "waiting_acceptance" => PairingPhase::WaitingAcceptance,
        "admission_unconfirmed" => PairingPhase::AdmissionUnconfirmed,
        "completed" => PairingPhase::Completed,
        "restart_required" => PairingPhase::RestartRequired,
        "cancelled" => PairingPhase::Cancelled,
        _ => return Err(PairingError::InvalidResponse),
    })
}

fn transcript(record: &PairingRecord) -> Result<Vec<Vec<u8>>, PairingError> {
    let Value::Array(values) = cbor::decode(record.transcript.as_bytes()).map_err(invalid)? else {
        return Err(PairingError::InvalidResponse);
    };
    if values.len() > 7 {
        return Err(PairingError::InvalidResponse);
    }
    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            let Value::Bytes(bytes) = value else {
                return Err(PairingError::InvalidResponse);
            };
            if bytes.is_empty() || bytes.len() > PairingStep::ALL[index].max_payload_bytes() {
                return Err(PairingError::InvalidResponse);
            }
            Ok(bytes)
        })
        .collect()
}

fn encoded_transcript(values: &[Vec<u8>]) -> Result<SecretVec, PairingError> {
    cbor::encode(&Value::Array(values.iter().cloned().map(Value::Bytes).collect()))
        .map(SecretVec::new)
        .map_err(invalid)
}

fn save(store: &Store, record: &mut PairingRecord) -> Result<(), PairingError> {
    if !store.save_pairing(Some(record.generation), record).map_err(stored)? {
        return Err(PairingError::Conflict);
    }
    record.generation = record.generation.checked_add(1).ok_or(PairingError::Conflict)?;
    Ok(())
}

fn crypto_context(
    store: &Store,
    record: &PairingRecord,
) -> Result<PairingApplicationContext, PairingError> {
    let peer = record.peer_id.ok_or(PairingError::InvalidResponse)?;
    let (initiator, responder) =
        if record.side == 1 { (store.device_id(), peer) } else { (peer, store.device_id()) };
    PairingApplicationContext::new(
        &record.origin,
        CryptoContext::new(record.pairing_id, initiator, responder).map_err(invalid)?,
    )
    .map_err(invalid)
}

// The shared DTO validates the complete UTC grammar before this local clock conversion.
fn expiry(context: &RelayContext) -> Result<u64, PairingError> {
    context.validate().map_err(invalid)?;
    let text = &context.expires_at;
    let field = |range: std::ops::Range<usize>| -> Result<i64, PairingError> {
        text.get(range).ok_or(PairingError::InvalidResponse)?.parse().map_err(invalid)
    };
    let (mut year, month, day) = (field(0..4)?, field(5..7)?, field(8..10)?);
    year -= i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let days = era * 146_097 + year_of_era * 365 + year_of_era / 4 - year_of_era / 100
        + (153 * adjusted_month + 2) / 5
        + day
        - 1
        - 719_468;
    u64::try_from(days * 86_400 + field(11..13)? * 3600 + field(14..16)? * 60 + field(17..19)?)
        .map_err(invalid)
}

fn bounded_deadline(started: Instant, expires_at: u64) -> Result<Instant, PairingError> {
    let remaining = expires_at.checked_sub(now()?).ok_or(PairingError::Expired)?;
    let deadline =
        (started + Duration::from_secs(300)).min(Instant::now() + Duration::from_secs(remaining));
    if deadline <= Instant::now() {
        return Err(PairingError::Expired);
    }
    Ok(deadline)
}

impl PersonalServer {
    /// Read saved public progress locally. Mounting Settings performs no network operation.
    pub fn pairing_status(&self, store: &Store) -> Result<PairingStatus, PairingError> {
        let Some(record) = store.pairing_record().map_err(stored)? else {
            return Ok(PairingStatus {
                phase: PairingPhase::Idle,
                side: None,
                origin: None,
                public_link: None,
                device_name: None,
                peer_name: None,
                peer_platform: None,
            });
        };
        let memory = self.pairing.lock().map_err(invalid)?;
        let active = memory.as_ref().filter(|memory| {
            memory.store_device == store.device_id() && memory.pairing_id == record.pairing_id
        });
        let mut phase = phase(&record.phase)?;
        if active.is_none()
            && matches!(
                phase,
                PairingPhase::Waiting | PairingPhase::Exchanging | PairingPhase::ConfirmDevice
            )
        {
            phase = PairingPhase::RestartRequired;
        }
        let device_name = if record.side == 2 {
            store.pairing_device().map_err(stored)?.map(|device| device.device_name)
        } else {
            store.personal_record().map_err(stored)?.map(|identity| identity.device_name)
        };
        Ok(PairingStatus {
            phase,
            side: Some(if record.side == 1 {
                PairingSide::OldDevice
            } else {
                PairingSide::NewDevice
            }),
            origin: Some(record.origin.clone()),
            public_link: Some(
                PairingLink::new(&record.origin, record.pairing_id).map_err(invalid)?.encode(),
            ),
            device_name,
            peer_name: active
                .and_then(|active| active.peer.as_ref())
                .map(|peer| peer.display_name.clone()),
            peer_platform: active
                .and_then(|active| active.peer.as_ref())
                .map(|peer| peer.platform.clone()),
        })
    }

    /// Generate a public locator and one transient password using retained local device keys.
    pub async fn pairing_create(
        &self,
        store: Arc<Store>,
        origin: String,
        device_name: String,
    ) -> Result<PairingStarted, PairingError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        validate_server_origin(&origin).map_err(|_| PairingError::InvalidInput)?;
        if device_name.is_empty()
            || device_name.len() > 128
            || device_name.chars().any(char::is_control)
        {
            return Err(PairingError::InvalidInput);
        }
        if store.personal_record().map_err(stored)?.is_some() {
            return Err(PersonalServerError::AlreadyConfigured.into());
        }
        let previous = store.pairing_record().map_err(stored)?;
        if previous.as_ref().is_some_and(|record| record.phase == "admission_unconfirmed") {
            return Err(PairingError::Conflict);
        }
        let device = if let Some(mut device) = store.pairing_device().map_err(stored)? {
            if device.origin != origin || device.device_name != device_name {
                if previous.is_some() {
                    return Err(PairingError::InvalidInput);
                }
                if !store
                    .correct_unbound_pairing_device(&device, &origin, &device_name)
                    .map_err(stored)?
                {
                    return Err(PairingError::Conflict);
                }
                device = store.pairing_device().map_err(stored)?.ok_or(PairingError::Conflict)?;
                if device.origin != origin || device.device_name != device_name {
                    return Err(PairingError::Conflict);
                }
            }
            device
        } else {
            let keys = generate_device_keys().map_err(invalid)?;
            let device = PairingDeviceRecord {
                origin: origin.clone(),
                device_name,
                signing: SecretVec::new(keys.signing.private_key_bytes().as_bytes().to_vec()),
                kem: SecretVec::new(keys.kem.private_key_bytes().as_bytes().to_vec()),
                created_at: scoplen_model::system_time_millis().map_err(invalid)?,
            };
            if !store.insert_pairing_device(&device).map_err(stored)? {
                return Err(PairingError::Conflict);
            }
            device
        };
        *self.pairing.lock().map_err(invalid)? = None;
        let code = PairingCode::generate().map_err(invalid)?;
        let started = Instant::now();
        let started_at = now()?;
        let body =
            PairingCreateRequest { device_id: store.device_id() }.to_json().map_err(invalid)?;
        let transport = self.transport.as_ref().map_err(|error| *error)?;
        let response = transport
            .pairing(
                Method::POST,
                &origin,
                "/api/v1/auth/pairings",
                Some(&body),
                PairingCredential::Anonymous,
                4096,
            )
            .await?;
        if response.status != 201 {
            return Err(PairingError::InvalidResponse);
        }
        let result = PairingCreateResponse::from_json(response.body.as_bytes()).map_err(invalid)?;
        let context = result.context;
        if context.origin != origin
            || context.responder_device_id != store.device_id()
            || context.initiator_device_id.is_some()
        {
            return Err(PairingError::InvalidResponse);
        }
        let expires_at = expiry(&context)?;
        let local_expires_at = expires_at.min(started_at.saturating_add(300));
        let deadline = bounded_deadline(started, local_expires_at)?;
        let record = PairingRecord {
            generation: 0,
            side: 2,
            origin,
            pairing_id: context.pairing_id,
            peer_id: None,
            expires_at,
            local_expires_at,
            attempt_started: false,
            phase: "waiting".into(),
            capability: Some(SecretVec::new(result.new_device_token.as_bytes().to_vec())),
            transcript: encoded_transcript(&[])?,
            certificate: None,
            key_update: None,
            handoff: None,
            acceptance: None,
            approval_request: None,
        };
        if !store
            .save_pairing_for_device(previous.map(|record| record.generation), &record, &device)
            .map_err(stored)?
        {
            return Err(PairingError::Conflict);
        }
        let password = SecretVec::new(code.as_ascii().to_vec());
        let qr = (|| {
            let signing = P256SigningKey::from_bytes(device.signing.as_bytes()).map_err(invalid)?;
            let kem =
                DeviceKemKeyPair::from_private_bytes(device.kem.as_bytes()).map_err(invalid)?;
            let payload = PairingQrPayload::new(
                &record.origin,
                record.pairing_id,
                kem.public_key(),
                &signing.public_key_sec1(),
                PairingCode::from_ascii(code.as_ascii()).map_err(invalid)?,
            )
            .map_err(invalid)?;
            qr::display(&payload)
        })()
        .ok();
        *self.pairing.lock().map_err(invalid)? = Some(ActivePairing {
            store_device: store.device_id(),
            pairing_id: record.pairing_id,
            deadline,
            next_poll: Instant::now(),
            code: Some(code),
            initiator: None,
            channel: None,
            peer: None,
            qr: None,
        });
        Ok(PairingStarted { status: self.pairing_status(&store)?, password, qr })
    }

    /// Claim a public locator using the selected account and one write-only password.
    pub async fn pairing_join(
        &self,
        store: Arc<Store>,
        public_link: String,
        password: Zeroizing<String>,
    ) -> Result<PairingStatus, PairingError> {
        let link = PairingLink::decode(&public_link).map_err(|_| PairingError::InvalidInput)?;
        let code =
            PairingCode::from_ascii(password.as_bytes()).map_err(|_| PairingError::InvalidInput)?;
        self.pairing_claim(store, link, code, None, || true).await
    }

    /// Read one native-selected PNG locally and claim only its strict, same-origin QRv2.
    pub async fn pairing_join_png(
        &self,
        store: Arc<Store>,
        path: std::path::PathBuf,
        current: impl FnOnce() -> bool,
    ) -> Result<PairingStatus, PairingError> {
        let payload = tokio::task::spawn_blocking(move || qr::read_png(&path))
            .await
            .map_err(|_| PairingError::QrImage)??;
        let code = PairingCode::from_ascii(payload.code().as_ascii()).map_err(invalid)?;
        self.pairing_claim(store, payload.link().clone(), code, Some(payload), current).await
    }

    async fn pairing_claim(
        &self,
        store: Arc<Store>,
        link: PairingLink,
        code: PairingCode,
        qr: Option<PairingQrPayload>,
        current: impl FnOnce() -> bool,
    ) -> Result<PairingStatus, PairingError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        if !current() {
            return Err(PairingError::Conflict);
        }
        let identity = record(&store)?;
        if identity.origin != link.origin() {
            return Err(PairingError::InvalidInput);
        }
        RetainedAccount::load(&store, &identity)?;
        let previous = store.pairing_record().map_err(stored)?;
        if previous.as_ref().is_some_and(|record| {
            matches!(record.phase.as_str(), "waiting_acceptance" | "admission_unconfirmed")
        }) {
            return Err(PairingError::Conflict);
        }
        *self.pairing.lock().map_err(invalid)? = None;
        let started = Instant::now();
        let started_at = now()?;
        let path = format!("/api/v1/auth/pairings/{}/claim", link.pairing_id());
        let body = PairingClaimRequest.to_json().map_err(invalid)?;
        let response = self
            .old_pairing_exchange(
                &store,
                Method::POST,
                link.origin(),
                &path,
                Some(&body),
                4096,
                Some(started + Duration::from_secs(300)),
            )
            .await?;
        if response.status != 200 {
            return Err(PairingError::Conflict);
        }
        let context =
            PairingClaimResponse::from_json(response.body.as_bytes()).map_err(invalid)?.context;
        if context.origin != link.origin()
            || context.pairing_id != link.pairing_id()
            || context.initiator_device_id != Some(store.device_id())
            || context.responder_device_id == store.device_id()
        {
            return Err(PairingError::InvalidResponse);
        }
        let expires_at = expiry(&context)?;
        let local_expires_at = expires_at.min(started_at.saturating_add(300));
        let deadline = bounded_deadline(started, local_expires_at)?;
        let mut pending = PairingRecord {
            generation: previous.as_ref().map_or(0, |row| row.generation),
            side: 1,
            origin: link.origin().to_owned(),
            pairing_id: link.pairing_id(),
            peer_id: Some(context.responder_device_id),
            expires_at,
            local_expires_at,
            attempt_started: false,
            phase: "exchanging".into(),
            capability: None,
            transcript: encoded_transcript(&[])?,
            certificate: None,
            key_update: None,
            handoff: None,
            acceptance: None,
            approval_request: None,
        };
        if !store.save_pairing(previous.map(|row| row.generation), &pending).map_err(stored)? {
            return Err(PairingError::Conflict);
        }
        pending.generation += 1;
        if !store.claim_pairing_attempt(&pending).map_err(stored)? {
            return Err(PairingError::RestartRequired);
        }
        pending.generation += 1;
        pending.attempt_started = true;
        let context = crypto_context(&store, &pending)?;
        let (initiator, share) =
            PairingInitiator::start(&context.pairing(), &code).map_err(invalid)?;
        pending.transcript = encoded_transcript(&[share.to_vec()])?;
        save(&store, &mut pending)?;
        *self.pairing.lock().map_err(invalid)? = Some(ActivePairing {
            store_device: store.device_id(),
            pairing_id: pending.pairing_id,
            deadline,
            next_poll: Instant::now(),
            code: None,
            initiator: Some(initiator),
            channel: None,
            peer: None,
            qr,
        });
        if let Err(error) =
            self.send_pairing_slot(&store, &pending, PairingStep::InitiatorShare, &share).await
        {
            *self.pairing.lock().map_err(invalid)? = None;
            pending.phase = "restart_required".into();
            save(&store, &mut pending)?;
            let _ = self.pairing_exchange(&store, &pending, Method::DELETE, "", None, 0).await;
            return Err(error);
        }
        self.pairing_status(&store)
    }

    #[allow(clippy::too_many_arguments)]
    async fn old_pairing_exchange(
        &self,
        store: &Store,
        method: Method,
        origin: &str,
        path: &str,
        body: Option<&[u8]>,
        limit: usize,
        deadline: Option<Instant>,
    ) -> Result<Response, PairingError> {
        self.refresh_for_operation(store).await?;
        let identity = record(store)?;
        if identity.origin != origin {
            return Err(PairingError::InvalidInput);
        }
        let access = store
            .personal_access_token(now()?)
            .map_err(stored)?
            .ok_or(PairingError::AuthenticationRequired)?;
        let token = std::str::from_utf8(access.as_bytes()).map_err(invalid)?;
        let secrets = identity::Secrets::parse(&identity.private_material)?;
        let signing = P256SigningKey::from_bytes(secrets.signing()).map_err(invalid)?;
        let transport = self.transport.as_ref().map_err(|error| *error)?;
        let trusted = trusted_token_keys(transport, origin).await?;
        let verified = DeviceAccessToken::parse(token)
            .and_then(|token| token.verify(&trusted, now().unwrap_or(u64::MAX)))
            .map_err(|_| PairingError::AuthenticationRequired)?;
        let claims = verified.claims();
        if claims.sub != identity.account_id
            || claims.did != store.device_id()
            || claims.cnf_jkt != dpop_jwk_thumbprint(&signing.public_key_sec1()).map_err(invalid)?
            || !claims.scope.split(' ').any(|scope| scope == "keys:write")
            || !store.personal_session_current(&identity, &access, now()?).map_err(stored)?
        {
            return Err(PairingError::AuthenticationRequired);
        }
        if deadline.is_some_and(|deadline| deadline <= Instant::now()) {
            return Err(PairingError::Expired);
        }
        let target = DpopTarget::new(method.as_str(), origin, path).map_err(invalid)?;
        let proof = DpopProof::sign(
            &signing,
            &signing.public_key_sec1(),
            &target,
            DpopToken::Protected(token),
            now()?,
            None,
        )
        .map_err(invalid)?;
        let response = transport
            .pairing(
                method,
                origin,
                path,
                body,
                PairingCredential::Old { access: token, proof: &proof },
                limit,
            )
            .await?;
        if matches!(response.status, 401 | 403) {
            store.invalidate_personal_session(&identity, &access).map_err(stored)?;
            return Err(PairingError::AuthenticationRequired);
        }
        Ok(response)
    }

    async fn pairing_exchange(
        &self,
        store: &Store,
        pending: &PairingRecord,
        method: Method,
        suffix: &str,
        body: Option<&[u8]>,
        limit: usize,
    ) -> Result<Response, PairingError> {
        let path = format!("/api/v1/auth/pairings/{}{suffix}", pending.pairing_id);
        let deadline = if method == Method::POST {
            let local = bounded_deadline(Instant::now(), pending.local_expires_at)?;
            Some(
                self.pairing
                    .lock()
                    .map_err(invalid)?
                    .as_ref()
                    .filter(|active| {
                        active.store_device == store.device_id()
                            && active.pairing_id == pending.pairing_id
                    })
                    .map_or(local, |active| active.deadline.min(local)),
            )
        } else {
            None
        };
        if pending.side == 1 {
            self.old_pairing_exchange(store, method, &pending.origin, &path, body, limit, deadline)
                .await
        } else {
            if deadline.is_some_and(|deadline| deadline <= Instant::now()) {
                return Err(PairingError::Expired);
            }
            let token = pending.capability.as_ref().ok_or(PairingError::InvalidResponse)?;
            Ok(self
                .transport
                .as_ref()
                .map_err(|error| *error)?
                .pairing(
                    method,
                    &pending.origin,
                    &path,
                    body,
                    PairingCredential::New(token.as_bytes()),
                    limit,
                )
                .await?)
        }
    }

    async fn send_pairing_slot(
        &self,
        store: &Store,
        pending: &PairingRecord,
        step: PairingStep,
        payload: &[u8],
    ) -> Result<(), PairingError> {
        let body =
            PairingMessageRequest { step, payload: payload.to_vec() }.to_json().map_err(invalid)?;
        let response = self
            .pairing_exchange(store, pending, Method::POST, "/messages", Some(&body), 256)
            .await?;
        if response.status != 200
            || PairingMessageAck::from_json(response.body.as_bytes()).map_err(invalid)?.step != step
        {
            return Err(PairingError::Conflict);
        }
        Ok(())
    }

    /// Advance one bounded ceremony cycle. Poll spacing and all protocol decisions live in Rust.
    pub async fn pairing_progress(&self, store: Arc<Store>) -> Result<PairingStatus, PairingError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let mut pending = store.pairing_record().map_err(stored)?.ok_or(PairingError::NotActive)?;
        if matches!(
            pending.phase.as_str(),
            "completed"
                | "cancelled"
                | "restart_required"
                | "confirm_device"
                | "admission_unconfirmed"
        ) {
            return self.pairing_status(&store);
        }
        let mut active =
            self.pairing.lock().map_err(invalid)?.take().ok_or(PairingError::RestartRequired)?;
        if active.store_device != store.device_id() || active.pairing_id != pending.pairing_id {
            return Err(PairingError::Conflict);
        }
        *self.pairing.lock().map_err(invalid)? = Some(active.public_marker());
        if active.next_poll > Instant::now() {
            tokio::time::sleep_until(active.next_poll.into()).await;
        }
        let result = if active.deadline <= Instant::now() {
            Err(PairingError::Expired)
        } else {
            active.next_poll = Instant::now() + Duration::from_secs(2);
            self.advance_pairing(&store, &mut pending, &mut active).await
        };
        match result {
            Ok(()) => {
                *self.pairing.lock().map_err(invalid)? = None;
                if !matches!(pending.phase.as_str(), "completed" | "cancelled" | "restart_required")
                {
                    *self.pairing.lock().map_err(invalid)? = Some(active);
                }
                self.pairing_status(&store)
            }
            Err(error) => {
                *self.pairing.lock().map_err(invalid)? = None;
                drop(active);
                if pending.acceptance.is_some() || pending.handoff.is_some() {
                    pending.phase = "admission_unconfirmed".into();
                } else {
                    pending.phase = "restart_required".into();
                }
                save(&store, &mut pending)?;
                if pending.phase == "restart_required" {
                    let _ =
                        self.pairing_exchange(&store, &pending, Method::DELETE, "", None, 0).await;
                }
                Err(error)
            }
        }
    }

    async fn read_pairing(
        &self,
        store: &Store,
        pending: &PairingRecord,
    ) -> Result<PairingSnapshot, PairingError> {
        let response =
            self.pairing_exchange(store, pending, Method::GET, "", None, 8_388_608).await?;
        if response.status != 200 {
            return Err(PairingError::Conflict);
        }
        let snapshot = PairingSnapshot::from_json(response.body.as_bytes()).map_err(invalid)?;
        let context = &snapshot.context;
        let (initiator, responder) = if pending.side == 1 {
            (Some(store.device_id()), pending.peer_id.ok_or(PairingError::InvalidResponse)?)
        } else {
            (pending.peer_id, store.device_id())
        };
        if context.origin != pending.origin
            || context.pairing_id != pending.pairing_id
            || context.responder_device_id != responder
            || expiry(context)? != pending.expires_at
            || initiator.is_some() && context.initiator_device_id != initiator
        {
            return Err(PairingError::InvalidResponse);
        }
        Ok(snapshot)
    }

    async fn advance_pairing(
        &self,
        store: &Arc<Store>,
        pending: &mut PairingRecord,
        active: &mut ActivePairing,
    ) -> Result<(), PairingError> {
        let snapshot = self.read_pairing(store, pending).await?;
        if matches!(snapshot.state, RelayState::Cancelled | RelayState::Expired) {
            return Err(PairingError::Expired);
        }
        if pending.side == 2 && pending.peer_id.is_none() {
            let Some(peer) = snapshot.context.initiator_device_id else {
                return Ok(());
            };
            if peer == store.device_id() {
                return Err(PairingError::InvalidResponse);
            }
            pending.peer_id = Some(peer);
            pending.phase = "exchanging".into();
            save(store, pending)?;
        }
        let mut values = merged_transcript(pending, &snapshot)?;
        if pending.side == 1 && values.len() == 7 && pending.acceptance.is_none() {
            retain_acceptance(store, pending, &values)?;
        }
        match snapshot.state {
            RelayState::Completed => {
                return self
                    .finish_pairing(
                        store,
                        pending,
                        snapshot.receipt.as_ref().ok_or(PairingError::InvalidResponse)?,
                    )
                    .await;
            }
            RelayState::Cancelled | RelayState::Expired => return Err(PairingError::Expired),
            _ => {}
        }
        if active.deadline <= Instant::now() {
            return Err(PairingError::Expired);
        }
        if snapshot.messages.len() < values.len() {
            let next = snapshot.messages.len();
            let step = PairingStep::ALL[next];
            let own = if pending.side == 1 {
                scoplen_api::pairing::PairingRole::Initiator
            } else {
                scoplen_api::pairing::PairingRole::Responder
            };
            if step.role() != own {
                return Err(PairingError::InvalidResponse);
            }
            self.send_pairing_slot(store, pending, step, &values[next]).await?;
            return Ok(());
        }
        pending.transcript = encoded_transcript(&values)?;
        save(store, pending)?;
        if values.is_empty() {
            return Ok(());
        }
        let context = crypto_context(store, pending)?;
        let generated = match (pending.side, values.len()) {
            (2, 1) => {
                if pending.attempt_started {
                    return Err(PairingError::RestartRequired);
                }
                if !store.claim_pairing_attempt(pending).map_err(stored)? {
                    return Err(PairingError::RestartRequired);
                }
                pending.generation += 1;
                pending.attempt_started = true;
                let code = active.code.take().ok_or(PairingError::RestartRequired)?;
                let (channel, share) =
                    PairingResponder::respond(&context.pairing(), &code, &values[0])
                        .map_err(invalid)?;
                active.channel = Some(channel);
                Some((PairingStep::ResponderShare, share.to_vec()))
            }
            (2, 2) => Some((
                PairingStep::ResponderConfirmation,
                active
                    .channel
                    .as_ref()
                    .ok_or(PairingError::RestartRequired)?
                    .confirmation()
                    .map_err(invalid)?
                    .to_vec(),
            )),
            (1, 3) => {
                let channel = active
                    .initiator
                    .take()
                    .ok_or(PairingError::RestartRequired)?
                    .finish(&values[1])
                    .map_err(invalid)?;
                channel.verify_peer_confirmation(&values[2]).map_err(invalid)?;
                let confirmation = channel.confirmation().map_err(invalid)?;
                active.channel = Some(channel);
                Some((PairingStep::InitiatorConfirmation, confirmation.to_vec()))
            }
            (2, 4) => {
                let channel = active.channel.as_ref().ok_or(PairingError::RestartRequired)?;
                channel.verify_peer_confirmation(&values[3]).map_err(invalid)?;
                let device =
                    store.pairing_device().map_err(stored)?.ok_or(PairingError::InvalidResponse)?;
                let signing =
                    P256SigningKey::from_bytes(device.signing.as_bytes()).map_err(invalid)?;
                let kem =
                    DeviceKemKeyPair::from_private_bytes(device.kem.as_bytes()).map_err(invalid)?;
                let material = PairingNewDevice {
                    context,
                    signing_public_key: signing.public_key_sec1(),
                    kem_public_key: kem.public_key().to_vec(),
                    display_name: device.device_name,
                    platform: std::env::consts::OS.into(),
                    created_at: device.created_at,
                };
                Some((PairingStep::NewDevice, material.seal(channel).map_err(invalid)?))
            }
            (1, 5) => {
                if active.peer.is_none() {
                    let peer = PairingNewDevice::open(
                        &context,
                        active.channel.as_ref().ok_or(PairingError::RestartRequired)?,
                        &values[4],
                    )
                    .map_err(invalid)?;
                    if let Some(qr) = active.qr.take() {
                        qr.verify_public_keys(&peer.kem_public_key, &peer.signing_public_key)
                            .map_err(invalid)?;
                    }
                    active.peer = Some(peer);
                }
                pending.phase = "confirm_device".into();
                save(store, pending)?;
                None
            }
            (2, 6) => {
                if pending.acceptance.is_some() {
                    return Ok(());
                }
                let handoff = PairingHandoff::open(
                    &context,
                    active.channel.as_ref().ok_or(PairingError::RestartRequired)?,
                    &values[5],
                )
                .map_err(invalid)?;
                let (identity, signing) = accepted_identity(store, pending, &handoff)?;
                let acceptance = PairingCompletionContext::from_update_hash(
                    &context,
                    identity.account_id,
                    &values[5],
                    &handoff.device_certificate,
                    &handoff.key_bundle_update_hash,
                )
                .map_err(invalid)?
                .sign(&signing)
                .map_err(invalid)?;
                values.push(acceptance.to_vec());
                pending.handoff = Some(SecretVec::new(values[5].clone()));
                pending.certificate = Some(SecretVec::new(handoff.device_certificate.clone()));
                let encoded = encoded_transcript(&values)?;
                if !store
                    .save_paired_identity(pending, &identity, &acceptance, &encoded)
                    .map_err(stored)?
                {
                    return Err(PairingError::Conflict);
                }
                pending.generation += 1;
                pending.acceptance = Some(SecretVec::new(acceptance.to_vec()));
                pending.transcript = encoded;
                pending.phase = "admission_unconfirmed".into();
                active.channel = None;
                active.code = None;
                self.send_pairing_slot(store, pending, PairingStep::Acceptance, &acceptance)
                    .await?;
                pending.phase = "waiting_acceptance".into();
                save(store, pending)?;
                None
            }
            (1, 7) => {
                active.channel = None;
                self.complete_pairing(store, pending).await?;
                None
            }
            _ => None,
        };
        if let Some((step, payload)) = generated {
            if step.index() != values.len() {
                return Err(PairingError::InvalidResponse);
            }
            values.push(payload.clone());
            pending.transcript = encoded_transcript(&values)?;
            save(store, pending)?;
            self.send_pairing_slot(store, pending, step, &payload).await?;
        }
        Ok(())
    }

    /// Approve only the authenticated device name/platform displayed by the old device.
    pub async fn pairing_confirm(&self, store: Arc<Store>) -> Result<PairingStatus, PairingError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let mut pending = store.pairing_record().map_err(stored)?.ok_or(PairingError::NotActive)?;
        if pending.side != 1 || pending.phase != "confirm_device" {
            return Err(PairingError::NotActive);
        }
        let active =
            self.pairing.lock().map_err(invalid)?.take().ok_or(PairingError::RestartRequired)?;
        *self.pairing.lock().map_err(invalid)? = Some(active.public_marker());
        let result = if active.store_device != store.device_id()
            || active.pairing_id != pending.pairing_id
        {
            Err(PairingError::Conflict)
        } else if active.deadline <= Instant::now() {
            Err(PairingError::Expired)
        } else {
            self.prepare_handoff(&store, &mut pending, &active).await
        };
        match result {
            Ok(()) => {
                *self.pairing.lock().map_err(invalid)? = Some(active);
                self.pairing_status(&store)
            }
            Err(error) => {
                *self.pairing.lock().map_err(invalid)? = None;
                pending.phase = if pending.handoff.is_some() {
                    "admission_unconfirmed"
                } else {
                    "restart_required"
                }
                .into();
                save(&store, &mut pending)?;
                if pending.phase == "restart_required" {
                    let _ =
                        self.pairing_exchange(&store, &pending, Method::DELETE, "", None, 0).await;
                }
                Err(error)
            }
        }
    }

    async fn prepare_handoff(
        &self,
        store: &Arc<Store>,
        pending: &mut PairingRecord,
        active: &ActivePairing,
    ) -> Result<(), PairingError> {
        let peer = active.peer.as_ref().ok_or(PairingError::RestartRequired)?;
        let source = self.pairing_source(store).await.map_err(invalid)?;
        if active.deadline <= Instant::now() {
            return Err(PairingError::Expired);
        }
        let retained = RetainedAccount::load(store, &source.identity)?;
        let secrets = identity::Secrets::parse(&source.identity.private_material)?;
        let ark = SymmetricKey::from_slice(secrets.ark()).ok_or(PairingError::InvalidResponse)?;
        let signing = Ed25519SigningKey::from_bytes(secrets.account_signing()).map_err(invalid)?;
        let context = crypto_context(store, pending)?;
        if peer.context != context
            || source
                .certificates
                .iter()
                .any(|cert| cert.device_id == context.pairing().responder_device_id())
        {
            return Err(PairingError::InvalidResponse);
        }
        let certificate = DeviceCertificate::issue(
            &signing,
            context.pairing().responder_device_id(),
            source.identity.account_id,
            peer.signing_public_key.clone(),
            peer.kem_public_key.clone(),
            peer.display_name.clone(),
            peer.platform.clone(),
            peer.created_at,
        )
        .map_err(invalid)?;
        let mut recipients = source.certificates;
        recipients.push(certificate.clone());
        recipients.sort_by_key(|cert| cert.device_id);
        let wraps = recipients
            .iter()
            .map(|cert| {
                Ok(SyncAccountDeviceWrap {
                    device_id: cert.device_id,
                    wrapped_ark: DeviceArkWrap::seal(
                        source.identity.account_id,
                        cert.device_id,
                        &cert.kem_public_key,
                        &ark,
                    )
                    .map_err(invalid)?
                    .encode()
                    .to_vec(),
                })
            })
            .collect::<Result<Vec<_>, PairingError>>()?;
        let mut update = SyncAccountKeyBundleUpdate {
            revision: source.bundle.revision.checked_add(1).ok_or(PairingError::Conflict)?,
            device_wraps: wraps,
            account_signing_key: source.bundle.account_signing_key,
            account_kem_key: source.bundle.account_kem_key,
            recovery_blob: source.bundle.recovery_blob,
            signature: vec![0; 64],
        };
        update.signature = signing.sign(&update.signature_input().map_err(invalid)?).to_vec();
        let update_bytes = update.to_cbor().map_err(invalid)?;
        let certificate_bytes = certificate.encode().map_err(invalid)?;
        let own = update
            .device_wraps
            .iter()
            .find(|wrap| wrap.device_id == certificate.device_id)
            .ok_or(PairingError::InvalidResponse)?;
        let anchor = pairing_key_anchor(PairingKeyProjection {
            revision: update.revision,
            wrapped_ark: &own.wrapped_ark,
            account_signing_key: &update.account_signing_key,
            account_kem_key: &update.account_kem_key,
            recovery_blob: &update.recovery_blob,
        })
        .map_err(invalid)?;
        let handoff = PairingHandoff {
            context,
            account_id: source.identity.account_id,
            personal_vault_id: source.identity.personal_vault_id,
            account_signing_public_key: retained.signing_public,
            account_kem_public_key: retained.kem_public,
            device_certificate: certificate_bytes.clone(),
            revision: update.revision,
            key_bundle_update_hash: Sha256::digest(&update_bytes).into(),
            key_anchor: anchor,
            wrapped_ark: own.wrapped_ark.clone(),
            account_signing_key: update.account_signing_key,
            account_kem_key: update.account_kem_key,
            recovery_blob: update.recovery_blob,
            personal_vault_keys: source.vault_keys.to_cbor().map_err(invalid)?,
        };
        let frame = handoff
            .seal(active.channel.as_ref().ok_or(PairingError::RestartRequired)?)
            .map_err(invalid)?;
        let mut values = transcript(pending)?;
        if values.len() != 5 {
            return Err(PairingError::InvalidResponse);
        }
        values.push(frame.clone());
        pending.certificate = Some(SecretVec::new(certificate_bytes));
        pending.key_update = Some(SecretVec::new(update_bytes));
        pending.handoff = Some(SecretVec::new(frame.clone()));
        pending.transcript = encoded_transcript(&values)?;
        pending.phase = "waiting_acceptance".into();
        save(store, pending)?;
        self.send_pairing_slot(store, pending, PairingStep::Handoff, &frame).await
    }

    async fn complete_pairing(
        &self,
        store: &Arc<Store>,
        pending: &mut PairingRecord,
    ) -> Result<(), PairingError> {
        let body = pending.approval_request.as_ref().ok_or(PairingError::InvalidResponse)?;
        let response = self
            .pairing_exchange(store, pending, Method::POST, "/complete", Some(body.as_bytes()), 256)
            .await?;
        if response.status != 200 {
            return Err(PairingError::Conflict);
        }
        let receipt = PairingReceipt::from_json(response.body.as_bytes()).map_err(invalid)?;
        self.finish_pairing(store, pending, &receipt).await
    }

    async fn finish_pairing(
        &self,
        store: &Arc<Store>,
        pending: &mut PairingRecord,
        receipt: &PairingReceipt,
    ) -> Result<(), PairingError> {
        let identity = record(store)?;
        let retained = RetainedAccount::load(store, &identity)?;
        let target = if pending.side == 1 {
            pending.peer_id.ok_or(PairingError::InvalidResponse)?
        } else {
            store.device_id()
        };
        let revision = if pending.side == 1 {
            if pending.acceptance.is_none() || pending.approval_request.is_none() {
                return Err(PairingError::InvalidResponse);
            }
            SyncAccountKeyBundleUpdate::from_cbor(
                pending.key_update.as_ref().ok_or(PairingError::InvalidResponse)?.as_bytes(),
            )
            .map_err(invalid)?
            .revision
        } else {
            retained.revision
        };
        if receipt.account_id != identity.account_id
            || receipt.device_id != target
            || receipt.revision != revision
        {
            return Err(PairingError::InvalidResponse);
        }
        if pending.side == 2 {
            super::authenticate(store, &identity, self.transport.as_ref().map_err(|error| *error)?)
                .await?
                .require_authenticated()?;
            self.pairing_source(store).await.map_err(invalid)?;
        }
        pending.phase = "completed".into();
        save(store, pending)
    }

    /// Recover an exact durable checkpoint without reconstructing CPace or changing account roots.
    pub async fn pairing_recover(&self, store: Arc<Store>) -> Result<PairingStatus, PairingError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let mut pending = store.pairing_record().map_err(stored)?.ok_or(PairingError::NotActive)?;
        *self.pairing.lock().map_err(invalid)? = None;
        if pending.phase == "completed" {
            return self.pairing_status(&store);
        }
        if pending.side == 2 && store.personal_record().map_err(stored)?.is_some() {
            let identity = record(&store)?;
            if super::authenticate(
                &store,
                &identity,
                self.transport.as_ref().map_err(|error| *error)?,
            )
            .await
            .is_ok_and(|outcome| matches!(outcome, super::AuthenticationOutcome::Authenticated))
            {
                self.pairing_source(&store).await.map_err(invalid)?;
                pending.phase = "completed".into();
                save(&store, &mut pending)?;
                return self.pairing_status(&store);
            }
        }
        if pending.handoff.is_none() {
            return Err(PairingError::RestartRequired);
        }
        let snapshot = self.read_pairing(&store, &pending).await?;
        let values = merged_transcript(&pending, &snapshot)?;
        if pending.side == 1 && values.len() == 7 && pending.acceptance.is_none() {
            retain_acceptance(&store, &mut pending, &values)?;
        }
        if snapshot.state == RelayState::Completed {
            self.finish_pairing(
                &store,
                &mut pending,
                snapshot.receipt.as_ref().ok_or(PairingError::InvalidResponse)?,
            )
            .await?;
        } else if matches!(snapshot.state, RelayState::Cancelled | RelayState::Expired) {
            return Err(PairingError::Expired);
        } else {
            let deadline = bounded_deadline(Instant::now(), pending.local_expires_at)?;
            if pending.side == 1 && pending.acceptance.is_some() {
                self.complete_pairing(&store, &mut pending).await?;
                return self.pairing_status(&store);
            }
            if pending.side == 2 {
                let acceptance =
                    pending.acceptance.as_ref().ok_or(PairingError::InvalidResponse)?;
                self.send_pairing_slot(
                    &store,
                    &pending,
                    PairingStep::Acceptance,
                    acceptance.as_bytes(),
                )
                .await?;
                pending.phase = "waiting_acceptance".into();
                save(&store, &mut pending)?;
            } else {
                let frame = pending.handoff.as_ref().ok_or(PairingError::InvalidResponse)?;
                self.send_pairing_slot(&store, &pending, PairingStep::Handoff, frame.as_bytes())
                    .await?;
                pending.phase = "waiting_acceptance".into();
                save(&store, &mut pending)?;
            }
            *self.pairing.lock().map_err(invalid)? = Some(ActivePairing {
                store_device: store.device_id(),
                pairing_id: pending.pairing_id,
                deadline,
                next_poll: Instant::now() + Duration::from_secs(2),
                code: None,
                initiator: None,
                channel: None,
                peer: None,
                qr: None,
            });
        }
        self.pairing_status(&store)
    }

    /// Stop volatile secrets, retain account roots/checkpoints, and explicitly request cancellation.
    pub async fn pairing_cancel(&self, store: Arc<Store>) -> Result<PairingStatus, PairingError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        *self.pairing.lock().map_err(invalid)? = None;
        let mut pending = store.pairing_record().map_err(stored)?.ok_or(PairingError::NotActive)?;
        if pending.phase == "completed" {
            return Err(PairingError::Conflict);
        }
        pending.phase = if pending.handoff.is_some() || pending.acceptance.is_some() {
            "admission_unconfirmed"
        } else {
            "cancelled"
        }
        .into();
        save(&store, &mut pending)?;
        let response = self.pairing_exchange(&store, &pending, Method::DELETE, "", None, 0).await?;
        if response.status != 204 {
            return Err(PairingError::Conflict);
        }
        self.pairing_status(&store)
    }
}

fn merged_transcript(
    pending: &PairingRecord,
    snapshot: &PairingSnapshot,
) -> Result<Vec<Vec<u8>>, PairingError> {
    let mut values = transcript(pending)?;
    let own = if pending.side == 1 {
        scoplen_api::pairing::PairingRole::Initiator
    } else {
        scoplen_api::pairing::PairingRole::Responder
    };
    for (index, message) in snapshot.messages.iter().enumerate() {
        if index < values.len() {
            if values[index] != message.payload {
                return Err(PairingError::InvalidResponse);
            }
        } else {
            if message.step.role() == own {
                return Err(PairingError::InvalidResponse);
            }
            values.push(message.payload.clone());
        }
    }
    Ok(values)
}

fn retain_acceptance(
    store: &Store,
    pending: &mut PairingRecord,
    values: &[Vec<u8>],
) -> Result<(), PairingError> {
    if pending.side != 1 || values.len() != 7 {
        return Err(PairingError::InvalidResponse);
    }
    let cert = pending.certificate.as_ref().ok_or(PairingError::InvalidResponse)?;
    let update = pending.key_update.as_ref().ok_or(PairingError::InvalidResponse)?;
    let handoff = pending.handoff.as_ref().ok_or(PairingError::InvalidResponse)?;
    let certificate = DeviceCertificate::decode(cert.as_bytes()).map_err(invalid)?;
    PairingCompletionContext::new(
        &crypto_context(store, pending)?,
        certificate.account_id,
        handoff.as_bytes(),
        cert.as_bytes(),
        update.as_bytes(),
    )
    .map_err(invalid)?
    .verify(&certificate.signing_public_key, &values[6])
    .map_err(invalid)?;
    let request = PairingCompleteRequest {
        device_certificate: cert.as_bytes().to_vec(),
        key_bundle_update: update.as_bytes().to_vec(),
        new_device_signature: values[6].as_slice().try_into().map_err(invalid)?,
    }
    .to_json()
    .map_err(invalid)?;
    pending.acceptance = Some(SecretVec::new(values[6].clone()));
    pending.approval_request = Some(SecretVec::new(request));
    pending.transcript = encoded_transcript(values)?;
    pending.phase = "admission_unconfirmed".into();
    save(store, pending)
}

fn accepted_identity(
    store: &Store,
    pending: &PairingRecord,
    handoff: &PairingHandoff,
) -> Result<(PersonalRecord, P256SigningKey), PairingError> {
    let device = store.pairing_device().map_err(stored)?.ok_or(PairingError::InvalidResponse)?;
    let signing = P256SigningKey::from_bytes(device.signing.as_bytes()).map_err(invalid)?;
    let kem = DeviceKemKeyPair::from_private_bytes(device.kem.as_bytes()).map_err(invalid)?;
    let cert = DeviceCertificate::decode(&handoff.device_certificate).map_err(invalid)?;
    if handoff.context != crypto_context(store, pending)?
        || cert.device_id != store.device_id()
        || cert.account_id != handoff.account_id
        || cert.signing_public_key != signing.public_key_sec1()
        || cert.kem_public_key != kem.public_key()
        || cert.display_name != device.device_name
        || cert.platform != std::env::consts::OS
        || cert.created_at != device.created_at
    {
        return Err(PairingError::InvalidResponse);
    }
    let ark = DeviceArkWrap::decode(&handoff.wrapped_ark)
        .map_err(invalid)?
        .open(handoff.account_id, store.device_id(), &kem)
        .map_err(invalid)?;
    let account_signing = AccountSigningKeyWrap::decode(&handoff.account_signing_key)
        .map_err(invalid)?
        .open(handoff.account_id, &ark, &handoff.account_signing_public_key)
        .map_err(invalid)?;
    let account_kem = AccountKemKeyWrap::decode(&handoff.account_kem_key)
        .map_err(invalid)?
        .open(handoff.account_id, &ark, &handoff.account_kem_public_key)
        .map_err(invalid)?;
    let keys = SyncVaultKeysResponse::from_cbor(&handoff.personal_vault_keys).map_err(invalid)?;
    let mut current = None;
    for epoch in &keys.keys {
        let key = PersonalVaultKeyWrap::decode(&epoch.wrapped_vault_key)
            .map_err(invalid)?
            .open(
                handoff.account_id,
                handoff.personal_vault_id,
                u32::try_from(epoch.epoch).map_err(invalid)?,
                &ark,
            )
            .map_err(invalid)?;
        current = Some(key);
    }
    let current = current.ok_or(PairingError::InvalidResponse)?;
    let mut material = Zeroizing::new(Vec::with_capacity(193));
    material.push(2);
    for bytes in [
        device.signing.as_bytes(),
        device.kem.as_bytes(),
        ark.as_bytes(),
        account_signing.private_key_bytes().as_bytes(),
        account_kem.private_key_bytes().as_bytes(),
        current.as_bytes(),
    ] {
        material.extend_from_slice(bytes);
    }
    Ok((
        PersonalRecord {
            origin: pending.origin.clone(),
            account_id: handoff.account_id,
            personal_vault_id: handoff.personal_vault_id,
            device_name: device.device_name,
            private_material: SecretVec::new(material.to_vec()),
            enrollment_request: None,
            paired_handoff: Some(handoff.encode().map_err(invalid)?),
            recovery_saved: false,
            recovery_confirmed: false,
            enrollment_attempted: false,
            access_expires_at: None,
            refresh_expires_at: None,
            auth_generation: 0,
            auth_scope: None,
            refresh_available: false,
            session_established: false,
            refresh_retry_at: None,
        },
        signing,
    ))
}

#[cfg(test)]
mod tests;
