// SPDX-License-Identifier: Apache-2.0
//! Organization SSH authorization and independent local signing material.

use scoplen_api::{
    auth::DeviceAccessOperation,
    certificate::{CertificateIssuanceRequest, CertificateIssuanceResponse, CertificateTargets},
    organization::OrganizationListQuery,
    user_ca::{UserCaCreateRequest, UserCaPage, UserCaResource},
};
use scoplen_crypto::{Ed25519SigningKey, SecretVec, generate_ed25519_signing_key};
use scoplen_ssh::{CertificateValidationPolicy, UserCertificate};
use serde::{Deserialize, Serialize};
use specta::Type;
use uuid::Uuid;

use super::{
    PersonalServer, PersonalServerError, TeamError, TeamFailure, parse_id, record, storage,
};
use crate::store::{
    Store,
    team_ssh::{TeamSshCertificateRecord, TeamSshOwner},
    team_ssh_operations::TeamSshOperationRecord,
};

mod operations;
pub use operations::{
    TeamSshHostSetup, TeamSshOperationKind, TeamSshOperationView, TeamUserCaView,
};

/// Immutable source of a team SSH intent, verified against the captured Account store.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamSshSource {
    /// Canonical HTTPS deployment origin.
    pub origin: String,
    /// Account whose encrypted local store owns this intent.
    pub account_id: String,
    /// Organization owning every resolved inventory object.
    pub organization_id: String,
    /// Enrolled installation whose local signer is selected.
    pub device_id: String,
}

/// Current local authorization fence, independent of periodic pull generations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TeamSshAuthority {
    pub vault: Uuid,
    pub revision: u64,
    pub generation: Uuid,
}

/// A validated certificate and the local signer it names; never serialized through IPC.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeamSshCertificate {
    /// Shared parsed certificate, validated for this source and exact Host/user principal.
    pub certificate: UserCertificate,
    /// Independent Ed25519 signing seed, retained only inside the encrypted Rust boundary.
    pub signing_key: SecretVec,
    /// True when an unexpired previously authorized certificate satisfied this connection.
    pub cached: bool,
    source: TeamSshSource,
    authority: TeamSshAuthority,
}

/// Fixed, content-free errors for Organization SSH preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type, thiserror::Error)]
#[serde(rename_all = "camelCase")]
pub enum TeamSshFailure {
    /// The source differs from the captured active Account or Device.
    #[error("This team connection belongs to another Account or device. Reopen its team assets.")]
    InvalidSource,
    /// No current view or eligible previously authorized certificate is available.
    #[error("Refresh this team's assets before requesting a new SSH certificate.")]
    ViewRequired,
    /// Membership or visibility was invalidated after this preparation started.
    #[error("Team access changed. Refresh the team's assets before connecting again.")]
    AuthorityChanged,
    /// An administrator has not provisioned the team's user CA.
    #[error("This team has no SSH user CA. Ask an administrator to complete SSH setup.")]
    CaMissing,
    /// The response could not establish the exact issuing CA, subject, source or principal.
    #[error(
        "The SSH certificate could not be verified for this team and Host. No connection was authorized."
    )]
    InvalidCertificate,
    /// A dispatched issuance needs explicit confirmation using its original request.
    #[error(
        "The certificate request may have completed. Confirm the original request before trying again."
    )]
    IssuanceUnknown,
    /// A dispatched CA provisioning operation needs explicit original-request confirmation.
    #[error(
        "The SSH CA may have been created. Confirm the original setup request before creating another."
    )]
    CaUnknown,
    /// Another original request must be resolved before preparing its replacement.
    #[error("Resolve the retained SSH setup request before preparing another.")]
    PreparationPending,
    /// Original-request confirmation no longer fits its fixed receipt lifetime.
    #[error(
        "The original request's confirmation window ended. Refresh and review SSH setup before continuing."
    )]
    OperationExpired,
    /// The selected original operation is no longer retained.
    #[error("This SSH setup request is no longer retained. Refresh its status.")]
    OperationMissing,
}

/// Existing Account/team failures and safe Organization SSH failure codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type, thiserror::Error)]
#[serde(untagged)]
pub enum TeamSshError {
    /// Authenticated Account or local-store failure.
    #[error(transparent)]
    Personal(#[from] PersonalServerError),
    /// Current team authority or resource failure.
    #[error(transparent)]
    Team(#[from] TeamFailure),
    /// Certificate or source-specific failure.
    #[error(transparent)]
    Ssh(#[from] TeamSshFailure),
}

impl From<TeamError> for TeamSshError {
    fn from(error: TeamError) -> Self {
        match error {
            TeamError::Personal(error) => Self::Personal(error),
            TeamError::Team(error) => Self::Team(error),
        }
    }
}

impl TeamSshSource {
    pub(crate) fn owner(&self, store: &Store) -> Result<TeamSshOwner, TeamSshError> {
        let identity = record(store)?;
        let account = parse_id(&self.account_id).map_err(|_| TeamSshFailure::InvalidSource)?;
        let organization =
            parse_id(&self.organization_id).map_err(|_| TeamSshFailure::InvalidSource)?;
        let device = parse_id(&self.device_id).map_err(|_| TeamSshFailure::InvalidSource)?;
        if self.origin != identity.origin
            || account != identity.account_id
            || device != store.device_id()
        {
            return Err(TeamSshFailure::InvalidSource.into());
        }
        Ok(TeamSshOwner { origin: self.origin.clone(), account, organization, device })
    }
}

impl PersonalServer {
    pub(crate) fn team_ssh_authority(
        &self,
        store: &Store,
        source: &TeamSshSource,
    ) -> Result<Option<super::super::TeamSshAuthority>, TeamSshError> {
        let owner = source.owner(store)?;
        if store.team_ssh_signer(&owner).map_err(storage)?.is_none() {
            let identity = record(store)?;
            if store
                .team_assets_record(&identity, owner.organization)
                .map_err(storage)?
                .is_none_or(|view| view.phase != 1)
            {
                return Ok(None);
            }
            let seed = generate_ed25519_signing_key().map_err(|_| PersonalServerError::Identity)?;
            store
                .create_team_ssh_signer(
                    &owner,
                    &SecretVec::new(seed.private_key_bytes().as_bytes().to_vec()),
                )
                .map_err(storage)?;
        }
        authority(store, &owner)
    }

    /// Obtain only this device's exact team/Host/user certificate after host-key review.
    /// An eligible local certificate performs no control-plane request.
    pub async fn team_ssh_certificate(
        &self,
        store: std::sync::Arc<Store>,
        source: &TeamSshSource,
        host: Uuid,
        remote_user: &str,
    ) -> Result<TeamSshCertificate, TeamSshError> {
        let owner = source.owner(&store)?;
        let captured =
            self.team_ssh_authority(&store, source)?.ok_or(TeamSshFailure::ViewRequired)?;
        let identity = record(&store)?;
        let snapshot = store
            .team_ssh_snapshot(&identity, owner.organization, captured.vault, captured.revision)
            .map_err(storage)?
            .ok_or(TeamSshFailure::ViewRequired)?;
        if !snapshot.iter().any(|object| {
            object.id == host && object.object_type == scoplen_model::ObjectType::HOST
        }) {
            return Err(TeamSshFailure::ViewRequired.into());
        }
        let signer =
            store.team_ssh_signer(&owner).map_err(storage)?.ok_or(TeamSshFailure::ViewRequired)?;
        let request = CertificateIssuanceRequest::new(
            public_key(&signer.seed)?,
            CertificateTargets::Hosts(vec![host]),
            remote_user,
            1800,
        )
        .map_err(|_| TeamSshFailure::InvalidCertificate)?;
        if let Some(cached) =
            store.team_ssh_certificate(&owner, host, remote_user).map_err(storage)?
        {
            let ca = UserCaResource::from_json(cached.ca.as_bytes())
                .map_err(|_| TeamSshFailure::InvalidCertificate)?;
            let original = CertificateIssuanceRequest::from_json(cached.request.as_bytes())
                .map_err(|_| TeamSshFailure::InvalidCertificate)?;
            let response = CertificateIssuanceResponse::from_json(cached.response.as_bytes())
                .map_err(|_| TeamSshFailure::InvalidCertificate)?;
            if original != request || cached.generation != captured.generation {
                return Err(TeamSshFailure::InvalidCertificate.into());
            }
            let parsed = ssh_key::Certificate::from_openssh(&response.certificate)
                .map_err(|_| TeamSshFailure::InvalidCertificate)?;
            if parsed.valid_before() > super::super::now()? {
                let certificate = validate_certificate(&owner, &ca, &request, &response)?;
                let result = TeamSshCertificate {
                    certificate,
                    signing_key: signer.seed,
                    cached: true,
                    source: source.clone(),
                    authority: captured,
                };
                result.current(&store)?;
                return Ok(result);
            }
        }
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        require_ready(&store, &owner, captured)?;
        if let Some(previous) = store.team_ssh_operation(&owner, 1).map_err(storage)? {
            if previous.phase == 1 {
                return Err(TeamSshFailure::IssuanceUnknown.into());
            }
            if previous.phase == 0 {
                if previous.payload.as_bytes()
                    != request.to_json().map_err(|_| TeamSshFailure::InvalidCertificate)?.as_slice()
                    || previous.generation != Some(captured.generation)
                {
                    return Err(TeamSshFailure::PreparationPending.into());
                }
                return self.issue_retained_certificate(&store, source, &owner, &previous).await;
            }
            if !store
                .discard_team_ssh_operation(&owner, &previous, super::super::now()?)
                .map_err(storage)?
            {
                return Err(PersonalServerError::Busy.into());
            }
        }
        let ca = self.read_team_user_ca(&store, source).await?.ok_or(TeamSshFailure::CaMissing)?;
        require_ready(&store, &owner, captured)?;
        let pending = TeamSshOperationRecord {
            kind: 1,
            id: scoplen_model::new_uuid_v7().map_err(|_| PersonalServerError::Identity)?,
            payload: SecretVec::new(
                request.to_json().map_err(|_| TeamSshFailure::InvalidCertificate)?,
            ),
            ca: Some(SecretVec::new(ca.to_json().map_err(|_| TeamSshFailure::InvalidCertificate)?)),
            generation: Some(captured.generation),
            phase: 0,
            first_attempt: None,
            response: None,
        };
        if !store.prepare_team_ssh_operation(&owner, &pending).map_err(storage)? {
            return Err(TeamSshFailure::PreparationPending.into());
        }
        self.issue_retained_certificate(&store, source, &owner, &pending).await
    }

    async fn issue_retained_certificate(
        &self,
        store: &Store,
        source: &TeamSshSource,
        owner: &TeamSshOwner,
        pending: &TeamSshOperationRecord,
    ) -> Result<TeamSshCertificate, TeamSshError> {
        let finished = self.execute_team_ssh_operation(store, source, pending).await?;
        self.certificate_from_operation(store, source, owner, &finished, false)
    }

    fn certificate_from_operation(
        &self,
        store: &Store,
        source: &TeamSshSource,
        owner: &TeamSshOwner,
        operation: &TeamSshOperationRecord,
        cached: bool,
    ) -> Result<TeamSshCertificate, TeamSshError> {
        let captured = authority(store, owner)?.ok_or(TeamSshFailure::AuthorityChanged)?;
        if operation.generation != Some(captured.generation) {
            return Err(TeamSshFailure::AuthorityChanged.into());
        }
        require_ready(store, owner, captured)?;
        let ca_bytes = operation.ca.as_ref().ok_or(TeamSshFailure::InvalidCertificate)?;
        let response_bytes =
            operation.response.as_ref().ok_or(TeamSshFailure::InvalidCertificate)?;
        let ca = UserCaResource::from_json(ca_bytes.as_bytes())
            .map_err(|_| TeamSshFailure::InvalidCertificate)?;
        let request = CertificateIssuanceRequest::from_json(operation.payload.as_bytes())
            .map_err(|_| TeamSshFailure::InvalidCertificate)?;
        let response = CertificateIssuanceResponse::from_json(response_bytes.as_bytes())
            .map_err(|_| TeamSshFailure::InvalidCertificate)?;
        let certificate = validate_certificate(owner, &ca, &request, &response)?;
        let CertificateTargets::Hosts(hosts) = &request.targets else {
            return Err(TeamSshFailure::InvalidCertificate.into());
        };
        let [host] = hosts.as_slice() else {
            return Err(TeamSshFailure::InvalidCertificate.into());
        };
        let signer = store
            .team_ssh_signer(owner)
            .map_err(storage)?
            .ok_or(TeamSshFailure::AuthorityChanged)?;
        if request.public_key != public_key(&signer.seed)? {
            return Err(TeamSshFailure::InvalidCertificate.into());
        }
        store
            .save_team_ssh_certificate(
                owner,
                *host,
                &request.remote_user,
                &TeamSshCertificateRecord {
                    generation: captured.generation,
                    ca: ca_bytes.clone(),
                    request: operation.payload.clone(),
                    response: response_bytes.clone(),
                },
            )
            .map_err(storage)?;
        let result = TeamSshCertificate {
            certificate,
            signing_key: signer.seed,
            cached,
            source: source.clone(),
            authority: captured,
        };
        result.current(store)?;
        Ok(result)
    }

    async fn read_team_user_ca(
        &self,
        store: &Store,
        source: &TeamSshSource,
    ) -> Result<Option<UserCaResource>, TeamSshError> {
        let owner = source.owner(store)?;
        let session = self.team_session(store, DeviceAccessOperation::UserCaList).await?;
        let path = format!("/api/v1/orgs/{}/certificate-authorities", owner.organization);
        let query = OrganizationListQuery { limit: 1, cursor: None };
        let proof = session.proof("GET", &path)?;
        let response = self
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .team_get(
                &owner.origin,
                &format!("{path}?limit=1"),
                session.token()?,
                &proof,
                scoplen_api::user_ca::MAX_USER_CA_PAGE_BYTES,
            )
            .await?;
        session.current(store)?;
        source.owner(store)?;
        if response.status != 200 {
            return Err(super::read_error(store, &session, &response)?.into());
        }
        let page = UserCaPage::from_http_json(
            response.body.as_bytes(),
            response.cache_control.as_deref(),
            response.pragma.as_deref(),
        )
        .map_err(|_| TeamFailure::InvalidTeamResponse)?;
        page.validate_for_query(query).map_err(|_| TeamFailure::InvalidTeamResponse)?;
        if page.next_cursor.is_some() {
            return Err(TeamFailure::InvalidTeamResponse.into());
        }
        Ok(page.items.into_iter().next())
    }
}

impl TeamSshCertificate {
    /// Recheck the captured source, local authority and actual expiry immediately before use.
    pub fn current(&self, store: &Store) -> Result<(), TeamSshError> {
        let owner = self.source.owner(store)?;
        if authority(store, &owner)? != Some(self.authority)
            || super::super::now()? >= self.certificate.certificate().valid_before()
        {
            return Err(TeamSshFailure::AuthorityChanged.into());
        }
        Ok(())
    }
}

fn authority(
    store: &Store,
    owner: &TeamSshOwner,
) -> Result<Option<TeamSshAuthority>, TeamSshError> {
    let Some(signer) = store.team_ssh_signer(owner).map_err(storage)? else {
        return Ok(None);
    };
    if !signer.active {
        return Ok(None);
    }
    let (Some(vault), Some(revision)) = (signer.vault, signer.revision) else {
        return Err(TeamSshFailure::AuthorityChanged.into());
    };
    Ok(Some(TeamSshAuthority { vault, revision, generation: signer.generation }))
}

fn public_key(seed: &SecretVec) -> Result<String, TeamSshError> {
    let key = Ed25519SigningKey::from_bytes(seed.as_bytes())
        .map_err(|_| PersonalServerError::Identity)?;
    ssh_key::PublicKey::from(ssh_key::public::Ed25519PublicKey(key.public_key()))
        .to_openssh()
        .map_err(|_| TeamSshFailure::InvalidCertificate.into())
}

fn require_ready(
    store: &Store,
    owner: &TeamSshOwner,
    captured: TeamSshAuthority,
) -> Result<(), TeamSshError> {
    if authority(store, owner)? != Some(captured) {
        return Err(TeamSshFailure::AuthorityChanged.into());
    }
    let identity = record(store)?;
    let view = store
        .team_assets_record(&identity, owner.organization)
        .map_err(storage)?
        .ok_or(TeamSshFailure::ViewRequired)?;
    if view.phase != 1
        || view.vault != Some(captured.vault)
        || view.revision != Some(captured.revision)
    {
        return Err(TeamSshFailure::ViewRequired.into());
    }
    Ok(())
}

fn validate_certificate(
    owner: &TeamSshOwner,
    ca: &UserCaResource,
    request: &CertificateIssuanceRequest,
    response: &CertificateIssuanceResponse,
) -> Result<UserCertificate, TeamSshError> {
    validate_certificate_at(owner, ca, request, response, super::super::now()?)
}

fn validate_certificate_at(
    owner: &TeamSshOwner,
    ca: &UserCaResource,
    request: &CertificateIssuanceRequest,
    response: &CertificateIssuanceResponse,
    now: u64,
) -> Result<UserCertificate, TeamSshError> {
    let invalid = || TeamSshFailure::InvalidCertificate;
    ca.validate().map_err(|_| invalid())?;
    response.validate_request_subject(request).map_err(|_| invalid())?;
    let CertificateTargets::Hosts(hosts) = &request.targets else {
        return Err(invalid().into());
    };
    let [host] = hosts.as_slice() else {
        return Err(invalid().into());
    };
    let parsed =
        ssh_key::Certificate::from_openssh(&response.certificate).map_err(|_| invalid())?;
    let principal = scoped_principal(owner.organization, *host, &request.remote_user);
    let key_id =
        format!("spl:{}:{}:{}:{}", owner.organization, owner.account, owner.device, response.id);
    let ca_key = ssh_key::PublicKey::from_openssh(&ca.public_key).map_err(|_| invalid())?;
    if parsed.signature_key() != ca_key.key_data()
        || parsed.key_id() != key_id
        || parsed.serial() == 0
        || parsed.valid_principals() != [principal.clone()]
        || parsed.valid_before().saturating_sub(parsed.valid_after())
            > u64::from(request.ttl_seconds) + 60
        || parsed.extensions().get("org@scoplen.com") != Some(&owner.organization.to_string())
        || parsed.extensions().iter().any(|(name, value)| match name.as_str() {
            "org@scoplen.com" => false,
            "permit-pty" | "permit-port-forwarding" | "permit-agent-forwarding" => {
                !value.is_empty()
            }
            _ => true,
        })
    {
        return Err(invalid().into());
    }
    let bytes = parsed.to_bytes().map_err(|_| invalid())?;
    UserCertificate::parse_and_validate(
        &bytes,
        &CertificateValidationPolicy::user(&principal, now)
            .with_allowed_critical_options(&["source-address"]),
    )
    .map_err(|_| invalid().into())
}

fn scoped_principal(organization: Uuid, host: Uuid, remote_user: &str) -> String {
    format!("spl:{organization}:h:{host}:{remote_user}")
}
