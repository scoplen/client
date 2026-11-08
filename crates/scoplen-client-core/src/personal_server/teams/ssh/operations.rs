// SPDX-License-Identifier: Apache-2.0
//! Explicit original-request confirmation for native SSH setup and issuance.

use reqwest::Method;

use super::*;
use crate::personal_server::TeamCreationPhase;

/// One of the two retained native SSH setup requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum TeamSshOperationKind {
    /// Provision the initial Organization-owned local user CA.
    UserCa,
    /// Confirm an original certificate request without extending its validity.
    Certificate,
}

impl TeamSshOperationKind {
    fn value(self) -> i64 {
        match self {
            Self::UserCa => 0,
            Self::Certificate => 1,
        }
    }
}

/// Public trust material from the authenticated selected team; never a private CA key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamUserCaView {
    /// Captured origin/Account/Organization/Device that authenticated this read.
    pub source: TeamSshSource,
    /// Exact immutable CA id.
    pub id: String,
    /// Canonical public Ed25519 key for explicit sshd configuration.
    pub public_key: String,
    /// SHA256 fingerprint of that public key.
    pub fingerprint: String,
    /// Exact per-Login configuration derived only from the complete current readable view.
    pub setups: Vec<TeamSshHostSetup>,
}

/// Manual sshd setup for one visible Login and its independently visible same-team Host.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamSshHostSetup {
    /// Login identifying this setup row.
    pub profile_id: String,
    /// Immutable Host scope; a matching username on another Host is insufficient.
    pub host_id: String,
    /// Ordinary local SSH username whose home holds the principals file.
    pub remote_user: String,
    /// Exact authorized principal to add on this Host for this local user.
    pub principal: String,
    /// System file to which the administrator adds the displayed public CA.
    pub ca_file: String,
    /// File relative to this local user's home directory.
    pub principals_file: String,
    /// sshd settings to review against the existing configuration before sshd -t and reload.
    pub sshd_config: String,
}

/// Durable safe recovery state, without keys, raw request bodies, tokens or certificates.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamSshOperationView {
    /// Exact source owning this original operation.
    pub source: TeamSshSource,
    /// Local original idempotency key; this id grants no server authority.
    pub operation_id: String,
    /// CA provisioning or certificate confirmation.
    pub kind: TeamSshOperationKind,
    /// Explicitly permitted recovery action.
    pub phase: TeamCreationPhase,
    /// Receipt deadline, as Unix seconds without JavaScript precision loss.
    pub retry_until: Option<String>,
    /// Exact Host of a retained issuance; absent for CA setup.
    pub host_id: Option<String>,
    /// Ordinary SSH username; absent for CA setup.
    pub remote_user: Option<String>,
}

impl PersonalServer {
    /// Read protected original-operation status without network access.
    pub fn team_ssh_operations(
        &self,
        store: &Store,
        source: &TeamSshSource,
    ) -> Result<Vec<TeamSshOperationView>, TeamSshError> {
        let owner = source.owner(store)?;
        let mut operations = Vec::new();
        for kind in [TeamSshOperationKind::UserCa, TeamSshOperationKind::Certificate] {
            if let Some(pending) =
                store.team_ssh_operation(&owner, kind.value()).map_err(storage)?
            {
                operations.push(operation_view(source, &pending)?);
            }
        }
        Ok(operations)
    }

    /// Fetch current public CA trust using the selected Account's enrolled Device session.
    pub async fn team_user_ca(
        &self,
        store: std::sync::Arc<Store>,
        source: &TeamSshSource,
    ) -> Result<Option<TeamUserCaView>, TeamSshError> {
        let owner = source.owner(&store)?;
        let Some(ca) = self.read_team_user_ca(&store, source).await? else {
            return Ok(None);
        };
        let identity = record(&store)?;
        let view = store.team_assets_record(&identity, owner.organization).map_err(storage)?;
        let mut setups = Vec::new();
        if let Some(view) = view.filter(|view| view.phase == 1) {
            use crate::repository::{AccessProfile, Record};
            for object in &view.objects {
                if object.object_type != scoplen_model::ObjectType::ACCESS_PROFILE {
                    continue;
                }
                scoplen_api::inventory::InventoryFields::from_object(object)
                    .map_err(|_| TeamFailure::InvalidTeamResponse)?;
                let profile =
                    AccessProfile::read(object).map_err(|_| TeamFailure::InvalidTeamResponse)?;
                let Some(host) = view.objects.iter().find(|host| {
                    host.id == profile.host && host.object_type == scoplen_model::ObjectType::HOST
                }) else {
                    continue;
                };
                scoplen_api::inventory::InventoryFields::from_object(host)
                    .map_err(|_| TeamFailure::InvalidTeamResponse)?;
                setups.push(TeamSshHostSetup {
                    profile_id: object.id.to_string(), host_id: profile.host.to_string(),
                    principal: scoped_principal(owner.organization, profile.host, &profile.username),
                    remote_user: profile.username,
                    ca_file: "/etc/ssh/scoplen_user_ca_keys".into(),
                    principals_file: ".ssh/scoplen_principals".into(),
                    sshd_config: "TrustedUserCAKeys /etc/ssh/scoplen_user_ca_keys\nAuthorizedPrincipalsFile .ssh/scoplen_principals".into(),
                });
            }
        }
        Ok(Some(TeamUserCaView {
            source: source.clone(),
            id: ca.id.to_string(),
            public_key: ca.public_key,
            fingerprint: ca.fingerprint,
            setups,
        }))
    }

    /// Prepare one explicit setup intent. The server generates its independent CA key.
    pub fn prepare_team_user_ca(
        &self,
        store: &Store,
        source: &TeamSshSource,
    ) -> Result<TeamSshOperationView, TeamSshError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let owner = source.owner(store)?;
        if store.team_ssh_operation(&owner, 0).map_err(storage)?.is_some() {
            return Err(TeamSshFailure::PreparationPending.into());
        }
        let id = scoplen_model::new_uuid_v7().map_err(|_| PersonalServerError::Identity)?;
        let request = UserCaCreateRequest::new(id).map_err(|_| TeamFailure::InvalidTeamResponse)?;
        let pending = TeamSshOperationRecord {
            kind: 0,
            id: scoplen_model::new_uuid_v7().map_err(|_| PersonalServerError::Identity)?,
            payload: SecretVec::new(
                request.to_json().map_err(|_| TeamFailure::InvalidTeamResponse)?,
            ),
            ca: None,
            generation: None,
            phase: 0,
            first_attempt: None,
            response: None,
        };
        if !store.prepare_team_ssh_operation(&owner, &pending).map_err(storage)? {
            return Err(TeamSshFailure::PreparationPending.into());
        }
        operation_view(source, &pending)
    }

    /// Explicitly send or confirm the exact protected original key/body within its receipt window.
    pub async fn confirm_team_ssh_operation(
        &self,
        store: std::sync::Arc<Store>,
        source: &TeamSshSource,
        kind: TeamSshOperationKind,
        operation_id: &str,
    ) -> Result<TeamSshOperationView, TeamSshError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let owner = source.owner(&store)?;
        let pending = load_operation(&store, &owner, kind, operation_id)?;
        let confirmed = self.execute_team_ssh_operation(&store, source, &pending).await?;
        if kind == TeamSshOperationKind::Certificate {
            self.certificate_from_operation(&store, source, &owner, &confirmed, false)?;
        }
        operation_view(source, &confirmed)
    }

    /// Clear known state, or explicitly archive expired uncertainty after reviewing current state.
    pub fn discard_team_ssh_operation(
        &self,
        store: &Store,
        source: &TeamSshSource,
        kind: TeamSshOperationKind,
        operation_id: &str,
    ) -> Result<(), TeamSshError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let owner = source.owner(store)?;
        let pending = load_operation(store, &owner, kind, operation_id)?;
        if !store
            .discard_team_ssh_operation(&owner, &pending, super::super::super::now()?)
            .map_err(storage)?
        {
            return Err(unknown(pending.kind));
        }
        Ok(())
    }

    pub(super) async fn execute_team_ssh_operation(
        &self,
        store: &Store,
        source: &TeamSshSource,
        pending: &TeamSshOperationRecord,
    ) -> Result<TeamSshOperationRecord, TeamSshError> {
        let owner = source.owner(store)?;
        let state = operation_view(source, pending)?;
        if state.phase == TeamCreationPhase::Confirmed {
            return store
                .team_ssh_operation(&owner, pending.kind)
                .map_err(storage)?
                .ok_or_else(|| TeamSshFailure::OperationMissing.into());
        }
        if state.phase == TeamCreationPhase::Expired {
            return Err(TeamSshFailure::OperationExpired.into());
        }
        let operation = if pending.kind == 0 {
            DeviceAccessOperation::UserCaCreate
        } else {
            DeviceAccessOperation::UserCertificateIssue
        };
        let session = self.team_session(store, operation).await?;
        source.owner(store)?;
        let path = format!(
            "/api/v1/orgs/{}/{}",
            owner.organization,
            if pending.kind == 0 { "certificate-authorities" } else { "certificates" }
        );
        let proof = session.proof("POST", &path)?;
        if !store
            .dispatch_team_ssh_operation(
                &owner,
                pending,
                &session.access,
                super::super::super::now()?,
            )
            .map_err(storage)?
        {
            return Err(TeamSshFailure::AuthorityChanged.into());
        }
        let sent = store
            .team_ssh_operation(&owner, pending.kind)
            .map_err(storage)?
            .ok_or(TeamSshFailure::OperationMissing)?;
        let response = self
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .team_exchange(
                &owner.origin,
                &path,
                Method::POST,
                Some(sent.payload.as_bytes()),
                session.token()?,
                &proof,
                Some(sent.id),
                None,
                if pending.kind == 0 { 16_384 } else { 131_072 },
            )
            .await;
        let response = match response {
            Ok(response) => response,
            Err(PersonalServerError::ConnectionBeforeRequest) if pending.phase == 0 => {
                if !store.finish_team_ssh_operation(&owner, &sent, None).map_err(storage)? {
                    return Err(PersonalServerError::Storage.into());
                }
                return Err(PersonalServerError::ConnectionBeforeRequest.into());
            }
            Err(_) => return Err(unknown(pending.kind)),
        };
        session.current(store)?;
        source.owner(store)?;
        if response.status == 201 {
            let canonical = if pending.kind == 0 {
                let original = UserCaCreateRequest::from_json(sent.payload.as_bytes())
                    .map_err(|_| unknown(0))?;
                let ca = UserCaResource::from_http_json(
                    response.body.as_bytes(),
                    response.etag.as_deref(),
                    response.cache_control.as_deref(),
                    response.pragma.as_deref(),
                )
                .map_err(|_| unknown(0))?;
                ca.validate_for_id(original.id).map_err(|_| unknown(0))?;
                ca.to_json().map_err(|_| unknown(0))?
            } else {
                let request = CertificateIssuanceRequest::from_json(sent.payload.as_bytes())
                    .map_err(|_| unknown(1))?;
                let ca = UserCaResource::from_json(
                    sent.ca.as_ref().ok_or(TeamSshFailure::InvalidCertificate)?.as_bytes(),
                )
                .map_err(|_| unknown(1))?;
                let certificate = CertificateIssuanceResponse::from_http_json(
                    response.body.as_bytes(),
                    response.etag.as_deref(),
                    response.cache_control.as_deref(),
                    response.pragma.as_deref(),
                )
                .map_err(|_| unknown(1))?;
                let parsed = ssh_key::Certificate::from_openssh(&certificate.certificate)
                    .map_err(|_| unknown(1))?;
                // Confirmation retains an expired original result without treating it as renewal.
                validate_certificate_at(&owner, &ca, &request, &certificate, parsed.valid_after())?;
                certificate.to_json().map_err(|_| unknown(1))?
            };
            if !store.finish_team_ssh_operation(&owner, &sent, Some(&canonical)).map_err(storage)? {
                return Err(PersonalServerError::Storage.into());
            }
            return store
                .team_ssh_operation(&owner, sent.kind)
                .map_err(storage)?
                .ok_or_else(|| TeamSshFailure::OperationMissing.into());
        }
        let problem = super::super::problem(&response).map_err(|_| unknown(pending.kind))?;
        if pending.phase == 0
            && !problem.changed
            && problem.code.as_str() != "organization.conflict"
            && !store.finish_team_ssh_operation(&owner, &sent, None).map_err(storage)?
        {
            return Err(PersonalServerError::Storage.into());
        }
        if matches!(problem.status, 401 | 403 | 404) && !problem.changed {
            store
                .invalidate_team_assets(&session.identity, owner.organization, None)
                .map_err(storage)?;
        }
        if problem.code.as_str() == "organization.commit_outcome_unknown" {
            return Err(unknown(pending.kind));
        }
        Err(super::super::response_error(&problem)
            .map(TeamSshError::from)
            .unwrap_or_else(|| unknown(pending.kind)))
    }
}

fn load_operation(
    store: &Store,
    owner: &TeamSshOwner,
    kind: TeamSshOperationKind,
    operation_id: &str,
) -> Result<TeamSshOperationRecord, TeamSshError> {
    let id = parse_id(operation_id)?;
    let pending = store
        .team_ssh_operation(owner, kind.value())
        .map_err(storage)?
        .ok_or(TeamSshFailure::OperationMissing)?;
    if pending.id != id {
        return Err(TeamSshFailure::OperationMissing.into());
    }
    Ok(pending)
}

fn operation_view(
    source: &TeamSshSource,
    pending: &TeamSshOperationRecord,
) -> Result<TeamSshOperationView, TeamSshError> {
    let deadline = pending.first_attempt.map(|time| time.saturating_add(86_400));
    let phase = match pending.phase {
        2 => TeamCreationPhase::Confirmed,
        0 | 1
            if deadline
                .is_some_and(|time| super::super::super::now().is_ok_and(|now| now >= time)) =>
        {
            TeamCreationPhase::Expired
        }
        0 => TeamCreationPhase::Prepared,
        1 => TeamCreationPhase::Unknown,
        _ => return Err(TeamSshFailure::OperationMissing.into()),
    };
    let (kind, host_id, remote_user) = if pending.kind == 0 {
        UserCaCreateRequest::from_json(pending.payload.as_bytes())
            .map_err(|_| TeamFailure::InvalidTeamResponse)?;
        (TeamSshOperationKind::UserCa, None, None)
    } else {
        let request = CertificateIssuanceRequest::from_json(pending.payload.as_bytes())
            .map_err(|_| TeamSshFailure::InvalidCertificate)?;
        let CertificateTargets::Hosts(hosts) = request.targets else {
            return Err(TeamSshFailure::InvalidCertificate.into());
        };
        let [host] = hosts.as_slice() else {
            return Err(TeamSshFailure::InvalidCertificate.into());
        };
        (TeamSshOperationKind::Certificate, Some(host.to_string()), Some(request.remote_user))
    };
    Ok(TeamSshOperationView {
        source: source.clone(),
        operation_id: pending.id.to_string(),
        kind,
        phase,
        retry_until: deadline.map(|time| time.to_string()),
        host_id,
        remote_user,
    })
}

fn unknown(kind: i64) -> TeamSshError {
    if kind == 0 { TeamSshFailure::CaUnknown } else { TeamSshFailure::IssuanceUnknown }.into()
}
