// SPDX-License-Identifier: Apache-2.0
//! Named invitations and current membership operations, owned by the captured Account.

use reqwest::Method;
use scoplen_api::{
    organization::OrganizationListQuery,
    team::{
        TEAM_RECEIPT_LIFETIME_SECONDS, TeamAcceptanceReceipt, TeamDissolutionReceipt,
        TeamDissolveRequest, TeamInvitationAcceptRequest, TeamInvitationCreateRequest,
        TeamInvitationLink, TeamInvitationPage, TeamInvitationResource, TeamInvitationStatus,
        TeamMemberPage, TeamMemberResource, TeamMemberStatus, TeamMemberUpdateRequest, TeamRole,
    },
};
use scoplen_crypto::TeamInvitationPassword;
use serde::Deserialize;

use super::*;
use crate::store::teams::TeamOperationRecord;

/// The three receipt-backed operations retain independent original requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum TeamOperationKind {
    /// An administrator's named invitation.
    Invitation,
    /// The designated Account's explicit acceptance.
    Acceptance,
    /// An Owner's confirmed team dissolution.
    Dissolution,
}

impl TeamOperationKind {
    const fn value(self) -> i64 {
        match self {
            Self::Invitation => 0,
            Self::Acceptance => 1,
            Self::Dissolution => 2,
        }
    }
}

/// Safe retained status; original passwords, verifiers and request bytes stay in Rust.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamOperationView {
    /// Original public operation key, not authority to perform it.
    pub operation_id: String,
    /// Original operation class.
    pub kind: TeamOperationKind,
    /// Captured team identity.
    pub organization_id: String,
    /// Captured invitation, absent for dissolution.
    pub invitation_id: Option<String>,
    /// Named recipient for an issuing operation.
    pub recipient_username: Option<String>,
    /// Issued roles, for display only.
    pub roles: Vec<String>,
    /// Local outcome and permitted recovery action.
    pub phase: TeamCreationPhase,
    /// Original deadline as decimal milliseconds.
    pub retry_until: Option<String>,
    /// Public link only; never contains its separate password.
    pub link: Option<String>,
}

/// Authorized invitation metadata, with no password or verifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamInvitationView {
    /// Invitation identity.
    pub id: String,
    /// Captured exact precondition.
    pub etag: String,
    /// Owning team.
    pub organization_id: String,
    /// Current name authorized by the preview.
    pub organization_name: String,
    /// Fixed recipient username.
    pub recipient_username: String,
    /// Intended built-in roles, without frontend authority.
    pub roles: Vec<String>,
    /// Current server invitation state.
    pub status: String,
    /// Fixed UTC expiry.
    pub expires_at: String,
}

/// One explicitly requested invitation page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamInvitationPageView {
    /// Current authorized invitations.
    pub items: Vec<TeamInvitationView>,
    /// Ascending continuation, fetched only on request.
    pub next_cursor: Option<String>,
}

/// Current authorized member metadata; no Personal data or Device information.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamMemberView {
    /// Membership identity, distinct from Account identity.
    pub id: String,
    /// Exact captured strong precondition.
    pub etag: String,
    /// Owning team.
    pub organization_id: String,
    /// Canonical current username.
    pub username: String,
    /// Complete current role set.
    pub roles: Vec<String>,
    /// Current active, suspended or removed state.
    pub status: String,
    /// Display distinction based on the captured Account.
    pub is_self: bool,
}

/// One explicitly requested member page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamMemberPageView {
    /// Current authorized members.
    pub items: Vec<TeamMemberView>,
    /// Ascending continuation, fetched only on request.
    pub next_cursor: Option<String>,
}

impl PersonalServer {
    /// Read all locally retained operations without contacting a server.
    pub fn pending_team_operations(
        &self,
        store: &Store,
    ) -> Result<Vec<TeamOperationView>, TeamError> {
        if store.personal_record().map_err(storage)?.is_none() {
            return Ok(Vec::new());
        }
        let identity = record(store)?;
        let mut operations = Vec::new();
        for kind in [
            TeamOperationKind::Invitation,
            TeamOperationKind::Acceptance,
            TeamOperationKind::Dissolution,
        ] {
            if let Some(pending) = store.team_operation(&identity, kind.value()).map_err(storage)? {
                operations.push(operation_view(&identity, &pending, now_ms()?, kind)?);
            }
        }
        Ok(operations)
    }

    /// Generate and durably protect the original password and canonical creation before dispatch.
    pub fn prepare_team_invitation(
        &self,
        store: &Store,
        organization_id: &str,
        recipient_username: String,
        roles: Vec<String>,
    ) -> Result<TeamOperationView, TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let identity = record(store)?;
        let organization_id = parse_id(organization_id)?;
        let invitation_id =
            scoplen_model::new_uuid_v7().map_err(|_| PersonalServerError::Identity)?;
        let password = TeamInvitationPassword::generate().map_err(invalid)?;
        let request = TeamInvitationCreateRequest {
            invitation_id,
            recipient_username,
            roles: requested_roles(roles)?,
            password_verifier: password
                .verifier(&identity.origin, &organization_id, &invitation_id)
                .map_err(invalid)?,
        };
        let payload = request.to_json().map_err(|_| TeamFailure::InvalidInvitation)?;
        prepare(
            store,
            &identity,
            TeamOperationKind::Invitation,
            organization_id,
            Some(invitation_id),
            payload,
            Some(SecretVec::new(password.as_bytes().to_vec())),
            None,
        )
    }

    /// Preview only the designated Account's invitation at its exact canonical origin.
    pub async fn preview_team_invitation(
        &self,
        store: Arc<Store>,
        link: &str,
    ) -> Result<TeamInvitationView, TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let identity = record(&store)?;
        let link = bound_link(&identity, link)?;
        let session = self.team_session(&store, DeviceAccessOperation::TeamInvitationRead).await?;
        Ok(invitation_view(self.invitation_preview(&store, &session, &link).await?))
    }

    /// Recheck the reviewed preview, then retain the original acceptance before sending it.
    pub async fn prepare_team_acceptance(
        &self,
        store: Arc<Store>,
        link: &str,
        preview_etag: &str,
        password: SecretVec,
    ) -> Result<TeamOperationView, TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let identity = record(&store)?;
        let link = bound_link(&identity, link)?;
        parse_organization_if_match(Some(preview_etag))
            .map_err(|_| TeamFailure::InvalidInvitation)?;
        let password = TeamInvitationPassword::parse(password.as_bytes())
            .map_err(|_| TeamFailure::InvalidInvitation)?;
        let session = self.team_session(&store, DeviceAccessOperation::TeamInvitationRead).await?;
        let preview = self.invitation_preview(&store, &session, &link).await?;
        if preview.etag != preview_etag {
            return Err(TeamFailure::MembershipConflict.into());
        }
        if preview.status != TeamInvitationStatus::Pending {
            return Err(TeamFailure::InvitationDenied.into());
        }
        let payload = TeamInvitationAcceptRequest { password }.to_json().map_err(invalid)?;
        prepare(
            &store,
            &session.identity,
            TeamOperationKind::Acceptance,
            link.organization_id,
            Some(link.invitation_id),
            payload,
            None,
            None,
        )
    }

    /// Preserve the Owner's original Organization validator and explicit dissolution body.
    pub fn prepare_team_dissolution(
        &self,
        store: &Store,
        organization_id: &str,
        etag: &str,
    ) -> Result<TeamOperationView, TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let identity = record(store)?;
        let organization_id = parse_id(organization_id)?;
        parse_organization_if_match(Some(etag)).map_err(invalid)?;
        let payload =
            SecretVec::new(TeamDissolveRequest { organization_id }.to_json().map_err(invalid)?);
        prepare(
            store,
            &identity,
            TeamOperationKind::Dissolution,
            organization_id,
            None,
            payload,
            None,
            Some(etag.to_owned()),
        )
    }

    /// Explicitly send or retry exactly the protected original request, with fresh authentication and proof.
    pub async fn submit_team_operation(
        &self,
        store: Arc<Store>,
        kind: TeamOperationKind,
        operation_id: &str,
    ) -> Result<TeamOperationView, TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let identity = record(&store)?;
        let pending = load_operation(&store, &identity, kind, operation_id)?;
        let current = operation_view(&identity, &pending, now_ms()?, kind)?;
        match current.phase {
            TeamCreationPhase::Confirmed => return Ok(current),
            TeamCreationPhase::Expired => return Err(TeamFailure::OperationExpired.into()),
            _ => {}
        }
        let operation = match kind {
            TeamOperationKind::Invitation => DeviceAccessOperation::TeamInvitationCreate,
            TeamOperationKind::Acceptance => DeviceAccessOperation::TeamInvitationAccept,
            TeamOperationKind::Dissolution => DeviceAccessOperation::TeamDissolve,
        };
        let session = self.team_session(&store, operation).await?;
        let path = operation_path(&pending, kind)?;
        let proof = session.proof("POST", &path)?;
        if !store
            .dispatch_team_operation(&session.identity, &pending, &session.access, now_ms()?)
            .map_err(storage)?
        {
            return Err(PersonalServerError::Busy.into());
        }
        let sent = load_operation(&store, &session.identity, kind, operation_id)?;
        let response = self
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .team_exchange(
                &session.identity.origin,
                &path,
                Method::POST,
                Some(sent.payload.as_bytes()),
                session.token()?,
                &proof,
                Some(sent.operation_id),
                sent.etag.as_deref(),
                MAX_ORGANIZATION_RESOURCE_BYTES,
            )
            .await;
        if kind != TeamOperationKind::Invitation {
            store
                .invalidate_team_assets(&session.identity, pending.organization_id, None)
                .map_err(storage)?;
        }
        let response = match response {
            Ok(response) => response,
            Err(PersonalServerError::ConnectionBeforeRequest) if pending.phase == 0 => {
                if !store
                    .finish_team_operation(
                        &session.identity,
                        &sent,
                        &session.access,
                        None,
                        now_ms()?,
                    )
                    .map_err(storage)?
                {
                    return Err(PersonalServerError::Storage.into());
                }
                return Err(PersonalServerError::ConnectionBeforeRequest.into());
            }
            Err(_) => return Err(TeamFailure::OutcomeUnknown.into()),
        };
        session.current(&store)?;
        if response.status == if kind == TeamOperationKind::Invitation { 201 } else { 200 } {
            let canonical = confirmation(&session.identity, &sent, kind, &response)?;
            if !store
                .finish_team_operation(
                    &session.identity,
                    &sent,
                    &session.access,
                    Some(&canonical),
                    now_ms()?,
                )
                .map_err(storage)?
            {
                return Err(PersonalServerError::Storage.into());
            }
            let confirmed = load_operation(&store, &session.identity, kind, operation_id)?;
            return operation_view(&session.identity, &confirmed, now_ms()?, kind);
        }
        let problem = problem(&response)?;
        let error = classify_membership_problem(&problem)?;
        // A later denial cannot settle a prior missing response or authorize a new key.
        if pending.phase == 0
            && !problem.changed
            && problem.code.as_str() != "organization.conflict"
            && !store
                .finish_team_operation(&session.identity, &sent, &session.access, None, now_ms()?)
                .map_err(storage)?
        {
            return Err(PersonalServerError::Storage.into());
        }
        if problem.status == 401 {
            store
                .invalidate_personal_session(&session.identity, &session.access)
                .map_err(storage)?;
        }
        Err(error)
    }

    /// Clear confirmed/prepared state, or explicitly archive expired uncertainty after review.
    pub fn discard_team_operation(
        &self,
        store: &Store,
        kind: TeamOperationKind,
        operation_id: &str,
    ) -> Result<(), TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let identity = record(store)?;
        let pending = load_operation(store, &identity, kind, operation_id)?;
        if operation_view(&identity, &pending, now_ms()?, kind)?.phase == TeamCreationPhase::Unknown
        {
            return Err(TeamFailure::OutcomeUnknown.into());
        }
        if !store.discard_team_operation(&identity, &pending, now_ms()?).map_err(storage)? {
            return Err(PersonalServerError::Busy.into());
        }
        Ok(())
    }

    /// Access the separate password only for an explicit invitation reveal or native copy.
    pub fn team_invitation_password(
        &self,
        store: &Store,
        operation_id: &str,
    ) -> Result<SecretVec, TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let identity = record(store)?;
        let pending =
            load_operation(store, &identity, TeamOperationKind::Invitation, operation_id)?;
        if operation_view(&identity, &pending, now_ms()?, TeamOperationKind::Invitation)?.phase
            != TeamCreationPhase::Confirmed
        {
            return Err(TeamFailure::OperationMismatch.into());
        }
        pending.password.ok_or_else(|| TeamFailure::OperationMissing.into())
    }

    /// Read only a confirmed issuing operation's public locator for explicit native copy.
    pub fn team_invitation_link(
        &self,
        store: &Store,
        operation_id: &str,
    ) -> Result<String, TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let identity = record(store)?;
        let pending =
            load_operation(store, &identity, TeamOperationKind::Invitation, operation_id)?;
        let view = operation_view(&identity, &pending, now_ms()?, TeamOperationKind::Invitation)?;
        if view.phase != TeamCreationPhase::Confirmed {
            return Err(TeamFailure::OperationMismatch.into());
        }
        view.link.ok_or_else(|| TeamFailure::OperationMismatch.into())
    }

    /// Fetch one bounded current invitation page, preserving the captured continuation.
    pub async fn team_invitations(
        &self,
        store: Arc<Store>,
        organization_id: &str,
        cursor: Option<&str>,
    ) -> Result<TeamInvitationPageView, TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let organization = parse_id(organization_id)?;
        let (query, path, proof_path) = directory_path(organization, "invitations", cursor)?;
        let session = self.team_session(&store, DeviceAccessOperation::TeamInvitationList).await?;
        let response = self
            .team_read(&store, &session, &path, &proof_path, MAX_ORGANIZATION_PAGE_BYTES)
            .await?;
        let page = TeamInvitationPage::from_http_json(
            response.body.as_bytes(),
            response.cache_control.as_deref(),
            response.pragma.as_deref(),
        )
        .map_err(invalid)?;
        page.validate_for_organization(organization, query).map_err(invalid)?;
        Ok(TeamInvitationPageView {
            items: page.items.into_iter().map(invitation_view).collect(),
            next_cursor: page.next_cursor.map(|id| id.to_string()),
        })
    }

    /// Fetch one bounded current member page; roles in the DTO never authorize mutations.
    pub async fn team_members(
        &self,
        store: Arc<Store>,
        organization_id: &str,
        cursor: Option<&str>,
    ) -> Result<TeamMemberPageView, TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let organization = parse_id(organization_id)?;
        let (query, path, proof_path) = directory_path(organization, "members", cursor)?;
        let session = self.team_session(&store, DeviceAccessOperation::TeamMemberList).await?;
        let response = self
            .team_read(&store, &session, &path, &proof_path, MAX_ORGANIZATION_PAGE_BYTES)
            .await?;
        let page = TeamMemberPage::from_http_json(
            response.body.as_bytes(),
            response.cache_control.as_deref(),
            response.pragma.as_deref(),
        )
        .map_err(invalid)?;
        page.validate_for_organization(organization, query).map_err(invalid)?;
        Ok(TeamMemberPageView {
            items: page
                .items
                .into_iter()
                .map(|item| member_view(item, session.identity.account_id))
                .collect(),
            next_cursor: page.next_cursor.map(|id| id.to_string()),
        })
    }

    /// Revoke only the explicitly reviewed invitation and original validator.
    pub async fn revoke_team_invitation(
        &self,
        store: Arc<Store>,
        organization_id: &str,
        invitation_id: &str,
        etag: &str,
    ) -> Result<(), TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let path = format!(
            "/api/v1/orgs/{}/invitations/{}",
            parse_id(organization_id)?,
            parse_id(invitation_id)?
        );
        let session =
            self.team_session(&store, DeviceAccessOperation::TeamInvitationRevoke).await?;
        self.team_mutation(&store, &session, &path, Method::DELETE, None, etag, 204).await?;
        Ok(())
    }

    /// Apply one complete reviewed role/status edit without refreshing its precondition.
    pub async fn update_team_member(
        &self,
        store: Arc<Store>,
        organization_id: &str,
        membership_id: &str,
        etag: &str,
        roles: Vec<String>,
        status: &str,
    ) -> Result<TeamMemberView, TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let organization = parse_id(organization_id)?;
        let membership = parse_id(membership_id)?;
        let request = TeamMemberUpdateRequest {
            roles: requested_roles(roles)?,
            status: TeamMemberStatus::parse(status).map_err(|_| TeamFailure::InvalidInvitation)?,
        };
        let body = request.to_json().map_err(|_| TeamFailure::InvalidInvitation)?;
        let path = format!("/api/v1/orgs/{organization}/members/{membership}");
        let session = self.team_session(&store, DeviceAccessOperation::TeamMemberUpdate).await?;
        let response = self
            .team_mutation(&store, &session, &path, Method::PATCH, Some(&body), etag, 200)
            .await;
        store.invalidate_team_assets(&session.identity, organization, None).map_err(storage)?;
        let response = response?;
        let item = TeamMemberResource::from_http_json(
            response.body.as_bytes(),
            response.etag.as_deref(),
            response.cache_control.as_deref(),
            response.pragma.as_deref(),
        )
        .map_err(|_| TeamFailure::MembershipUnknown)?;
        item.validate_for_organization(organization).map_err(|_| TeamFailure::MembershipUnknown)?;
        let mut roles = request.roles;
        roles.sort_unstable();
        if item.id != membership || item.roles != roles || item.status != request.status {
            return Err(TeamFailure::MembershipUnknown.into());
        }
        Ok(member_view(item, session.identity.account_id))
    }

    /// Remove a reviewed member, or leave using the caller's exact Organization projection.
    pub async fn remove_team_member(
        &self,
        store: Arc<Store>,
        organization_id: &str,
        membership_id: &str,
        etag: &str,
    ) -> Result<(), TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let organization = parse_id(organization_id)?;
        let path = format!("/api/v1/orgs/{organization}/members/{}", parse_id(membership_id)?);
        let session = self.team_session(&store, DeviceAccessOperation::TeamMemberRemove).await?;
        let result =
            self.team_mutation(&store, &session, &path, Method::DELETE, None, etag, 204).await;
        store.invalidate_team_assets(&session.identity, organization, None).map_err(storage)?;
        result?;
        Ok(())
    }

    async fn invitation_preview(
        &self,
        store: &Store,
        session: &TeamSession,
        link: &TeamInvitationLink,
    ) -> Result<TeamInvitationResource, TeamError> {
        let path =
            format!("/api/v1/orgs/{}/invitations/{}", link.organization_id, link.invitation_id);
        let response =
            self.team_read(store, session, &path, &path, MAX_ORGANIZATION_RESOURCE_BYTES).await?;
        let resource = invitation_resource(&response)?;
        resource
            .validate_for_recipient(
                session.identity.account_id,
                link.organization_id,
                link.invitation_id,
            )
            .map_err(invalid)?;
        Ok(resource)
    }

    async fn team_read(
        &self,
        store: &Store,
        session: &TeamSession,
        path: &str,
        proof_path: &str,
        limit: usize,
    ) -> Result<Response, TeamError> {
        let proof = session.proof("GET", proof_path)?;
        let response = self
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .team_get(&session.identity.origin, path, session.token()?, &proof, limit)
            .await?;
        session.current(store)?;
        if response.status != 200 {
            return Err(membership_error(store, session, &response)?);
        }
        Ok(response)
    }

    #[allow(clippy::too_many_arguments)]
    async fn team_mutation(
        &self,
        store: &Store,
        session: &TeamSession,
        path: &str,
        method: Method,
        body: Option<&[u8]>,
        etag: &str,
        success: u16,
    ) -> Result<Response, TeamError> {
        parse_organization_if_match(Some(etag)).map_err(invalid)?;
        let proof = session.proof(method.as_str(), path)?;
        let response = self
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .team_exchange(
                &session.identity.origin,
                path,
                method,
                body,
                session.token()?,
                &proof,
                None,
                Some(etag),
                MAX_ORGANIZATION_RESOURCE_BYTES,
            )
            .await;
        let response = match response {
            Ok(response) => response,
            Err(PersonalServerError::ConnectionBeforeRequest) => {
                return Err(PersonalServerError::ConnectionBeforeRequest.into());
            }
            Err(_) => return Err(TeamFailure::MembershipUnknown.into()),
        };
        session.current(store).map_err(|_| TeamFailure::MembershipUnknown)?;
        if response.status == success {
            return Ok(response);
        }
        Err(membership_error(store, session, &response)
            .map_err(|_| TeamFailure::MembershipUnknown)?)
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare(
    store: &Store,
    identity: &PersonalRecord,
    kind: TeamOperationKind,
    organization_id: Uuid,
    invitation_id: Option<Uuid>,
    payload: SecretVec,
    password: Option<SecretVec>,
    etag: Option<String>,
) -> Result<TeamOperationView, TeamError> {
    let pending = TeamOperationRecord {
        kind: kind.value(),
        operation_id: scoplen_model::new_uuid_v7().map_err(|_| PersonalServerError::Identity)?,
        organization_id,
        invitation_id,
        payload,
        password,
        etag,
        phase: 0,
        first_attempt_ms: None,
        response: None,
    };
    let view = operation_view(identity, &pending, now_ms()?, kind)?;
    if !store.prepare_team_operation(identity, &pending).map_err(storage)? {
        return Err(TeamFailure::MembershipPending.into());
    }
    Ok(view)
}

fn load_operation(
    store: &Store,
    identity: &PersonalRecord,
    kind: TeamOperationKind,
    operation_id: &str,
) -> Result<TeamOperationRecord, TeamError> {
    let operation = parse_id(operation_id)?;
    let pending = store
        .team_operation(identity, kind.value())
        .map_err(storage)?
        .ok_or(TeamFailure::OperationMissing)?;
    if pending.operation_id != operation {
        return Err(TeamFailure::OperationMismatch.into());
    }
    operation_view(identity, &pending, now_ms()?, kind)?;
    Ok(pending)
}

fn operation_view(
    identity: &PersonalRecord,
    pending: &TeamOperationRecord,
    time: u64,
    kind: TeamOperationKind,
) -> Result<TeamOperationView, TeamError> {
    validate_uuid_v7(pending.operation_id).map_err(invalid)?;
    validate_uuid_v7(pending.organization_id).map_err(invalid)?;
    if pending.kind != kind.value() {
        return Err(TeamFailure::OperationMismatch.into());
    }
    let mut recipient_username = None;
    let mut roles = Vec::new();
    let link = match kind {
        TeamOperationKind::Invitation => {
            let request = TeamInvitationCreateRequest::from_json(pending.payload.as_bytes())
                .map_err(invalid)?;
            let password = TeamInvitationPassword::parse(
                pending.password.as_ref().ok_or(TeamFailure::InvalidTeamResponse)?.as_bytes(),
            )
            .map_err(invalid)?;
            if Some(request.invitation_id) != pending.invitation_id
                || pending.etag.is_some()
                || password
                    .verifier(&identity.origin, &pending.organization_id, &request.invitation_id)
                    .map_err(invalid)?
                    != request.password_verifier
            {
                return Err(TeamFailure::InvalidTeamResponse.into());
            }
            recipient_username = Some(request.recipient_username);
            roles = request.roles.iter().map(|role| role.as_str().to_owned()).collect();
            Some(
                TeamInvitationLink {
                    origin: identity.origin.clone(),
                    organization_id: pending.organization_id,
                    invitation_id: request.invitation_id,
                }
                .to_url()
                .map_err(invalid)?,
            )
        }
        TeamOperationKind::Acceptance => {
            TeamInvitationAcceptRequest::from_json(pending.payload.as_bytes()).map_err(invalid)?;
            let invitation = pending.invitation_id.ok_or(TeamFailure::InvalidTeamResponse)?;
            validate_uuid_v7(invitation).map_err(invalid)?;
            if pending.password.is_some() || pending.etag.is_some() {
                return Err(TeamFailure::InvalidTeamResponse.into());
            }
            Some(
                TeamInvitationLink {
                    origin: identity.origin.clone(),
                    organization_id: pending.organization_id,
                    invitation_id: invitation,
                }
                .to_url()
                .map_err(invalid)?,
            )
        }
        TeamOperationKind::Dissolution => {
            TeamDissolveRequest::from_json(pending.payload.as_bytes())
                .and_then(|request| request.validate_for_organization(pending.organization_id))
                .map_err(invalid)?;
            parse_organization_if_match(pending.etag.as_deref()).map_err(invalid)?;
            if pending.invitation_id.is_some() || pending.password.is_some() {
                return Err(TeamFailure::InvalidTeamResponse.into());
            }
            None
        }
    };
    if let Some(response) = &pending.response {
        validate_confirmation(identity, pending, kind, response.as_bytes())?;
    }
    let deadline = pending
        .first_attempt_ms
        .map(|value| value.saturating_add(TEAM_RECEIPT_LIFETIME_SECONDS * 1000));
    let phase = match (pending.phase, pending.response.is_some()) {
        (2, true) => TeamCreationPhase::Confirmed,
        (0 | 1, false) if deadline.is_some_and(|deadline| time >= deadline) => {
            TeamCreationPhase::Expired
        }
        (0, false) => TeamCreationPhase::Prepared,
        (1, false) => TeamCreationPhase::Unknown,
        _ => return Err(TeamFailure::InvalidTeamResponse.into()),
    };
    Ok(TeamOperationView {
        operation_id: pending.operation_id.to_string(),
        kind,
        organization_id: pending.organization_id.to_string(),
        invitation_id: pending.invitation_id.map(|id| id.to_string()),
        recipient_username,
        roles,
        phase,
        retry_until: deadline.map(|value| value.to_string()),
        link,
    })
}

fn confirmation(
    identity: &PersonalRecord,
    pending: &TeamOperationRecord,
    kind: TeamOperationKind,
    response: &Response,
) -> Result<Vec<u8>, TeamError> {
    if kind == TeamOperationKind::Invitation {
        invitation_resource(response)?;
    }
    validate_confirmation(identity, pending, kind, response.body.as_bytes())
}

fn validate_confirmation(
    identity: &PersonalRecord,
    pending: &TeamOperationRecord,
    kind: TeamOperationKind,
    body: &[u8],
) -> Result<Vec<u8>, TeamError> {
    match kind {
        TeamOperationKind::Invitation => {
            let resource = TeamInvitationResource::from_json(body).map_err(invalid)?;
            let request = TeamInvitationCreateRequest::from_json(pending.payload.as_bytes())
                .map_err(invalid)?;
            let mut roles = request.roles;
            roles.sort_unstable();
            if Some(resource.id) != pending.invitation_id
                || resource.organization_id != pending.organization_id
                || resource.issuer_account_id != identity.account_id
                || resource.recipient_username != request.recipient_username
                || resource.roles != roles
            {
                return Err(TeamFailure::InvalidTeamResponse.into());
            }
            resource.to_json().map_err(invalid)
        }
        TeamOperationKind::Acceptance => {
            let receipt = TeamAcceptanceReceipt::from_json(body).map_err(invalid)?;
            receipt
                .validate_for_request(
                    identity.account_id,
                    pending.organization_id,
                    pending.invitation_id.ok_or(TeamFailure::InvalidTeamResponse)?,
                )
                .map_err(invalid)?;
            receipt.to_json().map_err(invalid)
        }
        TeamOperationKind::Dissolution => {
            let receipt = TeamDissolutionReceipt::from_json(body).map_err(invalid)?;
            receipt.validate_for_organization(pending.organization_id).map_err(invalid)?;
            receipt.to_json().map_err(invalid)
        }
    }
}

fn operation_path(
    pending: &TeamOperationRecord,
    kind: TeamOperationKind,
) -> Result<String, TeamError> {
    let base = format!("/api/v1/orgs/{}", pending.organization_id);
    Ok(match kind {
        TeamOperationKind::Invitation => format!("{base}/invitations"),
        TeamOperationKind::Acceptance => format!(
            "{base}/invitations/{}/accept",
            pending.invitation_id.ok_or(TeamFailure::InvalidTeamResponse)?
        ),
        TeamOperationKind::Dissolution => format!("{base}/dissolve"),
    })
}

fn bound_link(identity: &PersonalRecord, input: &str) -> Result<TeamInvitationLink, TeamError> {
    let link = TeamInvitationLink::parse(input).map_err(|_| TeamFailure::InvalidInvitation)?;
    if link.origin != identity.origin {
        return Err(TeamFailure::InvitationOriginMismatch.into());
    }
    Ok(link)
}

fn requested_roles(input: Vec<String>) -> Result<Vec<TeamRole>, TeamError> {
    input
        .iter()
        .map(|role| TeamRole::parse(role).map_err(|_| TeamFailure::InvalidInvitation.into()))
        .collect()
}

fn directory_path(
    organization: Uuid,
    directory: &str,
    cursor: Option<&str>,
) -> Result<(OrganizationListQuery, String, String), TeamError> {
    let query =
        OrganizationListQuery { cursor: cursor.map(parse_id).transpose()?, ..Default::default() };
    query.validate().map_err(invalid)?;
    let proof_path = format!("/api/v1/orgs/{organization}/{directory}");
    let mut path = format!("{proof_path}?limit={}", query.limit);
    if let Some(cursor) = query.cursor {
        path.push_str(&format!("&cursor={cursor}"));
    }
    Ok((query, path, proof_path))
}

fn invitation_resource(response: &Response) -> Result<TeamInvitationResource, TeamError> {
    TeamInvitationResource::from_http_json(
        response.body.as_bytes(),
        response.etag.as_deref(),
        response.cache_control.as_deref(),
        response.pragma.as_deref(),
    )
    .map_err(invalid)
}

fn invitation_view(item: TeamInvitationResource) -> TeamInvitationView {
    TeamInvitationView {
        id: item.id.to_string(),
        etag: item.etag,
        organization_id: item.organization_id.to_string(),
        organization_name: item.organization_name,
        recipient_username: item.recipient_username,
        roles: item.roles.iter().map(|role| role.as_str().to_owned()).collect(),
        status: match item.status {
            TeamInvitationStatus::Pending => "pending",
            TeamInvitationStatus::Accepted => "accepted",
            TeamInvitationStatus::Revoked => "revoked",
            TeamInvitationStatus::Expired => "expired",
            TeamInvitationStatus::Locked => "locked",
        }
        .into(),
        expires_at: item.expires_at,
    }
}

fn member_view(item: TeamMemberResource, account: Uuid) -> TeamMemberView {
    TeamMemberView {
        id: item.id.to_string(),
        etag: item.etag,
        organization_id: item.organization_id.to_string(),
        username: item.username,
        roles: item.roles.iter().map(|role| role.as_str().to_owned()).collect(),
        status: match item.status {
            TeamMemberStatus::Active => "active",
            TeamMemberStatus::Suspended => "suspended",
            TeamMemberStatus::Removed => "removed",
        }
        .into(),
        is_self: item.account_id == account,
    }
}

fn membership_error(
    store: &Store,
    session: &TeamSession,
    response: &Response,
) -> Result<TeamError, TeamError> {
    let problem = problem(response)?;
    let error = classify_membership_problem(&problem)?;
    if problem.status == 401 {
        store.invalidate_personal_session(&session.identity, &session.access).map_err(storage)?;
    }
    Ok(error)
}

fn classify_membership_problem(problem: &ProblemDetails) -> Result<TeamError, TeamError> {
    Ok(match (problem.status, problem.code.as_str(), problem.changed, problem.retryable) {
        (401, "auth.authentication_required", false, false) => {
            PersonalServerError::AuthenticationRequired.into()
        }
        (403, "policy.denied", false, false) => PersonalServerError::PermissionDenied.into(),
        (404, "organization.not_found", false, false) => TeamFailure::TeamNotFound.into(),
        (409, "organization.invitation_denied", false, false) => {
            TeamFailure::InvitationDenied.into()
        }
        (409, "organization.conflict", false, false) => TeamFailure::Conflict.into(),
        (412, "organization.precondition_failed", false, false)
        | (428, "organization.precondition_required", false, false) => {
            TeamFailure::MembershipConflict.into()
        }
        (503, "organization.commit_outcome_unknown", true, _) => {
            TeamFailure::MembershipUnknown.into()
        }
        (503, "organization.storage_unavailable", false, true) => {
            TeamFailure::ServiceUnavailable.into()
        }
        (429, _, false, true) => TeamFailure::ServiceUnavailable.into(),
        _ => return Err(TeamFailure::InvalidTeamResponse.into()),
    })
}
