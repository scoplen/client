// SPDX-License-Identifier: Apache-2.0
//! Current Organization Host Grant administration.
//!
//! Grants are server-readable authorization records. The client only exposes
//! the current authorized projection and sends an explicitly reviewed ETag for
//! withdrawal; it never treats a retained Grant as Personal data or authority.

use reqwest::Method;
use scoplen_api::{
    grant::{GrantPage, MAX_GRANT_BYTES, MAX_GRANT_PAGE_BYTES, format_grant_timestamp},
    organization::{OrganizationListQuery, parse_organization_if_match},
};
use serde::Serialize;
use specta::Type;
use std::sync::Arc;

use super::{
    DeviceAccessOperation, PersonalServer, PersonalServerError, TeamError, TeamFailure,
    authoring::authoring_problem, now_ms, parse_id, storage,
};
use crate::store::Store;

/// Whether the current whole-second Grant interval has started or ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum TeamGrantStatus {
    /// The Grant starts in the future.
    Future,
    /// The Grant currently contributes connection authority.
    Active,
    /// The Grant is retained for history but no longer contributes authority.
    Expired,
}

/// One current Grant projection. Membership and Host ids remain opaque typed
/// references; resolving their names is a separate authorized read.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamGrantView {
    /// The authenticated deployment origin.
    pub origin: String,
    /// The Account that loaded this projection.
    pub account_id: String,
    /// The owning Organization.
    pub organization_id: String,
    /// Immutable Grant id.
    pub id: String,
    /// Strong ETag captured for an explicit withdrawal.
    pub etag: String,
    /// Current Membership reference.
    pub membership_id: String,
    /// Current Host reference.
    pub host_id: String,
    /// Exact SSH username authorized by the Grant.
    pub remote_user: String,
    /// Inclusive whole-second UTC start.
    pub valid_from: String,
    /// Exclusive whole-second UTC end, or None for an explicit nonexpiring Grant.
    pub valid_until: Option<String>,
    /// Derived display state at the time the page was decoded.
    pub status: TeamGrantStatus,
}

/// One bounded current Grant page, including expired but unwithdrawn rows.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamGrantPageView {
    /// The authenticated deployment origin.
    pub origin: String,
    /// The Account that loaded this projection.
    pub account_id: String,
    /// The owning Organization.
    pub organization_id: String,
    /// Current page items in server UUID order.
    pub items: Vec<TeamGrantView>,
    /// Opaque next UUIDv7 continuation, when present.
    pub next_cursor: Option<String>,
}

impl PersonalServer {
    /// Fetch one current authorized Grant page. No frontend filtering or
    /// cached synchronized view is used as an authorization source.
    pub async fn team_grants_page(
        &self,
        store: Arc<Store>,
        organization_id: &str,
        cursor: Option<&str>,
    ) -> Result<TeamGrantPageView, TeamError> {
        let organization = parse_id(organization_id)?;
        let query = OrganizationListQuery {
            cursor: cursor.map(parse_id).transpose()?,
            ..Default::default()
        };
        query.validate().map_err(|_| TeamFailure::InvalidTeamResponse)?;
        let base = format!("/api/v1/orgs/{organization}/grants");
        let mut path = format!("{base}?limit={}", query.limit);
        if let Some(cursor) = query.cursor {
            path.push_str(&format!("&cursor={cursor}"));
        }
        let session =
            self.team_session(&store, DeviceAccessOperation::OrganizationGrantList).await?;
        let proof = session.proof("GET", &base)?;
        let response = self
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .team_get(
                &session.identity.origin,
                &path,
                session.token()?,
                &proof,
                MAX_GRANT_PAGE_BYTES,
            )
            .await?;
        session.current(&store)?;
        require_grant_success(&store, &session, &response, 200)?;
        let page = GrantPage::from_http_json(
            response.body.as_bytes(),
            response.cache_control.as_deref(),
            response.pragma.as_deref(),
        )
        .map_err(|_| TeamFailure::InvalidTeamResponse)?;
        page.validate_for_query(query).map_err(|_| TeamFailure::InvalidTeamResponse)?;
        let current = now_ms()? / 1_000;
        let items = page
            .items
            .into_iter()
            .map(|resource| grant_view(&session.identity, organization, resource, current))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TeamGrantPageView {
            origin: session.identity.origin,
            account_id: session.identity.account_id.to_string(),
            organization_id: organization.to_string(),
            items,
            next_cursor: page.next_cursor.map(|id| id.to_string()),
        })
    }

    /// Withdraw only the Grant whose strong ETag the user has reviewed.
    pub async fn withdraw_team_grant(
        &self,
        store: Arc<Store>,
        organization_id: &str,
        grant_id: &str,
        etag: &str,
    ) -> Result<(), TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        parse_organization_if_match(Some(etag)).map_err(|_| TeamFailure::AuthoringConflict)?;
        let organization = parse_id(organization_id)?;
        let grant = parse_id(grant_id)?;
        let session =
            self.team_session(&store, DeviceAccessOperation::OrganizationGrantDelete).await?;
        let path = format!("/api/v1/orgs/{organization}/grants/{grant}");
        let proof = session.proof(Method::DELETE.as_str(), &path)?;
        let result = self
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .team_exchange(
                &session.identity.origin,
                &path,
                Method::DELETE,
                None,
                session.token()?,
                &proof,
                None,
                Some(etag),
                MAX_GRANT_BYTES,
            )
            .await;
        store.invalidate_team_assets(&session.identity, organization, None).map_err(storage)?;
        let response = match result {
            Ok(response) => response,
            Err(PersonalServerError::ConnectionBeforeRequest) => {
                return Err(PersonalServerError::ConnectionBeforeRequest.into());
            }
            Err(_) => return Err(TeamFailure::AuthoringUnknown.into()),
        };
        session.current(&store).map_err(|_| TeamFailure::AuthoringUnknown)?;
        require_grant_success(&store, &session, &response, 204)
    }
}

fn grant_view(
    identity: &crate::store::personal::PersonalRecord,
    organization: uuid::Uuid,
    resource: scoplen_api::grant::GrantResource,
    current: u64,
) -> Result<TeamGrantView, TeamError> {
    let fields = resource.fields;
    let status = if fields.valid_from > current {
        TeamGrantStatus::Future
    } else if fields.valid_until.is_some_and(|until| current >= until) {
        TeamGrantStatus::Expired
    } else {
        TeamGrantStatus::Active
    };
    Ok(TeamGrantView {
        origin: identity.origin.clone(),
        account_id: identity.account_id.to_string(),
        organization_id: organization.to_string(),
        id: resource.id.to_string(),
        etag: resource.etag,
        membership_id: fields.membership.to_string(),
        host_id: fields.host.to_string(),
        remote_user: fields.remote_user,
        valid_from: format_grant_timestamp(fields.valid_from)
            .map_err(|_| TeamFailure::InvalidTeamResponse)?,
        valid_until: fields
            .valid_until
            .map(format_grant_timestamp)
            .transpose()
            .map_err(|_| TeamFailure::InvalidTeamResponse)?,
        status,
    })
}

fn require_grant_success(
    store: &Store,
    session: &super::TeamSession,
    response: &super::Response,
    expected: u16,
) -> Result<(), TeamError> {
    if response.status == expected {
        return Ok(());
    }
    let problem = super::problem(response)?;
    let error = authoring_problem(&problem)?;
    if problem.status == 401 {
        store.invalidate_personal_session(&session.identity, &session.access).map_err(storage)?;
    }
    Err(error)
}
