// SPDX-License-Identifier: Apache-2.0
//! Display-only access-request projections and explicit local intents.

use std::fmt;

use serde::{Deserialize, Serialize};
use specta::Type;

use crate::personal_server::{PersonalServerError, TeamCreationPhase, TeamFailure, TeamSshSource};

/// Editable text for one concrete connection-policy denial; Rust supplies its target.
#[derive(Clone, Eq, PartialEq, Deserialize, Type)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TeamAccessRequestDraft {
    /// Requested finite duration, validated by the shared codec.
    pub duration_seconds: u32,
    /// Exact review text, without trimming or normalization.
    pub reason: String,
}

impl fmt::Debug for TeamAccessRequestDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TeamAccessRequestDraft").finish_non_exhaustive()
    }
}

/// Original request fields, containing no current inventory or permission projection.
#[derive(Clone, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamAccessRequestFields {
    /// Original same-team Host identifier.
    pub host_id: String,
    /// Exact remote username, retained without normalization.
    pub remote_user: String,
    /// Original finite interval length.
    pub duration_seconds: u32,
    /// Exact reason, shown only on the explicit request surface.
    pub reason: String,
}

impl fmt::Debug for TeamAccessRequestFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TeamAccessRequestFields").finish_non_exhaustive()
    }
}

/// The side-effect-free answer for one exact Rust-owned input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamAccessRequestCheckView {
    /// Complete authenticated deployment and Account source.
    pub source: TeamSshSource,
    /// Exact checked values, including the original denial target.
    pub fields: TeamAccessRequestFields,
    /// A complete current permit, never a connection permit or reservation.
    pub allowed: bool,
    /// Opaque Rust intent, present only for a permitted exact input.
    pub check_id: Option<String>,
}

/// A historical attributable approval or denial.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamAccessRequestDecisionView {
    /// Known approve or deny outcome.
    pub outcome: String,
    /// Historical actor, without implying current membership.
    pub actor_account_id: String,
    /// Exact server metadata timestamp.
    pub decided_at: String,
}

/// The original finite approval interval, not evidence of current access.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamAccessRequestGrantView {
    /// Server-generated original Grant identifier.
    pub id: String,
    /// Inclusive original whole-second UTC start.
    pub valid_from: String,
    /// Exclusive original whole-second UTC end.
    pub valid_until: String,
}

/// One validated server record, bound to the captured read source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamAccessRequestResourceView {
    /// Owning deployment, Account, Organization and Device.
    pub source: TeamSshSource,
    /// Original request identifier.
    pub id: String,
    /// Persisted server version, never replaced during confirmation.
    pub etag: String,
    /// Original server creation timestamp.
    pub created_at: String,
    /// Last persisted mutation timestamp.
    pub updated_at: String,
    /// Original requester attribution.
    pub requester_account_id: String,
    /// Exact original Membership, never substituted after rejoining.
    pub requester_membership_id: String,
    /// Original application text and concrete target.
    pub fields: TeamAccessRequestFields,
    /// Original fixed pending deadline, including any fractional seconds.
    pub expires_at: String,
    /// Exact persisted status, including bounded unknown future values.
    pub status: String,
    /// Local deadline observation; pending alone never enables an action.
    pub deadline_passed: bool,
    /// Current source may review its own pending cancellation.
    pub can_cancel: bool,
    /// This non-requester read may review an unexpired pending decision.
    pub can_decide: bool,
    /// Own approved history can offer a separate normal connection intent.
    pub can_connect: bool,
    /// Original historical decision, if present.
    pub decision: Option<TeamAccessRequestDecisionView>,
    /// Original historical Grant, if present.
    pub grant: Option<TeamAccessRequestGrantView>,
}

/// One explicit, ascending server list view.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum TeamAccessRequestList {
    /// Only the current Account's requests.
    Mine,
    /// Only currently routed, unexpired pending requests.
    Approvals,
}

/// One validated page; a continuation is only a locator for another authorized read.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamAccessRequestPageView {
    /// Exact captured source of this page.
    pub source: TeamSshSource,
    /// Exact read view, never mixed while appending pages.
    pub view: TeamAccessRequestList,
    /// At most the shared bounded page size.
    pub items: Vec<TeamAccessRequestResourceView>,
    /// Ascending request locator, if another page is available.
    pub next_cursor: Option<String>,
}

/// The exact GET response held by Rust for an explicit decision or cancellation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamAccessRequestReviewView {
    /// Opaque one-use reviewed intent; never a caller-authored ETag or Resource.
    pub intent_id: String,
    /// Current complete server projection reviewed by the person.
    pub resource: TeamAccessRequestResourceView,
}

/// One currently visible ordinary Login retaining the approved exact target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamAccessRequestLogin {
    /// Current Login display label.
    pub name: String,
    /// A separate explicit ordinary connection intent, never an approval permit.
    pub target: crate::connection::SessionTarget,
}

/// A single original mutation, never an editable decision or partial approval.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum TeamAccessRequestAction {
    /// Create the checked original application.
    Create,
    /// Approve the reviewed pending request.
    Approve,
    /// Deny the reviewed pending request.
    Deny,
    /// Cancel the requester's reviewed pending request.
    Cancel,
}

/// Durable recovery state, without proofs, tokens or a caller-selectable precondition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamAccessRequestOperationView {
    /// Complete original deployment, Account, Organization and Device.
    pub source: TeamSshSource,
    /// Original Idempotency-Key, used only as this local operation's identity.
    pub operation_id: String,
    /// Exact original resource identifier.
    pub request_id: String,
    /// Original immutable mutation kind.
    pub action: TeamAccessRequestAction,
    /// Only Unknown enables explicit original-request confirmation.
    pub phase: TeamCreationPhase,
    /// Original receipt deadline in Unix milliseconds, without number precision loss.
    pub retry_until: Option<String>,
    /// Original immutable application values, for explicit review.
    pub fields: TeamAccessRequestFields,
    /// Original successful response, not a current read or new connection authority.
    pub result: Option<TeamAccessRequestResourceView>,
}

/// Fixed, safe errors specific to access-request intent and recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type, thiserror::Error)]
#[serde(rename_all = "camelCase")]
pub enum TeamAccessRequestFailure {
    /// Shared input profile was not satisfied.
    #[error("Review the requested duration and reason before checking again.")]
    InvalidInput,
    /// Exact input or its captured authenticated context changed.
    #[error("Check these exact request details again before submitting.")]
    CheckRequired,
    /// The reviewed original version or source is no longer retained.
    #[error("Refresh and review this request again before choosing an action.")]
    ReviewRequired,
    /// Another original mutation must be resolved first.
    #[error("Resolve the retained access request operation before preparing another.")]
    OperationPending,
    /// No matching original local operation remains.
    #[error("This original access request operation is no longer retained.")]
    OperationMissing,
    /// Its fixed original confirmation deadline has ended.
    #[error("The original confirmation window ended. Refresh and review current state.")]
    OperationExpired,
    /// An attempted mutation may have committed.
    #[error("The change may have completed. Confirm only the retained original operation.")]
    OutcomeUnknown,
    /// Response shape, HTTP metadata or original tuple did not validate.
    #[error("The access request response could not be verified. Refresh before continuing.")]
    InvalidResponse,
    /// The original reviewed precondition no longer matches.
    #[error("This request changed. Refresh and review its current state before acting.")]
    StaleVersion,
    /// No current visible Login retains the original Host and remote user.
    #[error(
        "No currently visible Login matches this exact Host and SSH username. Refresh team assets."
    )]
    LoginRequired,
}

/// Existing authenticated Account/team failures and narrow access-request failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type, thiserror::Error)]
#[serde(untagged)]
pub enum TeamAccessRequestError {
    /// Account or encrypted local-store failure.
    #[error(transparent)]
    Personal(#[from] PersonalServerError),
    /// Current team authority failure.
    #[error(transparent)]
    Team(#[from] TeamFailure),
    /// Exact request or original-operation recovery failure.
    #[error(transparent)]
    Request(#[from] TeamAccessRequestFailure),
}

impl From<crate::personal_server::TeamError> for TeamAccessRequestError {
    fn from(error: crate::personal_server::TeamError) -> Self {
        match error {
            crate::personal_server::TeamError::Personal(error) => Self::Personal(error),
            crate::personal_server::TeamError::Team(error) => Self::Team(error),
        }
    }
}
