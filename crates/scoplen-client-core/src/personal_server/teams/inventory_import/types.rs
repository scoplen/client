// SPDX-License-Identifier: Apache-2.0
//! Internal native import projections; the shared HTTP contract is unchanged.

use serde::{Deserialize, Serialize};
use specta::Type;

use super::super::{TeamAssetsView, TeamError};

/// One explicitly selected shared source interpretation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum TeamImportSource {
    /// D-151's complete five-column CSV profile.
    Csv,
    /// D-153's one-file Direct OpenSSH profile.
    OpenSsh,
}

/// Fixed shared diagnostic metadata, without source text or paths.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamImportDiagnostic {
    /// Fixed shared parser code.
    pub code: String,
    /// One-based CSV data record, if supplied by the parser.
    pub record: Option<u32>,
    /// One-based OpenSSH physical line, if supplied by the parser.
    pub line: Option<u32>,
    /// Known shared field name only.
    pub field: Option<String>,
}

/// Intentional successful metadata projection for disclosure review.
#[derive(Clone, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamImportFields {
    /// Original Host name.
    pub name: String,
    /// Direct connection address.
    pub address: String,
    /// Direct SSH port.
    pub port: u16,
    /// Exact remote username.
    pub username: String,
    /// Optional CSV Login name.
    pub login_name: Option<String>,
}

/// Every source candidate remains represented in its original order.
#[derive(Clone, Serialize, Type)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum TeamImportCandidate {
    /// Explicitly selectable typed metadata, without identities.
    Ready {
        /// One-based ordinal in the complete source result.
        ordinal: u32,
        /// Metadata that will become team inventory.
        fields: TeamImportFields,
    },
    /// A refused candidate cannot become part of a batch.
    Blocked {
        /// One-based ordinal in the complete source result.
        ordinal: u32,
        /// Fixed source-free reason.
        diagnostic: TeamImportDiagnostic,
    },
}

/// Rust-owned review identity and its complete intentional display projection.
#[derive(Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamImportPreview {
    /// Opaque identity, invalidated when replaced or explicitly cleared.
    pub preview_id: String,
    /// Canonical deployment.
    pub origin: String,
    /// Owning admitted Account.
    pub account_id: String,
    /// Explicit selected team.
    pub organization_id: String,
    /// Captured source interpretation.
    pub source: TeamImportSource,
    /// Complete ordered Ready/Blocked result.
    pub candidates: Vec<TeamImportCandidate>,
}

/// Durable original-operation state; reads never submit it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum TeamImportPhase {
    /// Safe for explicit dispatch or cancellation.
    Prepared,
    /// A dispatch may have committed; only the original operation can be confirmed.
    Unknown,
    /// Complete exact ordered result was verified and retained.
    Confirmed,
    /// The original 24-hour confirmation window ended.
    Expired,
}

/// An original pair and its reviewed metadata; these ids never change on confirmation.
#[derive(Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamImportRow {
    /// Original Host UUIDv7.
    pub host_id: String,
    /// Original default Login UUIDv7.
    pub login_id: String,
    /// Exact submitted metadata.
    pub fields: TeamImportFields,
}

/// Exact batch recovery projection, independent of current inventory visibility.
#[derive(Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamImportPending {
    /// Original canonical deployment.
    pub origin: String,
    /// Original Account.
    pub account_id: String,
    /// Original team.
    pub organization_id: String,
    /// Original Idempotency-Key.
    pub operation_id: String,
    /// Current permitted recovery action.
    pub phase: TeamImportPhase,
    /// Original submitted order and allocated identities.
    pub rows: Vec<TeamImportRow>,
    /// An expired operation has had an explicit current-inventory review attempt.
    pub can_archive: bool,
}

/// Explicit current-member refresh, including a failed attempt before expired archive.
#[derive(Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamImportInventoryReview {
    /// Retained operation, including its newly recorded review attempt.
    pub pending: TeamImportPending,
    /// Only the ordinary current view/ACK result can establish availability.
    pub inventory: Option<TeamAssetsView>,
    /// A fixed ordinary refresh refusal; it never changes historical confirmation.
    pub error: Option<TeamError>,
}

/// Current Account's saved destinations, without any unselected batch contents.
#[derive(Clone, Debug, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamImportSavedPage {
    /// Original teams with retained imports; these ids grant no new-import authority.
    pub organization_ids: Vec<String>,
    /// Explicit ascending continuation, if more retained destinations exist.
    pub next_cursor: Option<String>,
}

/// Fixed native failures; no filesystem/process/server diagnostic is rendered.
#[derive(Clone, Debug, Serialize, Type, thiserror::Error)]
#[serde(tag = "kind", content = "detail", rename_all = "camelCase")]
pub enum TeamImportError {
    /// Existing fixed Account/team error.
    #[error(transparent)]
    Team(#[from] TeamError),
    /// Whole-file shared preparation refusal.
    #[error("The selected source cannot be prepared. Correct it and choose it again.")]
    Source(TeamImportDiagnostic),
    /// File opening, regular-file admission or bounded reading failed.
    #[error("The selected file could not be read. Choose an accessible regular file.")]
    FileUnavailable,
    /// Another operation owns the current mutation slot.
    #[error("Another Account operation is running. Try again when it finishes.")]
    Busy,
    /// The exact preview was cleared, replaced or belongs to another runtime context.
    #[error("This preview is no longer current. Choose the source again.")]
    StalePreview,
    /// Empty, duplicate, blocked or foreign ordinals.
    #[error("Select at least one Ready row from the current preview.")]
    InvalidSelection,
    /// An existing original batch must not be replaced.
    #[error("Resolve the saved import before preparing another for this team.")]
    Pending,
    /// No exact original operation is retained.
    #[error("This saved import is no longer available. Reload its status.")]
    Missing,
    /// The original confirmation window ended.
    #[error("The confirmation window ended. Review current inventory before archiving.")]
    Expired,
    /// Handoff or exact response could not be established.
    #[error("The import may have committed. Confirm this original import explicitly.")]
    Unknown,
    /// Expired archive requires a real explicit review attempt.
    #[error("Review current inventory before archiving this expired import.")]
    ReviewRequired,
    /// Retained canonical bytes or a shared request failed validation.
    #[error("The import could not be validated. Its original state was retained.")]
    InvalidRequest,
}

impl From<crate::personal_server::PersonalServerError> for TeamImportError {
    fn from(value: crate::personal_server::PersonalServerError) -> Self {
        Self::Team(value.into())
    }
}

macro_rules! redact_debug {
    ($($ty:ty),+ $(,)?) => {$(
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($ty)).finish_non_exhaustive()
            }
        }
    )+};
}
redact_debug!(
    TeamImportFields,
    TeamImportCandidate,
    TeamImportPreview,
    TeamImportRow,
    TeamImportPending,
    TeamImportInventoryReview
);
