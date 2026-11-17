// SPDX-License-Identifier: Apache-2.0
//! Local, complete-view Team Snippet projections; terminal admission owns execution.

use super::*;
use crate::personal_server::{TeamAssetsPhase, TeamSshSource};

/// Existing terminal identity, never a request to connect or replace a transport.
#[derive(Clone, Debug, Deserialize, Serialize, Type, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SnippetTerminal {
    /// Logical terminal owner.
    pub session_id: String,
    /// Exact existing transport.
    pub transport_id: String,
}

/// Captured existing view and authentication owners, without an execution lease.
#[derive(Clone, Debug, Deserialize, Serialize, Type, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TeamSnippetFence {
    /// Canonical deployment, Account, Device and Organization.
    pub source: TeamSshSource,
    /// Organization inventory namespace.
    pub vault_id: String,
    /// Exact uint64 revision, without JavaScript precision loss.
    pub revision: String,
    /// Matching acknowledged cursor.
    pub cursor: String,
    /// Existing complete-view publication owner.
    pub view_generation: String,
    /// Existing retained authentication owner.
    pub auth_generation: String,
}

/// Read-only library from one terminal's actual Organization source.
#[derive(Clone, Debug, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamSnippetLibrary {
    /// Actual source, never inferred from a display label.
    pub source: TeamSshSource,
    /// Existing current-view state.
    pub phase: TeamAssetsPhase,
    /// Whether the complete publication's ACK is confirmed.
    pub acknowledged: bool,
    /// Present only for a complete Ready publication with matching ACK.
    pub fence: Option<TeamSnippetFence>,
    /// Safe complete definitions; asset immutability is independent of eligibility.
    pub snippets: Vec<SnippetView>,
}

/// Exact command and ordered existing terminals confirmed by the user.
#[derive(Clone, Debug, Deserialize, Serialize, Type, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PreparedTeamSnippet {
    /// The original complete view and its current owners.
    pub fence: TeamSnippetFence,
    /// Originating ready terminal that owns the dialog.
    pub origin: SnippetTerminal,
    /// Complete exact command, never rerendered at Send.
    pub snippet: PreparedSnippet,
    /// One to 64 distinct transports in the confirmed order.
    pub targets: Vec<SnippetTerminal>,
}

/// Local queue outcomes; none claims remote execution or an exit status.
#[derive(Clone, Copy, Debug, Serialize, Type, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TeamSnippetSendOutcome {
    /// Accepted by the exact existing input queue.
    Sent,
    /// Refused before queue handoff; another reviewed target may still qualify.
    NotSent,
    /// The originating source/view is obsolete; stop starting further sends.
    Invalidated,
}

pub(crate) fn library(
    store: &Store,
    source: &TeamSshSource,
) -> Result<TeamSnippetLibrary, SnippetIssue> {
    let owner = source.owner(store).map_err(|_| SnippetIssue::Unavailable)?;
    let identity = store.personal_record()?.ok_or(SnippetIssue::Unavailable)?;
    let saved = store.team_assets_record(&identity, owner.organization)?;
    let mut result = TeamSnippetLibrary {
        source: source.clone(),
        phase: TeamAssetsPhase::NotLoaded,
        acknowledged: false,
        fence: None,
        snippets: Vec::new(),
    };
    if let Some(saved) = saved {
        result.phase = match saved.phase {
            0 => TeamAssetsPhase::Updating,
            1 => TeamAssetsPhase::Ready,
            2 => TeamAssetsPhase::Stale,
            3 => TeamAssetsPhase::Unavailable,
            _ => TeamAssetsPhase::Failed,
        };
        result.acknowledged = saved.acknowledged;
        if saved.phase == 1 && saved.acknowledged {
            result.fence = Some(TeamSnippetFence {
                source: source.clone(),
                vault_id: saved.vault.ok_or(SnippetIssue::Storage)?.to_string(),
                revision: saved.revision.ok_or(SnippetIssue::Storage)?.to_string(),
                cursor: saved.cursor.to_string(),
                view_generation: saved.generation.to_string(),
                auth_generation: identity.auth_generation.to_string(),
            });
            result.snippets = saved
                .objects
                .iter()
                .filter(|object| {
                    object.object_type == ObjectType::SNIPPET && !object.is_tombstoned()
                })
                .map(view)
                .collect();
            result.snippets.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
        }
    }
    Ok(result)
}

pub(crate) fn current(store: &Store, fence: &TeamSnippetFence) -> Result<(), SnippetIssue> {
    let owner = fence.source.owner(store).map_err(|_| SnippetIssue::Unavailable)?;
    let identity = store.personal_record()?.ok_or(SnippetIssue::Unavailable)?;
    if identity.auth_generation.to_string() != fence.auth_generation
        || !store.team_snippet_view_current(
            &identity,
            &crate::store::team_assets::TeamAssetPublication {
                organization: owner.organization,
                vault: Uuid::parse_str(&fence.vault_id).map_err(|_| SnippetIssue::Unavailable)?,
                revision: fence.revision.parse().map_err(|_| SnippetIssue::Unavailable)?,
                cursor: fence.cursor.parse().map_err(|_| SnippetIssue::Unavailable)?,
                generation: Uuid::parse_str(&fence.view_generation)
                    .map_err(|_| SnippetIssue::Unavailable)?,
            },
        )?
    {
        return Err(SnippetIssue::Unavailable);
    }
    Ok(())
}

pub(crate) fn prepare(
    store: &Store,
    fence: &TeamSnippetFence,
    id: &str,
    values: BTreeMap<String, String>,
) -> Result<PreparedSnippet, SnippetIssue> {
    current(store, fence)?;
    let parsed = Uuid::parse_str(id).map_err(|_| SnippetIssue::InvalidId)?;
    if parsed.get_version_num() != 7 || parsed.to_string() != id {
        return Err(SnippetIssue::InvalidId);
    }
    let owner = fence.source.owner(store).map_err(|_| SnippetIssue::Unavailable)?;
    let identity = store.personal_record()?.ok_or(SnippetIssue::Unavailable)?;
    let saved = store
        .team_assets_record(&identity, owner.organization)?
        .ok_or(SnippetIssue::Unavailable)?;
    if saved.generation.to_string() != fence.view_generation
        || saved.phase != 1
        || !saved.acknowledged
    {
        return Err(SnippetIssue::Unavailable);
    }
    let object = saved
        .objects
        .iter()
        .find(|object| {
            object.id == parsed
                && object.object_type == ObjectType::SNIPPET
                && !object.is_tombstoned()
        })
        .ok_or(SnippetIssue::NotFound)?;
    prepare_object(object, values)
}
