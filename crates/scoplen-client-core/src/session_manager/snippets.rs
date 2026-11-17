// SPDX-License-Identifier: Apache-2.0
//! Source-bound Team Snippet intents on already-ready ordinary terminal transports.

use super::*;
use crate::personal_server::TeamSshSource;
use crate::snippets::{
    SnippetIssue,
    team::{
        self, PreparedTeamSnippet, SnippetTerminal, TeamSnippetFence, TeamSnippetLibrary,
        TeamSnippetSendOutcome,
    },
};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
mod tests;

impl SessionManager {
    fn snippet_source(&self, terminal: &SnippetTerminal) -> Result<TeamSshSource, SnippetIssue> {
        let sessions = self.sessions.lock().map_err(|_| SnippetIssue::Unavailable)?;
        ready_source(&sessions, terminal).ok_or(SnippetIssue::Unavailable)
    }

    /// List only the originating ready terminal's complete, acknowledged Team library.
    pub fn team_snippets(
        &self,
        store: &Store,
        origin: &SnippetTerminal,
    ) -> Result<TeamSnippetLibrary, SnippetIssue> {
        let source = self.snippet_source(origin)?;
        team::library(store, &source)
    }

    /// Prepare one current Team definition and explicitly selected same-source terminals.
    pub fn prepare_team_snippet(
        &self,
        store: &Store,
        origin: SnippetTerminal,
        fence: TeamSnippetFence,
        id: &str,
        values: BTreeMap<String, String>,
        targets: Vec<SnippetTerminal>,
    ) -> Result<PreparedTeamSnippet, SnippetIssue> {
        if targets.is_empty()
            || targets.len() > 64
            || targets
                .iter()
                .map(|target| (&target.session_id, &target.transport_id))
                .collect::<BTreeSet<_>>()
                .len()
                != targets.len()
        {
            return Err(SnippetIssue::Unavailable);
        }
        {
            let sessions = self.sessions.lock().map_err(|_| SnippetIssue::Unavailable)?;
            if ready_source(&sessions, &origin).as_ref() != Some(&fence.source)
                || targets
                    .iter()
                    .any(|target| ready_source(&sessions, target).as_ref() != Some(&fence.source))
            {
                return Err(SnippetIssue::Unavailable);
            }
        }
        let snippet = team::prepare(store, &fence, id, values)?;
        Ok(PreparedTeamSnippet { fence, origin, snippet, targets })
    }

    /// Send the exact reviewed bytes once to one original target, without rerendering or reconnecting.
    pub fn send_team_snippet(
        &self,
        store: &Store,
        prepared: &PreparedTeamSnippet,
        index: usize,
    ) -> Result<TeamSnippetSendOutcome, SnippetIssue> {
        if team::current(store, &prepared.fence).is_err() {
            return Ok(TeamSnippetSendOutcome::Invalidated);
        }
        let command = &prepared.snippet.command;
        if command.len() >= MAX_SSH_INPUT || command.chars().any(|value| value.is_ascii_control()) {
            return Err(SnippetIssue::InvalidTemplate);
        }
        let target = prepared.targets.get(index).ok_or(SnippetIssue::Unavailable)?;
        let sessions = self.sessions.lock().map_err(|_| SnippetIssue::Unavailable)?;
        if ready_source(&sessions, &prepared.origin).as_ref() != Some(&prepared.fence.source) {
            return Ok(TeamSnippetSendOutcome::Invalidated);
        }
        if ready_source(&sessions, target).as_ref() != Some(&prepared.fence.source) {
            return Ok(TeamSnippetSendOutcome::NotSent);
        }
        let active =
            sessions[&target.session_id].active.as_ref().ok_or(SnippetIssue::Unavailable)?;
        let mut bytes = command.as_bytes().to_vec();
        bytes.push(b'\r');
        Ok(if active.sender.try_send(TransportCommand::Input(bytes)).is_ok() {
            TeamSnippetSendOutcome::Sent
        } else {
            TeamSnippetSendOutcome::NotSent
        })
    }
}

fn ready_source(
    sessions: &HashMap<String, SessionEntry>,
    terminal: &SnippetTerminal,
) -> Option<TeamSshSource> {
    let entry = sessions.get(&terminal.session_id)?;
    let active = entry.active.as_ref()?;
    if !entry.pty
        || !active.ready
        || active.id.to_string() != terminal.transport_id
        || *entry.intent.borrow() != Intent::None
    {
        return None;
    }
    active.context.as_ref()?.source.clone()
}
