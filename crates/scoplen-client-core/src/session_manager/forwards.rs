// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::forward_manager::ForwardIssue;

#[cfg(test)]
mod tests;

impl SessionManager {
    /// Read attached outcomes only for the exact current store and terminal transport.
    pub fn forward_list(
        &self,
        store: &Arc<Store>,
        session_id: &str,
        transport_id: &str,
    ) -> Result<Vec<SessionForwardSnapshot>, ForwardIssue> {
        let sessions = self.sessions.lock().map_err(|_| ForwardIssue::Unavailable)?;
        let state = Self::forward_state(&sessions, store, session_id, transport_id)?;
        state.snapshots()
    }

    /// Stop a selected definition for this logical terminal, including future reconnects.
    pub fn forward_stop(
        &self,
        store: &Arc<Store>,
        session_id: &str,
        transport_id: &str,
        forward_id: &str,
    ) -> Result<(), ForwardIssue> {
        let sessions = self.sessions.lock().map_err(|_| ForwardIssue::Unavailable)?;
        let state = Self::forward_state(&sessions, store, session_id, transport_id)?;
        let id = Uuid::parse_str(forward_id).map_err(|_| ForwardIssue::Expired)?;
        state.stop_entry(id)
    }

    fn forward_state<'a>(
        sessions: &'a HashMap<String, SessionEntry>,
        store: &Arc<Store>,
        session_id: &str,
        transport_id: &str,
    ) -> Result<&'a AttachedForwardState, ForwardIssue> {
        let transport = Uuid::parse_str(transport_id).map_err(|_| ForwardIssue::Expired)?;
        let entry = sessions.get(session_id).ok_or(ForwardIssue::Expired)?;
        if *entry.intent.borrow() != Intent::None
            || !entry.active.as_ref().is_some_and(|active| active.id == transport && active.ready)
        {
            return Err(ForwardIssue::Expired);
        }
        entry
            .attached_forwards
            .as_ref()
            .filter(|state| state.belongs_to(store, transport))
            .map(Arc::as_ref)
            .ok_or(ForwardIssue::Expired)
    }
}
