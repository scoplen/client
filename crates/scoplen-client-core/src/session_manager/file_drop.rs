// SPDX-License-Identifier: Apache-2.0

//! Native selections remain Rust-owned until one context-bound batch is admitted.

use std::collections::HashSet;

use serde::Serialize;
use specta::Type;

use super::*;
use crate::session_transfers::{SessionTransferIssue, SessionTransferReview, TRANSFER_CAPACITY};

const DROP_TTL: Duration = Duration::from_secs(30);

/// Path-free phases emitted by the application, independently of framework drag events.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum FileDragPhase {
    /// Native pointer movement over the webview.
    Over,
    /// Native drag left the webview; a completed drop is unaffected.
    Leave,
    /// A bounded selection is waiting for destination hit testing.
    Drop,
    /// Native admission refused the selection or its geometry.
    Refused,
}

/// Only opaque identities, bounded counts and normalized positions cross product IPC.
#[derive(Clone, Debug, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct FileDrag {
    /// Current Files view identity.
    pub context_id: String,
    /// Native drag transition.
    pub phase: FileDragPhase,
    /// Present only for an unconsumed native Drop.
    pub ticket_id: Option<String>,
    /// At most 17, where 17 also represents an oversized selection.
    pub count: u32,
    /// Horizontal webview fraction, when valid.
    pub x: Option<f64>,
    /// Vertical webview fraction, when valid.
    pub y: Option<f64>,
}

/// Whole-batch admission result, without native paths or display filenames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct FileDropAccepted {
    /// Number of items appended together to the existing queue.
    pub accepted: u32,
}

pub(super) struct DropContext {
    id: Uuid,
    session: String,
    transport: Uuid,
    queue: Uuid,
    directory: Vec<u8>,
    hover_count: u32,
    ticket: Option<DropTicket>,
}

struct DropTicket {
    id: Uuid,
    expires: Instant,
    paths: Option<Vec<PathBuf>>,
}

impl SessionManager {
    /// Arm one visible Files view. The shell supplies the actual caller's window identity.
    pub fn arm_file_drop(
        &self,
        window: &str,
        context_id: &str,
        session_id: &str,
        transport_id: &str,
        queue_id: &str,
        directory: Vec<u8>,
    ) -> Result<(), SessionTransferIssue> {
        session_files::validate_path(&directory).map_err(transfers::file_issue)?;
        let context = DropContext {
            id: parse_id(context_id)?,
            session: session_id.to_owned(),
            transport: parse_id(transport_id)?,
            queue: parse_id(queue_id)?,
            directory,
            hover_count: 0,
            ticket: None,
        };
        let mut drops = self.drops.lock().map_err(|_| SessionTransferIssue::SessionUnavailable)?;
        let sessions =
            self.sessions.lock().map_err(|_| SessionTransferIssue::SessionUnavailable)?;
        validate_context(&sessions, &context, false)?;
        drops.insert(window.to_owned(), context);
        Ok(())
    }

    /// Revoke only the caller's obsolete view, never a newer view in the same window.
    pub fn revoke_file_drop(&self, window: &str, context_id: &str) {
        if let Ok(mut drops) = self.drops.lock()
            && drops.get(window).is_some_and(|context| context.id.to_string() == context_id)
        {
            drops.remove(window);
        }
    }

    /// Native geometry/lifetime changes invalidate every pending intent for this window.
    pub fn invalidate_file_drop(&self, window: &str) {
        if let Ok(mut drops) = self.drops.lock() {
            drops.remove(window);
        }
    }

    /// Retain only the bounded native selection count for later pointer movement.
    pub fn begin_file_drag(
        &self,
        window: &str,
        count: usize,
        position: Option<(f64, f64)>,
    ) -> Option<FileDrag> {
        let mut drops = self.drops.lock().ok()?;
        let context = drops.get_mut(window)?;
        let sessions = self.sessions.lock().ok()?;
        validate_context(&sessions, context, false).ok()?;
        context.hover_count = count.min(TRANSFER_CAPACITY + 1) as u32;
        let phase = if (1..=TRANSFER_CAPACITY).contains(&count) && valid_position(position) {
            FileDragPhase::Over
        } else {
            FileDragPhase::Refused
        };
        Some(drag(context, phase, None, context.hover_count, position))
    }

    /// Reuse the native Enter count; Leave clears hover without revoking a ticket.
    pub fn file_drag(
        &self,
        window: &str,
        phase: FileDragPhase,
        position: Option<(f64, f64)>,
    ) -> Option<FileDrag> {
        let mut drops = self.drops.lock().ok()?;
        let context = drops.get_mut(window)?;
        let sessions = self.sessions.lock().ok()?;
        validate_context(&sessions, context, false).ok()?;
        if phase == FileDragPhase::Leave {
            context.hover_count = 0;
        }
        let phase = if phase == FileDragPhase::Over
            && !(1..=TRANSFER_CAPACITY as u32).contains(&context.hover_count)
        {
            FileDragPhase::Refused
        } else {
            phase
        };
        Some(drag(context, phase, None, context.hover_count, position))
    }

    /// Freeze native-only paths and the complete destination context into a one-use ticket.
    /// The explicit runtime also supports synchronous native callbacks outside a Tokio context.
    pub fn capture_file_drop(
        &self,
        runtime: &tokio::runtime::Handle,
        window: &str,
        paths: Vec<PathBuf>,
        position: Option<(f64, f64)>,
    ) -> Option<FileDrag> {
        let mut drops = self.drops.lock().ok()?;
        let context = drops.get_mut(window)?;
        context.ticket = None;
        let sessions = self.sessions.lock().ok()?;
        let count = paths.len().min(TRANSFER_CAPACITY + 1) as u32;
        if validate_context(&sessions, context, false).is_err()
            || paths.is_empty()
            || paths.len() > TRANSFER_CAPACITY
            || !valid_position(position)
        {
            return Some(drag(context, FileDragPhase::Refused, None, count, None));
        }
        let id = Uuid::now_v7();
        let expires = Instant::now() + DROP_TTL;
        context.ticket = Some(DropTicket { id, expires, paths: Some(paths) });
        let event = drag(context, FileDragPhase::Drop, Some(id), count, position);
        let manager = self.clone();
        let window = window.to_owned();
        let context_id = context.id;
        drop(runtime.spawn(async move {
            tokio::time::sleep_until(expires).await;
            manager.expire_file_drop(&window, context_id, id);
        }));
        Some(event)
    }

    fn expire_file_drop(&self, window: &str, context_id: Uuid, ticket_id: Uuid) {
        if let Ok(mut drops) = self.drops.lock()
            && let Some(context) = drops.get_mut(window).filter(|context| context.id == context_id)
            && context
                .ticket
                .as_ref()
                .is_some_and(|ticket| ticket.id == ticket_id && Instant::now() >= ticket.expires)
        {
            context.ticket = None;
        }
    }

    /// Cancel one exact pending drop, without changing any admitted queue items.
    pub fn cancel_file_drop(&self, window: &str, context_id: &str, ticket_id: &str) {
        if let Ok(mut drops) = self.drops.lock()
            && let Some(context) =
                drops.get_mut(window).filter(|context| context.id.to_string() == context_id)
            && context.ticket.as_ref().is_some_and(|ticket| ticket.id.to_string() == ticket_id)
        {
            context.ticket = None;
        }
    }

    /// Consume once, reserve the entire batch before opening files, then append once.
    pub async fn consume_file_drop<C, Fut>(
        &self,
        window: &str,
        context_id: &str,
        ticket_id: &str,
        confirm: C,
    ) -> Result<FileDropAccepted, SessionTransferIssue>
    where
        C: Fn(SessionTransferReview) -> Fut + Clone + Send + 'static,
        Fut: Future<Output = Result<bool, SessionTransferIssue>> + Send + 'static,
    {
        let context_id = parse_id(context_id)?;
        let ticket_id = parse_id(ticket_id)?;
        let (frozen, paths, expires) = {
            let mut drops =
                self.drops.lock().map_err(|_| SessionTransferIssue::SessionUnavailable)?;
            let context = drops
                .get_mut(window)
                .filter(|context| context.id == context_id)
                .ok_or(SessionTransferIssue::StaleItem)?;
            if context.ticket.as_ref().is_some_and(|ticket| Instant::now() >= ticket.expires) {
                context.ticket = None;
            }
            let ticket = context
                .ticket
                .as_mut()
                .filter(|ticket| ticket.id == ticket_id && Instant::now() < ticket.expires)
                .ok_or(SessionTransferIssue::StaleItem)?;
            // Taking the selection before capacity admission makes every consume attempt single-use.
            let paths = ticket.paths.take().ok_or(SessionTransferIssue::StaleItem)?;
            let expires = ticket.expires;
            (
                DropContext {
                    id: context.id,
                    session: context.session.clone(),
                    transport: context.transport,
                    queue: context.queue,
                    directory: context.directory.clone(),
                    hover_count: 0,
                    ticket: None,
                },
                paths,
                expires,
            )
        };
        let reservation = {
            let mut sessions =
                self.sessions.lock().map_err(|_| SessionTransferIssue::SessionUnavailable)?;
            validate_context(&sessions, &frozen, false)?;
            let entry = sessions
                .get_mut(&frozen.session)
                .ok_or(SessionTransferIssue::SessionUnavailable)?;
            entry.transfers.reserve_selections(frozen.transport, paths.len())?
        };
        let session = frozen.session;
        let directory = frozen.directory;
        let manager = self.clone();
        let window = window.to_owned();
        tokio::spawn(async move {
            let _lease = transfers::SelectionLease {
                manager: manager.clone(),
                session: session.clone(),
                reservation,
            };
            // A blocked filesystem call may outlive its waiter, but never the queue reservation.
            tokio::time::timeout_at(expires, async move {
                let mut selected = Vec::with_capacity(paths.len());
                let mut targets = HashSet::with_capacity(paths.len());
                for path in paths {
                    let source = session_files::open_upload_source(&path)
                        .await
                        .map_err(transfers::file_issue)?;
                    let target = source.target(&directory).map_err(transfers::file_issue)?;
                    if !targets.insert(target) {
                        return Err(SessionTransferIssue::InvalidSelection);
                    }
                    let callback = confirm.clone();
                    selected.push((
                        source.display_name(),
                        source.size(),
                        SelectedTransfer::Upload {
                            source,
                            directory: directory.clone(),
                            confirm: Box::new(move |review| Box::pin(callback(review))),
                        },
                    ));
                }
                let accepted = selected.len() as u32;
                {
                    let mut drops = manager
                        .drops
                        .lock()
                        .map_err(|_| SessionTransferIssue::SessionUnavailable)?;
                    let context = drops
                        .get_mut(&window)
                        .filter(|context| context.id == context_id)
                        .ok_or(SessionTransferIssue::StaleItem)?;
                    let mut sessions = manager
                        .sessions
                        .lock()
                        .map_err(|_| SessionTransferIssue::SessionUnavailable)?;
                    validate_context(&sessions, context, true)?;
                    if !context.ticket.as_ref().is_some_and(|ticket| {
                        ticket.id == ticket_id
                            && ticket.paths.is_none()
                            && Instant::now() < ticket.expires
                    }) {
                        return Err(SessionTransferIssue::StaleItem);
                    }
                    let entry = sessions
                        .get_mut(&session)
                        .ok_or(SessionTransferIssue::SessionUnavailable)?;
                    entry.transfers.enqueue_upload_batch(reservation, selected)?;
                    entry.transfer_notify.notify_one();
                    context.ticket = None;
                }
                manager.start_transfer_worker(&session);
                Ok(FileDropAccepted { accepted })
            })
            .await
            .unwrap_or(Err(SessionTransferIssue::StaleItem))
        })
        .await
        .map_err(|_| SessionTransferIssue::SelectionFailed)?
    }
}

fn parse_id(value: &str) -> Result<Uuid, SessionTransferIssue> {
    Uuid::parse_str(value).map_err(|_| SessionTransferIssue::InvalidIdentifier)
}

fn validate_context(
    sessions: &HashMap<String, SessionEntry>,
    context: &DropContext,
    selecting: bool,
) -> Result<(), SessionTransferIssue> {
    let entry = sessions.get(&context.session).ok_or(SessionTransferIssue::SessionUnavailable)?;
    if entry.transfers.id() != context.queue {
        return Err(SessionTransferIssue::StaleItem);
    }
    let active = entry
        .active
        .as_ref()
        .filter(|active| {
            active.ready && active.id == context.transport && *entry.intent.borrow() == Intent::None
        })
        .ok_or(SessionTransferIssue::TransportEnded)?;
    if !selecting
        && (entry.transfers.snapshot(&context.session).picker_busy
            || active.file.as_ref().is_some_and(|file| file.transfer.is_none()))
    {
        return Err(SessionTransferIssue::NativeDialogBusy);
    }
    Ok(())
}

fn valid_position(position: Option<(f64, f64)>) -> bool {
    position.is_some_and(|(x, y)| {
        x.is_finite() && y.is_finite() && (0.0..1.0).contains(&x) && (0.0..1.0).contains(&y)
    })
}

fn drag(
    context: &DropContext,
    phase: FileDragPhase,
    ticket: Option<Uuid>,
    count: u32,
    position: Option<(f64, f64)>,
) -> FileDrag {
    let position = position.filter(|_| valid_position(position));
    FileDrag {
        context_id: context.id.to_string(),
        phase,
        ticket_id: ticket.map(|id| id.to_string()),
        count,
        x: position.map(|(x, _)| x),
        y: position.map(|(_, y)| y),
    }
}

#[cfg(test)]
mod tests;
