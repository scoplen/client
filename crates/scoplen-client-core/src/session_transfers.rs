// SPDX-License-Identifier: Apache-2.0

//! Bounded, display-safe state for a logical terminal's file-transfer queue.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use specta::Type;
use uuid::Uuid;

use crate::connection::preparation::PreparationContext;
use crate::session_files::{FileTransferProgress, SessionFileTransferPhase};

mod local;
mod selected;

pub(crate) use local::DownloadDestination;
pub(crate) use selected::{ReplaceConfirmation, SelectedTransfer};

pub(crate) const TRANSFER_CAPACITY: usize = 16;
const TRANSFER_HISTORY: usize = 32;
const MAX_NAME_CHARACTERS: usize = 128;

/// The direction of a terminal-owned transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum SessionTransferDirection {
    /// Publish one native-selected local file on the remote host.
    Upload,
    /// Save one remote file to a native-selected local destination.
    Download,
}

/// Bound connection context used only by the owned native confirmation callback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionTransferReview {
    /// Selected file's bounded display name.
    pub name: String,
    /// Authenticated target's saved display label.
    pub host: String,
    /// Actual username used for this target connection.
    pub username: String,
    /// Actual endpoint used for this target connection.
    pub address: String,
    /// Actual endpoint port.
    pub port: u16,
    /// Direction of the retained queue item.
    pub direction: SessionTransferDirection,
}

impl SessionTransferReview {
    pub(crate) fn new(
        context: &PreparationContext,
        name: &str,
        direction: SessionTransferDirection,
    ) -> Self {
        Self {
            name: display_text(name, MAX_NAME_CHARACTERS),
            host: display_text(&context.host, 256),
            username: display_text(&context.username, 256),
            address: display_text(&context.address, 256),
            port: context.port,
            direction,
        }
    }
}

fn display_text(value: &str, limit: usize) -> String {
    value
        .chars()
        .take(limit)
        .map(|character| {
            if character.is_control()
                || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

/// Current state or confirmed result of one transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum SessionTransferState {
    /// Waiting behind another transfer.
    Queued,
    /// Waiting for a native replacement decision.
    AwaitingConfirmation,
    /// Preparing or moving file data; publication has not succeeded.
    Transferring,
    /// The current bounded download segment is settling before retaining a checkpoint.
    Pausing,
    /// An owned download checkpoint is waiting for explicit continuation.
    Paused,
    /// The retained local and remote prefixes are being verified before continuation.
    Validating,
    /// Checking and saving the completed byte stream.
    Finalizing,
    /// Cancellation or disconnection cleanup is still settling.
    Cancelling,
    /// Publication was confirmed.
    Saved,
    /// Explicit cancellation settled before publication.
    Cancelled,
    /// The reviewed source or destination no longer matches.
    Conflict,
    /// The operation failed without an unknown publication.
    Failed,
    /// The bound transport ended; this item will not be replayed.
    Interrupted,
    /// Publication may have happened; explicit acknowledgement is required.
    Unknown,
}

/// Fixed operational categories; native paths and underlying errors stay in Rust.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type, thiserror::Error)]
#[serde(rename_all = "camelCase")]
pub enum SessionTransferIssue {
    /// An opaque identifier was malformed.
    #[error("the transfer identifier is invalid")]
    InvalidIdentifier,
    /// The remote path violated the file-access boundary.
    #[error("the selected remote path is invalid")]
    InvalidPath,
    /// The logical session owner is unavailable.
    #[error("the terminal session is unavailable")]
    SessionUnavailable,
    /// The authenticated transport selected for this item ended.
    #[error("the selected SSH connection has ended")]
    TransportEnded,
    /// All outstanding slots are occupied, including unresolved unknown results.
    #[error("the file-transfer queue is full")]
    QueueFull,
    /// A native selection or confirmation is already open for this queue.
    #[error("finish the current file selection or confirmation first")]
    NativeDialogBusy,
    /// The native picker or replacement dialog could not finish.
    #[error("the native file selection or confirmation failed")]
    SelectionFailed,
    /// The selected source or destination is not an ordinary usable local file.
    #[error("choose an ordinary local file or file destination")]
    InvalidSelection,
    /// The selected local or remote source changed before publication.
    #[error("the selected source file changed")]
    SourceChanged,
    /// The reviewed destination changed before publication.
    #[error("the reviewed file destination changed")]
    TargetChanged,
    /// The peer cannot safely perform the requested operation.
    #[error("this SSH server does not support the required file operation")]
    Unsupported,
    /// The remote server explicitly refused the operation.
    #[error("the SSH server refused the file operation")]
    RemoteRefused,
    /// A native source read, temporary file or destination operation failed.
    #[error("the local file operation failed")]
    LocalIo,
    /// A file exchange failed without a confirmed publication.
    #[error("the file transfer failed")]
    TransferFailed,
    /// Confirmed-owned temporary material could not be removed.
    #[error("temporary file cleanup could not be confirmed")]
    CleanupIncomplete,
    /// A publication acknowledgement was lost or could not be interpreted.
    #[error("the file publication result is unknown")]
    PublicationUnknown,
    /// Cancellation arrived after the irreversible publication boundary.
    #[error("file publication has started; wait for its result")]
    PublicationStarted,
    /// The item or execution no longer matches the caller's snapshot.
    #[error("this transfer item or execution is no longer current")]
    StaleItem,
}

/// One bounded projection. It contains no native path or open file handle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct SessionTransferItem {
    /// Stable queue item identity.
    pub item_id: String,
    /// Exact execution identity, allocated before dispatch.
    pub execution_id: String,
    /// Authenticated transport selected when this item was added.
    pub transport_id: String,
    /// A bounded display filename, never the local source or destination path.
    pub name: String,
    /// Upload or download.
    pub direction: SessionTransferDirection,
    /// Current state or confirmed terminal result.
    pub state: SessionTransferState,
    /// Decimal text preserves the complete unsigned 64-bit count.
    pub transferred_bytes: String,
    /// Expected total as decimal text, when known.
    pub total_bytes: Option<String>,
    /// Whether this exact execution can accept an explicit cancellation.
    pub can_cancel: bool,
    /// Whether this execution has admitted the handles required for a checkpoint.
    pub can_pause: bool,
    /// Whether explicit continuation can queue this retained checkpoint.
    pub can_resume: bool,
    /// Whether acknowledgement can clear an unresolved publication reminder.
    pub can_acknowledge: bool,
    /// A fixed category for localized interface feedback.
    pub issue: Option<SessionTransferIssue>,
    /// Temporary-file cleanup could not be confirmed.
    pub staging_may_remain: bool,
}

/// A complete on-demand snapshot of one logical session's transfer queue.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct SessionTransferQueueSnapshot {
    /// Logical terminal owning this queue.
    pub session_id: String,
    /// Queue lifetime identity; a replacement owner has a different identity.
    pub queue_id: String,
    /// Monotonic decimal revision fences late snapshot replies.
    pub revision: String,
    /// Maximum outstanding items, including native-picker reservations.
    pub capacity: u32,
    /// Outstanding items and native-picker reservations currently using capacity.
    pub outstanding: u32,
    /// A native selection or replacement confirmation is already open.
    pub picker_busy: bool,
    /// Browsing and remote mutations must wait for queued file work to settle.
    pub blocks_file_operations: bool,
    /// Outstanding rows, including every unacknowledged unknown result.
    pub items: Vec<SessionTransferItem>,
    /// Latest confirmed terminal results, oldest first, limited to 32 rows.
    pub recent: Vec<SessionTransferItem>,
}

/// Native selection either queued a Rust-owned item or was cancelled.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(tag = "status", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SessionTransferEnqueueResult {
    /// Selected resources now belong to the queue independently of this request.
    Queued {
        /// Owning queue lifetime.
        queue_id: String,
        /// Stable transfer identity.
        item_id: String,
        /// Exact execution allocated for this transfer.
        execution_id: String,
    },
    /// The person closed native selection without choosing a file.
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransferIdentity {
    pub item: Uuid,
    pub execution: Uuid,
    pub transport: Uuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SelectionReservation {
    id: Uuid,
    transport: Uuid,
    count: usize,
}

enum NativeInteraction {
    Selection { reservation: SelectionReservation, current: bool },
    Confirmation(TransferIdentity),
}

struct TransferRecord<T> {
    identity: TransferIdentity,
    name: String,
    direction: SessionTransferDirection,
    state: SessionTransferState,
    transferred: u64,
    total: Option<u64>,
    issue: Option<SessionTransferIssue>,
    staging_may_remain: bool,
    publication_started: bool,
    pause_supported: bool,
    resources: Option<T>,
}

impl<T> TransferRecord<T> {
    fn view(&self) -> SessionTransferItem {
        SessionTransferItem {
            item_id: self.identity.item.to_string(),
            execution_id: self.identity.execution.to_string(),
            transport_id: self.identity.transport.to_string(),
            name: self.name.clone(),
            direction: self.direction,
            state: self.state,
            transferred_bytes: self.transferred.to_string(),
            total_bytes: self.total.map(|value| value.to_string()),
            can_cancel: !self.publication_started
                && matches!(
                    self.state,
                    SessionTransferState::Queued
                        | SessionTransferState::AwaitingConfirmation
                        | SessionTransferState::Transferring
                        | SessionTransferState::Finalizing
                        | SessionTransferState::Pausing
                        | SessionTransferState::Paused
                        | SessionTransferState::Validating
                ),
            can_pause: !self.publication_started
                && self.pause_supported
                && self.state == SessionTransferState::Transferring,
            can_resume: self.state == SessionTransferState::Paused,
            can_acknowledge: self.state == SessionTransferState::Unknown,
            issue: self.issue,
            staging_may_remain: self.staging_may_remain,
        }
    }
}

pub(crate) struct DispatchedTransfer<T> {
    pub identity: TransferIdentity,
    pub resources: T,
}

pub(crate) enum CancelTransfer<T> {
    Queued(T),
    Cleanup(TransferIdentity, T),
    Running(TransferIdentity),
    Settled,
}

pub(crate) struct TransferCompletion {
    pub state: SessionTransferState,
    pub issue: Option<SessionTransferIssue>,
    pub staging_may_remain: bool,
}

pub(crate) struct InterruptedTransfers<T> {
    pub selected: Vec<T>,
    pub running: Option<TransferIdentity>,
}

/// Private selected resources move exactly once from the queue to its worker.
pub(crate) struct TransferQueue<T> {
    id: Uuid,
    revision: u64,
    items: VecDeque<TransferRecord<T>>,
    recent: VecDeque<SessionTransferItem>,
    native: Option<NativeInteraction>,
    running: Option<TransferIdentity>,
}

impl<T> Default for TransferQueue<T> {
    fn default() -> Self {
        Self {
            id: Uuid::now_v7(),
            revision: 0,
            items: VecDeque::new(),
            recent: VecDeque::new(),
            native: None,
            running: None,
        }
    }
}

impl<T> TransferQueue<T> {
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn has_pending(&self) -> bool {
        self.items.iter().any(|record| {
            record.state == SessionTransferState::Queued
                || (record.state == SessionTransferState::Cancelling && record.resources.is_some())
        })
    }

    pub fn has_state(&self) -> bool {
        !self.items.is_empty() || !self.recent.is_empty() || self.native.is_some()
    }

    pub fn is_settling(&self) -> bool {
        self.running.is_some()
            || self.items.iter().any(|record| record.state == SessionTransferState::Cancelling)
    }

    pub fn blocks_file_operations(&self) -> bool {
        self.native.is_some()
            || self.items.iter().any(|item| {
                !matches!(item.state, SessionTransferState::Unknown | SessionTransferState::Paused)
            })
    }

    pub fn confirmation_open(&self, identity: TransferIdentity) -> bool {
        matches!(self.native, Some(NativeInteraction::Confirmation(current)) if current == identity)
    }

    fn changed(&mut self) {
        self.revision = self.revision.saturating_add(1);
    }

    fn selection_count(&self) -> usize {
        match self.native {
            Some(NativeInteraction::Selection { reservation, .. }) => reservation.count,
            _ => 0,
        }
    }

    pub fn snapshot(&self, session_id: &str) -> SessionTransferQueueSnapshot {
        SessionTransferQueueSnapshot {
            session_id: session_id.to_owned(),
            queue_id: self.id.to_string(),
            revision: self.revision.to_string(),
            capacity: TRANSFER_CAPACITY as u32,
            outstanding: (self.items.len() + self.selection_count()) as u32,
            picker_busy: self.native.is_some(),
            blocks_file_operations: self.blocks_file_operations(),
            items: self.items.iter().map(TransferRecord::view).collect(),
            recent: self.recent.iter().cloned().collect(),
        }
    }

    pub fn reserve_selection(
        &mut self,
        transport: Uuid,
    ) -> Result<SelectionReservation, SessionTransferIssue> {
        self.reserve_selections(transport, 1)
    }

    pub fn reserve_selections(
        &mut self,
        transport: Uuid,
        count: usize,
    ) -> Result<SelectionReservation, SessionTransferIssue> {
        if count == 0 || count > TRANSFER_CAPACITY {
            return Err(SessionTransferIssue::InvalidSelection);
        }
        if self.items.len() + self.selection_count() + count > TRANSFER_CAPACITY {
            return Err(SessionTransferIssue::QueueFull);
        }
        if self.native.is_some() {
            return Err(SessionTransferIssue::NativeDialogBusy);
        }
        let reservation = SelectionReservation { id: Uuid::now_v7(), transport, count };
        self.native = Some(NativeInteraction::Selection { reservation, current: true });
        self.changed();
        Ok(reservation)
    }

    pub fn release_selection(&mut self, selected: SelectionReservation) {
        if matches!(&self.native, Some(NativeInteraction::Selection { reservation, .. }) if *reservation == selected)
        {
            self.native = None;
            self.changed();
        }
    }

    pub fn enqueue_selected(
        &mut self,
        selected: SelectionReservation,
        name: &str,
        direction: SessionTransferDirection,
        total: Option<u64>,
        resources: T,
    ) -> Result<SessionTransferEnqueueResult, SessionTransferIssue> {
        if selected.count != 1 {
            return Err(SessionTransferIssue::InvalidSelection);
        }
        self.accept_selection(selected)?;
        Ok(self.append_selected(selected.transport, name, direction, total, resources))
    }

    pub fn enqueue_batch(
        &mut self,
        selected: SelectionReservation,
        direction: SessionTransferDirection,
        resources: Vec<(String, u64, T)>,
    ) -> Result<Vec<SessionTransferEnqueueResult>, SessionTransferIssue> {
        if resources.len() != selected.count {
            return Err(SessionTransferIssue::InvalidSelection);
        }
        self.accept_selection(selected)?;
        let mut admitted = Vec::with_capacity(resources.len());
        for (name, total, resource) in resources {
            admitted.push(self.append_selected(
                selected.transport,
                &name,
                direction,
                Some(total),
                resource,
            ));
        }
        Ok(admitted)
    }

    fn accept_selection(
        &mut self,
        selected: SelectionReservation,
    ) -> Result<(), SessionTransferIssue> {
        let current = match &self.native {
            Some(NativeInteraction::Selection { reservation, current })
                if *reservation == selected =>
            {
                *current
            }
            _ => return Err(SessionTransferIssue::StaleItem),
        };
        self.native = None;
        self.changed();
        if !current {
            return Err(SessionTransferIssue::TransportEnded);
        }
        Ok(())
    }

    fn append_selected(
        &mut self,
        transport: Uuid,
        name: &str,
        direction: SessionTransferDirection,
        total: Option<u64>,
        resources: T,
    ) -> SessionTransferEnqueueResult {
        let identity =
            TransferIdentity { item: Uuid::now_v7(), execution: Uuid::now_v7(), transport };
        let name = display_text(name, MAX_NAME_CHARACTERS);
        self.items.push_back(TransferRecord {
            identity,
            name,
            direction,
            state: SessionTransferState::Queued,
            transferred: 0,
            total,
            issue: None,
            staging_may_remain: false,
            publication_started: false,
            pause_supported: direction == SessionTransferDirection::Download,
            resources: Some(resources),
        });
        SessionTransferEnqueueResult::Queued {
            queue_id: self.id.to_string(),
            item_id: identity.item.to_string(),
            execution_id: identity.execution.to_string(),
        }
    }

    pub fn take_next(&mut self, transport: Uuid) -> Option<DispatchedTransfer<T>> {
        if self.running.is_some() {
            return None;
        }
        let record = self.items.iter_mut().find(|record| {
            record.state == SessionTransferState::Queued && record.identity.transport == transport
        })?;
        let resources = record.resources.take()?;
        record.state = if record.transferred > 0 {
            SessionTransferState::Validating
        } else {
            SessionTransferState::Transferring
        };
        let identity = record.identity;
        self.running = Some(identity);
        self.changed();
        Some(DispatchedTransfer { identity, resources })
    }

    fn running_mut(&mut self, identity: TransferIdentity) -> Option<&mut TransferRecord<T>> {
        if self.running != Some(identity) {
            return None;
        }
        self.items.iter_mut().find(|record| record.identity == identity)
    }

    pub fn begin_confirmation(
        &mut self,
        identity: TransferIdentity,
    ) -> Result<(), SessionTransferIssue> {
        let record = self.running_mut(identity).ok_or(SessionTransferIssue::StaleItem)?;
        if record.state == SessionTransferState::Cancelling {
            return Err(SessionTransferIssue::StaleItem);
        }
        if record.publication_started {
            return Err(SessionTransferIssue::PublicationStarted);
        }
        if self.native.is_some() {
            return Err(SessionTransferIssue::NativeDialogBusy);
        }
        self.native = Some(NativeInteraction::Confirmation(identity));
        let record = self.running_mut(identity).expect("running item was checked");
        if record.state != SessionTransferState::Pausing {
            record.state = SessionTransferState::AwaitingConfirmation;
        }
        self.changed();
        Ok(())
    }

    pub fn end_confirmation(&mut self, identity: TransferIdentity) {
        if matches!(self.native, Some(NativeInteraction::Confirmation(current)) if current == identity)
        {
            self.native = None;
            if let Some(record) = self.running_mut(identity)
                && record.state == SessionTransferState::AwaitingConfirmation
            {
                record.state = SessionTransferState::Transferring;
            }
            self.changed();
        }
    }

    pub fn admit_upload_pause(&mut self, identity: TransferIdentity) {
        let Some(record) = self.running_mut(identity) else { return };
        if record.direction == SessionTransferDirection::Upload && !record.pause_supported {
            record.pause_supported = true;
            self.changed();
        }
    }

    pub fn progress(&mut self, identity: TransferIdentity, update: FileTransferProgress) {
        let Some(record) = self.running_mut(identity) else { return };
        if record.state == SessionTransferState::Cancelling
            || record.transferred > update.transferred
            || update.total.is_some_and(|total| update.transferred > total)
            || (record.state == SessionTransferState::Finalizing
                && update.phase == SessionFileTransferPhase::Transferring)
        {
            return;
        }
        record.transferred = update.transferred;
        record.total = update.total;
        record.state = match update.phase {
            SessionFileTransferPhase::Transferring
                if record.state == SessionTransferState::Pausing =>
            {
                SessionTransferState::Pausing
            }
            SessionFileTransferPhase::Transferring => SessionTransferState::Transferring,
            SessionFileTransferPhase::Finalizing => SessionTransferState::Finalizing,
        };
        self.changed();
    }

    pub fn begin_publication(
        &mut self,
        identity: TransferIdentity,
    ) -> Result<(), SessionTransferIssue> {
        let record = self.running_mut(identity).ok_or(SessionTransferIssue::StaleItem)?;
        if record.state == SessionTransferState::Cancelling {
            return Err(SessionTransferIssue::StaleItem);
        }
        record.publication_started = true;
        self.changed();
        Ok(())
    }

    pub fn cancel(
        &mut self,
        queue: Uuid,
        item: Uuid,
        execution: Uuid,
    ) -> Result<CancelTransfer<T>, SessionTransferIssue> {
        if queue != self.id {
            return Err(SessionTransferIssue::StaleItem);
        }
        let Some(index) = self.items.iter().position(|record| {
            record.identity.item == item && record.identity.execution == execution
        }) else {
            return if self.recent.iter().any(|record| {
                record.item_id == item.to_string() && record.execution_id == execution.to_string()
            }) {
                Ok(CancelTransfer::Settled)
            } else {
                Err(SessionTransferIssue::StaleItem)
            };
        };
        let record = &mut self.items[index];
        if record.state == SessionTransferState::Unknown {
            return Err(SessionTransferIssue::PublicationUnknown);
        }
        if record.publication_started {
            return Err(SessionTransferIssue::PublicationStarted);
        }
        if record.state == SessionTransferState::Paused
            || (record.state == SessionTransferState::Queued && record.transferred > 0)
        {
            record.state = SessionTransferState::Cancelling;
            let resources = record.resources.take().expect("paused item owns checkpoint");
            let identity = record.identity;
            self.changed();
            return Ok(CancelTransfer::Cleanup(identity, resources));
        }
        if record.state == SessionTransferState::Queued {
            let mut record = self.items.remove(index).expect("matching item exists");
            record.state = SessionTransferState::Cancelled;
            let resources = record.resources.take().expect("queued item owns selected resources");
            self.remember(record.view());
            self.changed();
            Ok(CancelTransfer::Queued(resources))
        } else {
            record.state = SessionTransferState::Cancelling;
            let identity = record.identity;
            self.changed();
            Ok(CancelTransfer::Running(identity))
        }
    }

    pub fn acknowledge(
        &mut self,
        queue: Uuid,
        item: Uuid,
        execution: Uuid,
    ) -> Result<(), SessionTransferIssue> {
        if queue != self.id {
            return Err(SessionTransferIssue::StaleItem);
        }
        let index = self
            .items
            .iter()
            .position(|record| {
                record.identity.item == item
                    && record.identity.execution == execution
                    && record.state == SessionTransferState::Unknown
            })
            .ok_or(SessionTransferIssue::StaleItem)?;
        self.items.remove(index);
        self.changed();
        Ok(())
    }

    pub fn finish(&mut self, identity: TransferIdentity, completion: TransferCompletion) -> bool {
        if self.running != Some(identity)
            || !matches!(
                completion.state,
                SessionTransferState::Saved
                    | SessionTransferState::Cancelled
                    | SessionTransferState::Conflict
                    | SessionTransferState::Failed
                    | SessionTransferState::Interrupted
                    | SessionTransferState::Unknown
            )
        {
            return false;
        }
        let Some(index) = self.items.iter().position(|record| record.identity == identity) else {
            return false;
        };
        self.running = None;
        let record = &mut self.items[index];
        record.state = completion.state;
        record.issue = completion.issue;
        record.staging_may_remain = completion.staging_may_remain;
        if completion.state != SessionTransferState::Unknown {
            let record = self.items.remove(index).expect("matching item exists");
            self.remember(record.view());
        }
        self.changed();
        true
    }

    pub fn interrupt_transport(&mut self, transport: Uuid) -> InterruptedTransfers<T> {
        if let Some(NativeInteraction::Selection { reservation, current }) = &mut self.native
            && reservation.transport == transport
        {
            // The OS dialog may still be open; its actual completion releases the permit.
            *current = false;
        }
        let mut selected = Vec::new();
        let mut index = 0;
        while index < self.items.len() {
            let record = &self.items[index];
            if record.identity.transport == transport
                && (record.state == SessionTransferState::Paused
                    || (record.state == SessionTransferState::Queued && record.transferred > 0))
            {
                let record = &mut self.items[index];
                record.state = SessionTransferState::Cancelling;
                record.issue = Some(SessionTransferIssue::TransportEnded);
                index += 1;
                continue;
            }
            if record.identity.transport == transport
                && record.state == SessionTransferState::Queued
            {
                let mut record = self.items.remove(index).expect("matching item exists");
                record.state = SessionTransferState::Interrupted;
                record.issue = Some(SessionTransferIssue::TransportEnded);
                selected
                    .push(record.resources.take().expect("queued item owns selected resources"));
                self.remember(record.view());
            } else {
                index += 1;
            }
        }
        let running = self.running.filter(|identity| identity.transport == transport);
        if let Some(identity) = running
            && let Some(record) = self.running_mut(identity)
        {
            record.issue = Some(SessionTransferIssue::TransportEnded);
            if !record.publication_started {
                record.state = SessionTransferState::Cancelling;
            }
        }
        self.changed();
        InterruptedTransfers { selected, running }
    }

    fn remember(&mut self, mut view: SessionTransferItem) {
        view.can_cancel = false;
        view.can_pause = false;
        view.can_resume = false;
        view.can_acknowledge = false;
        if self.recent.len() == TRANSFER_HISTORY {
            self.recent.pop_front();
        }
        self.recent.push_back(view);
    }

    pub fn pause(
        &mut self,
        queue: Uuid,
        item: Uuid,
        execution: Uuid,
    ) -> Result<TransferIdentity, SessionTransferIssue> {
        if queue != self.id {
            return Err(SessionTransferIssue::StaleItem);
        }
        let record = self
            .items
            .iter_mut()
            .find(|record| record.identity.item == item && record.identity.execution == execution)
            .ok_or(SessionTransferIssue::StaleItem)?;
        if record.publication_started {
            return Err(SessionTransferIssue::PublicationStarted);
        }
        if record.state == SessionTransferState::Pausing {
            return Ok(record.identity);
        }
        if !record.view().can_pause {
            return Err(SessionTransferIssue::StaleItem);
        }
        record.state = SessionTransferState::Pausing;
        let identity = record.identity;
        self.changed();
        Ok(identity)
    }

    pub fn is_pausing(&self, identity: TransferIdentity) -> bool {
        self.items.iter().any(|record| {
            record.identity == identity && record.state == SessionTransferState::Pausing
        })
    }

    pub fn retain_paused(&mut self, identity: TransferIdentity, resources: T) -> Result<(), T> {
        let Some(record) = self.running_mut(identity) else { return Err(resources) };
        if record.state != SessionTransferState::Pausing {
            return Err(resources);
        }
        record.resources = Some(resources);
        record.state = SessionTransferState::Paused;
        self.running = None;
        self.changed();
        Ok(())
    }

    pub fn resume(
        &mut self,
        queue: Uuid,
        item: Uuid,
        execution: Uuid,
        transport: Uuid,
    ) -> Result<(), SessionTransferIssue> {
        if queue != self.id {
            return Err(SessionTransferIssue::StaleItem);
        }
        let index = self
            .items
            .iter()
            .position(|record| {
                record.identity.item == item
                    && record.identity.execution == execution
                    && record.state == SessionTransferState::Paused
            })
            .ok_or(SessionTransferIssue::StaleItem)?;
        if self.items[index].identity.transport != transport {
            return Err(SessionTransferIssue::TransportEnded);
        }
        let mut record = self.items.remove(index).expect("paused item exists");
        record.identity.execution = Uuid::now_v7();
        record.state = SessionTransferState::Queued;
        self.items.push_back(record);
        self.changed();
        Ok(())
    }

    pub fn finish_cleanup(&mut self, identity: TransferIdentity, completion: TransferCompletion) {
        let Some(index) = self.items.iter().position(|record| {
            record.identity == identity
                && record.state == SessionTransferState::Cancelling
                && record.resources.is_none()
        }) else {
            return;
        };
        let mut record = self.items.remove(index).expect("settling item exists");
        record.state = completion.state;
        record.issue = completion.issue;
        record.staging_may_remain = completion.staging_may_remain;
        self.remember(record.view());
        self.changed();
    }

    pub fn take_cleanup(&mut self) -> Option<(DispatchedTransfer<T>, bool)> {
        let record = self.items.iter_mut().find(|record| {
            record.state == SessionTransferState::Cancelling && record.resources.is_some()
        })?;
        let resources = record.resources.take()?;
        Some((
            DispatchedTransfer { identity: record.identity, resources },
            record.issue == Some(SessionTransferIssue::TransportEnded),
        ))
    }
}

#[cfg(test)]
mod tests;
