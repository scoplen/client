// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::session_directory_sync::{
    SessionDirectorySyncPhase as Phase, SessionDirectorySyncProgress as Progress,
};
use std::pin::Pin;

pub(crate) type Confirmation = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<bool, SessionTransferIssue>> + Send>>
        + Send
        + Sync,
>;

pub(crate) struct Callbacks {
    pub progress: Arc<dyn Fn(u64, u64, Progress) + Send + Sync>,
    pub authorize: Arc<dyn Fn() -> Result<(), FileAccessError> + Send + Sync>,
    pub settled: Arc<dyn Fn() + Send + Sync>,
    pub confirm: Confirmation,
    pub state: Arc<UploadState>,
}

pub(crate) struct ExecutionResult {
    pub issue: Option<Issue>,
    pub staging_may_remain: bool,
}

pub(crate) fn initial_progress(plan: &ComparedDirectory) -> Progress {
    Progress {
        phase: Phase::Copying,
        files_total: plan.summary.files_create + plan.summary.files_changed,
        directories_total: plan.summary.directories_create,
        files_created: 0,
        files_updated: 0,
        files_skipped: plan.summary.files_same,
        directories_created: 0,
        current_name: None,
        failed_name: None,
        issue: None,
    }
}

struct Reporter {
    callbacks: Callbacks,
    progress: Progress,
    total: u64,
    completed: u64,
    transferred: u64,
}
impl Reporter {
    fn emit(&self) {
        (self.callbacks.progress)(self.transferred, self.total, self.progress.clone());
    }
    fn child(&mut self, update: FileTransferProgress) {
        self.transferred = self.completed.saturating_add(update.transferred);
        self.progress.phase = match update.phase {
            SessionFileTransferPhase::Transferring => Phase::Copying,
            SessionFileTransferPhase::Finalizing => Phase::Finalizing,
        };
        self.emit();
    }
}
fn check_cancel(control: &watch::Receiver<TransferControl>) -> Result<(), Issue> {
    if *control.borrow() == TransferControl::Cancel { Err(Issue::Cancelled) } else { Ok(()) }
}
async fn confirm(
    reporter: &Reporter,
    name: String,
    control: &mut watch::Receiver<TransferControl>,
) -> Result<(), Issue> {
    check_cancel(control)?;
    let accepted = tokio::select! { biased;
        _ = control.changed() => return Err(Issue::Cancelled),
        result = (reporter.callbacks.confirm)(name) => result.map_err(Issue::from)?,
    };
    check_cancel(control)?;
    if accepted { Ok(()) } else { Err(Issue::Cancelled) }
}

async fn execute(
    connection: &SshConnection,
    plan: &ComparedDirectory,
    control: &mut watch::Receiver<TransferControl>,
    reporter: &mut Reporter,
) -> Result<(), (Issue, bool)> {
    let mut remote = remote_session(connection, &plan.remote_root).await.map_err(|e| (e, false))?;
    for (index, row) in plan.rows.iter().enumerate() {
        if matches!(
            row.change,
            RowChange::Directory { create: false } | RowChange::File { change: Change::Same, .. }
        ) {
            continue;
        }
        reporter.progress.current_name = Some(plan.tree.display(index));
        check_cancel(control).map_err(|e| (e, false))?;
        reporter.progress.phase = Phase::Copying;
        reporter.emit();
        check_row(connection, &mut remote, plan, index).await.map_err(|e| (e, false))?;
        let local_path = plan.tree.local_path(&plan.local_root, index);
        let remote_path =
            plan.tree.remote_path(&plan.remote_root, index).map_err(|e| (e.into(), false))?;
        match row.change {
            RowChange::Directory { create: true } => {
                let authorize = reporter.callbacks.authorize.clone();
                let settled = reporter.callbacks.settled.clone();
                match plan.direction {
                    SessionTransferDirection::Upload => {
                        directory_copy::create_remote(
                            connection,
                            remote_path,
                            authorize,
                            settled,
                            None,
                        )
                        .await
                    }
                    SessionTransferDirection::Download => {
                        directory_copy::create_local(local_path, authorize, settled, None).await
                    }
                }
                .map_err(|e| (e.into(), false))?;
                reporter.progress.directories_created += 1;
            }
            RowChange::File { change, size, .. } => {
                if change == Change::Changed {
                    confirm(reporter, plan.tree.display(index), control)
                        .await
                        .map_err(|e| (e, false))?;
                }
                check_cancel(control).map_err(|e| (e, false))?;
                check_row(connection, &mut remote, plan, index).await.map_err(|e| (e, false))?;
                reporter.callbacks.state.staging_may_remain.store(true, Ordering::SeqCst);
                match plan.direction {
                    SessionTransferDirection::Upload => {
                        let source = open_reviewed_source(
                            &local_path,
                            row.local.as_ref().ok_or((Issue::FileChanged, false))?,
                            size,
                        )
                        .await
                        .map_err(|e| (e, false))?;
                        let preflight = preflight_upload(connection, &remote_path)
                            .await
                            .map_err(|e| (e.into(), false))?;
                        if match (&preflight.target_attributes, &row.remote) {
                            (None, None) => false,
                            (Some(a), Some(b)) => !stable_attributes(a, b),
                            _ => true,
                        } {
                            return Err((Issue::FileChanged, false));
                        }
                        if preflight.target_attributes.is_some() && !preflight.replacement_supported
                        {
                            return Err((Issue::UnsupportedEntry, false));
                        }
                        let directory =
                            remote_path.rsplitn(2, |b| *b == b'/').nth(1).unwrap_or(b"/").to_vec();
                        let callbacks_authorize = reporter.callbacks.authorize.clone();
                        let execution = transfer_upload(
                            connection,
                            UploadInput::New {
                                source: Box::new(source),
                                directory,
                                target: remote_path,
                                preflight,
                            },
                            control.clone(),
                            Arc::new(UploadState::default()),
                            |update| reporter.child(update),
                            || {},
                            move || callbacks_authorize(),
                        )
                        .await;
                        match execution {
                            UploadExecution::Published => (reporter.callbacks.settled)(),
                            UploadExecution::Failed { error, staging_may_remain } => {
                                let issue = Issue::from(error);
                                if issue != Issue::PublicationUnknown {
                                    (reporter.callbacks.settled)();
                                }
                                return Err((issue, staging_may_remain));
                            }
                            UploadExecution::Paused(checkpoint) => {
                                return Err((Issue::Failed, !checkpoint.discard().await));
                            }
                        }
                    }
                    SessionTransferDirection::Download => {
                        let destination = DownloadDestination::capture(local_path)
                            .await
                            .map_err(|e| (e.into(), false))?;
                        let prepared = prepare_download(
                            connection,
                            DownloadInput::New { remote_path, destination, text_only: false },
                        )
                        .await
                        .map_err(|e| (e.into(), false))?;
                        if let downloads::DownloadPreparation::New { attributes, .. } = &prepared
                            && row
                                .remote
                                .as_ref()
                                .is_none_or(|before| !stable_attributes(before, attributes))
                        {
                            return Err((Issue::FileChanged, false));
                        }
                        check_row(connection, &mut remote, plan, index)
                            .await
                            .map_err(|e| (e, false))?;
                        match continue_download(prepared, control.clone(), |update| {
                            reporter.child(update)
                        })
                        .await
                        {
                            DownloadExecution::Ready { prepared, destination } => {
                                directory_copy::publish_local(
                                    prepared,
                                    destination,
                                    reporter.callbacks.authorize.clone(),
                                    reporter.callbacks.settled.clone(),
                                )
                                .await
                                .map_err(|(e, remains)| (e.into(), remains))?;
                            }
                            DownloadExecution::Failed { error, staging_may_remain } => {
                                return Err((error.into(), staging_may_remain));
                            }
                            DownloadExecution::Paused(checkpoint) => {
                                return Err((Issue::Failed, !checkpoint.discard().await));
                            }
                            DownloadExecution::Published { .. } => {
                                return Err((Issue::Failed, true));
                            }
                        }
                    }
                }
                reporter.callbacks.state.staging_may_remain.store(false, Ordering::SeqCst);
                reporter.completed += size;
                reporter.transferred = reporter.completed;
                if change == Change::Create {
                    reporter.progress.files_created += 1;
                } else {
                    reporter.progress.files_updated += 1;
                }
                reporter.progress.phase = Phase::Copying;
            }
            _ => unreachable!("nonmutating rows were skipped"),
        }
        reporter.emit();
    }
    Ok(())
}

pub(crate) async fn synchronize(
    connection: &SshConnection,
    plan: ComparedDirectory,
    mut control: watch::Receiver<TransferControl>,
    callbacks: Callbacks,
) -> ExecutionResult {
    let mut reporter = Reporter {
        progress: initial_progress(&plan),
        total: plan.summary.transfer_size_bytes.parse().expect("computed unsigned size"),
        completed: 0,
        transferred: 0,
        callbacks,
    };
    reporter.emit();
    let result = execute(connection, &plan, &mut control, &mut reporter).await;
    let (issue, staging_may_remain) = match result {
        Ok(()) => (None, false),
        Err((issue, remains)) => (Some(issue), remains),
    };
    if issue.is_some() {
        reporter.progress.failed_name = reporter.progress.current_name.clone();
    }
    reporter.progress.issue = issue;
    reporter.callbacks.state.staging_may_remain.store(staging_may_remain, Ordering::SeqCst);
    reporter.emit();
    ExecutionResult { issue, staging_may_remain }
}
