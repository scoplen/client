// SPDX-License-Identifier: Apache-2.0
//! One retained public native consumer across externally authored Team view changes.

use std::{collections::BTreeMap, io::Write as _, sync::Mutex as OutputMutex};

use scoplen_api::inventory::{InventoryFields, InventoryType};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc;

use crate::{
    connection::{
        SessionTarget,
        preparation::{PreparationEvent, PreparationResponse},
    },
    personal_server::{TeamAssetsPhase, TeamSnippetFields, TeamSshSource},
    session_manager::{SessionEvent, SessionManager},
    snippets::{
        SnippetIssue, SnippetVariableKind, SnippetView, Snippets,
        team::{PreparedTeamSnippet, SnippetTerminal, TeamSnippetLibrary, TeamSnippetSendOutcome},
    },
};

use super::*;

const PHASES: [&str; 6] =
    ["published", "replaced", "view-withdrawn", "restored", "membership-withdrawn", "deleted"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    disposable: bool,
    phase: String,
    origin: String,
    ca_certificate: PathBuf,
    member_username: String,
    member_password_file: PathBuf,
    organization_id: String,
    host_id: String,
    profile_id: String,
    snippet_id: String,
    secret_snippet_id: String,
    writer_family_id: String,
    fields: serde_json::Value,
    secret_fields: serde_json::Value,
    inputs: BTreeMap<String, String>,
    output_marker: String,
}

impl Descriptor {
    fn validate(&self, phase: &str) {
        assert!(self.disposable);
        assert_eq!(self.phase, phase);
        assert!(self.ca_certificate.is_absolute() && self.member_password_file.is_absolute());
        assert!(
            self.origin
                .strip_prefix("https://localhost:")
                .and_then(|port| port.parse::<u16>().ok())
                .is_some_and(|port| port != 0)
        );
        for id in [
            &self.organization_id,
            &self.host_id,
            &self.profile_id,
            &self.snippet_id,
            &self.secret_snippet_id,
            &self.writer_family_id,
        ] {
            let parsed = uuid::Uuid::parse_str(id).expect("canonical fixture UUIDv7");
            assert_eq!(parsed.get_version_num(), 7);
            assert_eq!(parsed.to_string(), *id);
        }
        assert_ne!(self.snippet_id, self.secret_snippet_id);
        assert_eq!(self.inputs.len(), 3);
        assert_eq!(self.inputs.get("message").map(String::as_str), Some("native value"));
        assert_eq!(self.inputs.get("count").map(String::as_str), Some("42"));
        assert_eq!(self.inputs.get("color").map(String::as_str), Some("green"));
        assert!(self.output_marker.len() >= 16 && self.output_marker.len() <= 128);
        assert!(self.output_marker.bytes().all(|byte| byte.is_ascii_graphic()));
        let ordinary = self.definition(false);
        let variables = ordinary.variables.as_ref().expect("three typed variables");
        assert_eq!(variables.len(), 3);
        assert_eq!(variables["message"].kind, 1);
        assert_eq!(variables["count"].kind, 2);
        assert_eq!(variables["color"].kind, 3);
        let secret = self.definition(true);
        let variables = secret.variables.as_ref().expect("one Secret definition");
        assert_eq!(variables.len(), 1);
        assert!(variables.values().all(|variable| {
            variable.kind == 4 && variable.default.is_none() && variable.choices.is_none()
        }));
    }

    fn definition(&self, secret: bool) -> TeamSnippetFields {
        let json = serde_json::to_vec(if secret { &self.secret_fields } else { &self.fields })
            .expect("ordinary fixture fields");
        let fields = InventoryFields::from_json(InventoryType::Snippet, &json)
            .expect("published shared InventoryFields contract");
        serde_json::from_slice(&fields.to_json().expect("canonical shared fields"))
            .expect("native named Snippet fields")
    }

    fn same_owner(&self, original: &Self) {
        assert!(
            self.origin == original.origin
                && self.ca_certificate == original.ca_certificate
                && self.member_username == original.member_username
                && self.member_password_file == original.member_password_file
                && self.organization_id == original.organization_id
                && self.host_id == original.host_id
                && self.profile_id == original.profile_id
                && self.snippet_id == original.snippet_id
                && self.secret_snippet_id == original.secret_snippet_id
                && self.writer_family_id == original.writer_family_id
                && self.secret_fields == original.secret_fields
                && self.inputs == original.inputs
                && self.output_marker == original.output_marker,
            "the finite handoff must retain its original public owners"
        );
    }
}

struct Terminal {
    id: &'static str,
    events: mpsc::UnboundedReceiver<SessionEvent>,
    output: Arc<OutputMutex<Vec<u8>>>,
    task: tokio::task::JoinHandle<Result<(), String>>,
}

impl Terminal {
    fn start(
        sessions: SessionManager,
        personal: Arc<PersonalServer>,
        store: Arc<Store>,
        id: &'static str,
        source: TeamSshSource,
        host_id: String,
        profile_id: String,
    ) -> Self {
        sessions.reserve(id, true).expect("reserve an ordinary terminal");
        let (sender, events) = mpsc::unbounded_channel();
        let output = Arc::new(OutputMutex::new(Vec::<u8>::new()));
        let captured = output.clone();
        let task = tokio::spawn(async move {
            let target = SessionTarget::Organization { source: source.clone(), profile_id };
            sessions
                .run_target(
                    id,
                    &target,
                    &personal,
                    None,
                    true,
                    store,
                    |event| {
                        if matches!(
                            &event,
                            SessionEvent::Starting { automatic: true, .. }
                                | SessionEvent::Retrying { .. }
                                | SessionEvent::Failed { .. }
                        ) {
                            return Err("Team Snippet fixture must not reconnect or retry".into());
                        }
                        if let SessionEvent::Preparation { event, .. } = &event
                            && let PreparationEvent::Trust { context, .. }
                            | PreparationEvent::Verified { context, .. } = event.as_ref()
                        {
                            assert_eq!(context.source.as_ref(), Some(&source));
                            assert_eq!(context.host_id, host_id);
                            assert_eq!(context.profile_id, target.profile_id());
                        }
                        sender.send(event).map_err(|_| "fixture event receiver closed".into())
                    },
                    |_, bytes| {
                        let mut output = captured.lock().unwrap();
                        if output.len() + bytes.len() > 65_536 {
                            return Err("Team Snippet fixture output exceeded its bound".into());
                        }
                        output.extend_from_slice(&bytes);
                        Ok(())
                    },
                    |_, _| {},
                )
                .await
        });
        Self { id, events, output, task }
    }

    async fn ready(&mut self, sessions: &SessionManager) -> SnippetTerminal {
        let transport_id = tokio::time::timeout(Duration::from_secs(30), async {
            while let Some(event) = self.events.recv().await {
                match event {
                    SessionEvent::Ready { transport_id } => return transport_id,
                    SessionEvent::Preparation { transport_id, event } => match *event {
                        PreparationEvent::Trust { prompt_id, .. } => sessions
                            .respond(
                                self.id,
                                &transport_id,
                                &prompt_id,
                                PreparationResponse::AcceptHostKey,
                            )
                            .expect("explicit fixture Host trust"),
                        PreparationEvent::Progress { .. } | PreparationEvent::Verified { .. } => {}
                        _ => panic!("certificate fixture requested unexpected authentication"),
                    },
                    SessionEvent::Starting { automatic: false, .. }
                    | SessionEvent::Forwards { .. } => {}
                    _ => panic!("fixture terminal ended before becoming ready"),
                }
            }
            panic!("fixture event stream ended before readiness")
        })
        .await
        .expect("real Team SSH readiness deadline");
        SnippetTerminal { session_id: self.id.into(), transport_id }
    }

    fn count(&self, marker: &str) -> usize {
        self.output
            .lock()
            .unwrap()
            .split_inclusive(|byte| *byte == b'\n')
            .filter_map(|line| line.strip_suffix(b"\n"))
            .filter(|line| line.strip_suffix(b"\r").unwrap_or(line) == marker.as_bytes())
            .count()
    }

    async fn barrier(&self, sessions: &SessionManager, target: &SnippetTerminal) {
        let suffix = uuid::Uuid::now_v7();
        let marker = format!("SCOPLEN-D156-BARRIER:{suffix}");
        let command = format!("printf '\\123COPLEN-D156-BARRIER:{suffix}\\n'\r");
        sessions
            .input(&target.session_id, &target.transport_id, command.into_bytes())
            .expect("independent ordinary output barrier");
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.count(&marker) == 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("actual SSH output barrier deadline");
        assert_eq!(self.count(&marker), 1);
    }

    async fn close(self, sessions: &SessionManager) {
        sessions.close(self.id).expect("close only the fixture terminal");
        tokio::time::timeout(Duration::from_secs(10), self.task)
            .await
            .expect("fixture SSH close deadline")
            .expect("fixture terminal task")
            .expect("ordinary terminal shutdown");
    }
}

#[derive(Serialize)]
struct TargetCheckpoint {
    session_id: String,
    transport_id: String,
    outcome: TeamSnippetSendOutcome,
    marker_count: usize,
}

#[derive(Serialize)]
struct Checkpoint<'a> {
    phase: &'a str,
    descriptor_sha256: &'a str,
    source: &'a TeamSshSource,
    ack_revision: Option<&'a str>,
    ack_cursor: Option<&'a str>,
    snippet_id: &'a str,
    command_sha256: String,
    origin: &'a SnippetTerminal,
    targets: Vec<TargetCheckpoint>,
    old_preparation_refused: bool,
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

async fn wait_file(path: &Path, limit: u64) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(300), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        bounded_file(path, limit)
    })
    .await
    .expect("finite external acceptance handoff deadline")
}

async fn descriptor(directory: &Path, phase: &str) -> (Descriptor, String) {
    let stem = directory.join(format!("snippet-client-{phase}"));
    let _ready = wait_file(&stem.with_extension("ready"), 64).await;
    let bytes = bounded_file(&stem.with_extension("json"), 8192);
    let digest = hash(&bytes);
    let value: Descriptor = serde_json::from_slice(&bytes).expect("strict finite phase descriptor");
    value.validate(phase);
    (value, digest)
}

fn publish_checkpoint(directory: &Path, checkpoint: &Checkpoint<'_>) {
    let bytes = serde_json::to_vec(checkpoint).expect("nonsecret native checkpoint");
    assert!(bytes.len() <= 8192);
    let path = directory.join(format!("snippet-native-{}.json", checkpoint.phase));
    let temporary = path.with_extension("pending");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .expect("absent-only checkpoint staging");
    file.write_all(&bytes).expect("bounded checkpoint write");
    file.sync_all().expect("closed checkpoint publication");
    drop(file);
    std::fs::hard_link(&temporary, &path).expect("atomic absent-only checkpoint publication");
    std::fs::remove_file(&temporary).expect("remove owned checkpoint staging");
}

fn compare_definition(view: &SnippetView, expected: &TeamSnippetFields) {
    assert_eq!(view.name, expected.name);
    assert_eq!(view.template, expected.template);
    assert_eq!(view.folder, expected.folder);
    let tags: Vec<_> = expected
        .tags
        .as_ref()
        .into_iter()
        .flat_map(|tags| tags.iter().filter(|(_, present)| **present).map(|(tag, _)| tag.clone()))
        .collect();
    assert_eq!(view.tags, tags);
    let expected = expected.variables.as_ref().expect("fixture variable definitions");
    assert_eq!(view.variables.len(), expected.len());
    for variable in &view.variables {
        let expected = &expected[&variable.name];
        let kind = match expected.kind {
            1 => SnippetVariableKind::Text,
            2 => SnippetVariableKind::Integer,
            3 => SnippetVariableKind::Choice,
            4 => SnippetVariableKind::Secret,
            _ => panic!("fixture kind outside the frozen contract"),
        };
        assert_eq!(variable.kind, kind);
        assert_eq!(variable.default, expected.default);
        assert_eq!(variable.choices, expected.choices.clone().unwrap_or_default());
        assert_eq!(variable.has_default, expected.default.is_some());
    }
}

fn review(
    sessions: &SessionManager,
    store: &Arc<Store>,
    origin: &SnippetTerminal,
    targets: &[SnippetTerminal],
    descriptor: &Descriptor,
) -> (TeamSnippetLibrary, PreparedTeamSnippet) {
    let library = sessions.team_snippets(store, origin).expect("public current Team library");
    assert_eq!(library.phase, TeamAssetsPhase::Ready);
    assert!(library.acknowledged);
    let fence = library.fence.clone().expect("complete confirmed view fence");
    assert_eq!(library.snippets.len(), 2);
    let executable = library
        .snippets
        .iter()
        .find(|snippet| snippet.id == descriptor.snippet_id)
        .expect("same authored executable Snippet id");
    compare_definition(executable, &descriptor.definition(false));
    assert!(!executable.read_only && executable.issue.is_none());
    let secret = library
        .snippets
        .iter()
        .find(|snippet| snippet.id == descriptor.secret_snippet_id)
        .expect("separate authored Secret Snippet");
    compare_definition(secret, &descriptor.definition(true));
    assert!(secret.read_only);
    assert_eq!(secret.issue, Some(SnippetIssue::SecretUnsupported));
    assert_eq!(
        sessions.prepare_team_snippet(
            store,
            origin.clone(),
            fence.clone(),
            &descriptor.secret_snippet_id,
            BTreeMap::new(),
            targets.to_vec(),
        ),
        Err(SnippetIssue::SecretUnsupported)
    );
    assert!(Snippets::new(store.clone()).list().unwrap().is_empty());
    assert_eq!(
        Snippets::new(store.clone()).prepare(&descriptor.snippet_id, descriptor.inputs.clone()),
        Err(SnippetIssue::NotFound),
        "Organization objects must not leak into Personal Snippet storage"
    );
    let prepared = sessions
        .prepare_team_snippet(
            store,
            origin.clone(),
            fence,
            &descriptor.snippet_id,
            descriptor.inputs.clone(),
            targets.to_vec(),
        )
        .expect("explicit review of current typed fields and ordered existing terminals");
    let mut expected = descriptor.definition(false).template;
    for (name, value) in &descriptor.inputs {
        expected = expected.replace(&format!("{{{{{name}}}}}"), value);
    }
    assert_eq!(prepared.snippet.command, expected);
    assert!(
        !prepared.snippet.command.contains(&descriptor.output_marker),
        "the real output marker must be absent from echoed input"
    );
    (library, prepared)
}

async fn roundtrip(directory: &Path) {
    let (initial, initial_hash) = descriptor(directory, PHASES[0]).await;
    let artifact = std::env::var_os("SCOPLEN_LIVE_TEAM_SSH_FIXTURE")
        .expect("provide the owned OpenSSH fixture descriptor");
    let ssh: team_ssh::SshFixture =
        serde_json::from_slice(&bounded_file(Path::new(&artifact), 8192)).unwrap();
    ssh.verify().await;
    let ca = bounded_file(&initial.ca_certificate, 65_536);
    let local = OwnedDirectory::new();
    let device = Device::new(local.path());
    let personal = Arc::new(manager(&ca));
    let lease = sign_in(
        &device,
        &personal,
        &initial.origin,
        &initial.member_username,
        SecretVec::new(bounded_file(&initial.member_password_file, 4096)),
    )
    .await;
    let store = device.store(&lease);
    let visible = personal
        .refresh_team_assets(store.clone(), &initial.organization_id)
        .await
        .expect("public native complete initial view and confirmed ACK");
    assert_eq!(visible.phase, TeamAssetsPhase::Ready);
    assert!(visible.acknowledged);
    assert_eq!(visible.origin, initial.origin);
    assert_eq!(visible.organization_id, initial.organization_id);
    assert_eq!(visible.account_id, lease.account().unwrap().account_id.to_string());
    assert_eq!(visible.device_id, lease.account().unwrap().device_id.to_string());
    assert!(visible.assets.iter().any(|asset| asset.id == initial.host_id));
    assert!(visible.assets.iter().any(|asset| asset.id == initial.profile_id));
    let source = TeamSshSource {
        origin: visible.origin,
        account_id: visible.account_id,
        device_id: visible.device_id,
        organization_id: visible.organization_id,
    };
    let sessions = SessionManager::default();
    let mut terminals = Vec::new();
    let mut targets = Vec::new();
    for id in ["snippet-origin", "snippet-replaced", "snippet-peer"] {
        let mut terminal = Terminal::start(
            sessions.clone(),
            personal.clone(),
            store.clone(),
            id,
            source.clone(),
            initial.host_id.clone(),
            initial.profile_id.clone(),
        );
        targets.push(terminal.ready(&sessions).await);
        terminals.push(terminal);
    }
    let origin = targets[0].clone();
    let mut captured = Vec::<PreparedTeamSnippet>::new();
    let mut last_command_hash = String::new();
    for (ordinal, phase) in PHASES.into_iter().enumerate() {
        let (current, descriptor_hash) = if ordinal == 0 {
            // Reread only the closed descriptor; its hash and owners must be stable.
            let (current, digest) = descriptor(directory, phase).await;
            assert_eq!(digest, initial_hash);
            (current, digest)
        } else {
            descriptor(directory, phase).await
        };
        current.same_owner(&initial);
        let before_counts: Vec<_> =
            terminals.iter().map(|terminal| terminal.count(&current.output_marker)).collect();
        if ordinal > 0 {
            let refreshed =
                personal.refresh_team_assets(store.clone(), &current.organization_id).await;
            if matches!(phase, "membership-withdrawn" | "deleted") {
                assert!(refreshed.is_err());
            } else {
                let refreshed = refreshed.expect("reconcile the externally changed public view");
                assert_eq!(refreshed.phase, TeamAssetsPhase::Ready);
                assert!(refreshed.acknowledged);
            }
        }
        let mut old_refused = false;
        if !captured.is_empty() {
            for old in &captured {
                for index in 0..old.targets.len() {
                    assert_eq!(
                        sessions.send_team_snippet(&store, old, index).unwrap(),
                        TeamSnippetSendOutcome::Invalidated,
                        "old captured preparation must be refused after reconciliation"
                    );
                }
            }
            old_refused = true;
        }
        let mut checkpoints = Vec::new();
        let library = if matches!(phase, "published" | "replaced" | "restored") {
            let (library, prepared) = review(&sessions, &store, &origin, &targets, &current);
            if phase == "published" {
                let old = terminals.remove(1);
                old.close(&sessions).await;
                let mut replacement = Terminal::start(
                    sessions.clone(),
                    personal.clone(),
                    store.clone(),
                    "snippet-replaced",
                    source.clone(),
                    initial.host_id.clone(),
                    initial.profile_id.clone(),
                );
                let fresh = replacement.ready(&sessions).await;
                assert_ne!(fresh.transport_id, targets[1].transport_id);
                targets[1] = fresh;
                terminals.insert(1, replacement);
            }
            for (index, target) in prepared.targets.iter().enumerate() {
                let outcome = sessions.send_team_snippet(&store, &prepared, index).unwrap();
                let expected = if phase == "published" && index == 1 {
                    TeamSnippetSendOutcome::NotSent
                } else {
                    TeamSnippetSendOutcome::Sent
                };
                assert_eq!(outcome, expected);
                terminals[index].barrier(&sessions, &targets[index]).await;
                let count = terminals[index].count(&current.output_marker) - before_counts[index];
                assert_eq!(count, usize::from(expected == TeamSnippetSendOutcome::Sent));
                checkpoints.push(TargetCheckpoint {
                    session_id: target.session_id.clone(),
                    transport_id: target.transport_id.clone(),
                    outcome,
                    marker_count: count,
                });
            }
            last_command_hash = hash(prepared.snippet.command.as_bytes());
            captured.push(prepared);
            library
        } else {
            let library = sessions.team_snippets(&store, &origin).unwrap();
            assert!(library.snippets.is_empty());
            if phase == "view-withdrawn" {
                assert_eq!(library.phase, TeamAssetsPhase::Ready);
                assert!(library.acknowledged && library.fence.is_some());
            } else {
                assert_ne!(library.phase, TeamAssetsPhase::Ready);
                assert!(library.fence.is_none());
            }
            for (index, target) in targets.iter().enumerate() {
                terminals[index].barrier(&sessions, target).await;
                let count = terminals[index].count(&current.output_marker) - before_counts[index];
                assert_eq!(count, 0, "withdrawal must not replay any captured command");
                checkpoints.push(TargetCheckpoint {
                    session_id: target.session_id.clone(),
                    transport_id: target.transport_id.clone(),
                    outcome: TeamSnippetSendOutcome::Invalidated,
                    marker_count: count,
                });
            }
            library
        };
        publish_checkpoint(
            directory,
            &Checkpoint {
                phase,
                descriptor_sha256: &descriptor_hash,
                source: &source,
                ack_revision: library.fence.as_ref().map(|fence| fence.revision.as_str()),
                ack_cursor: library.fence.as_ref().map(|fence| fence.cursor.as_str()),
                snippet_id: &current.snippet_id,
                command_sha256: last_command_hash.clone(),
                origin: &origin,
                targets: checkpoints,
                old_preparation_refused: old_refused,
            },
        );
        let complete = directory.join(format!("snippet-client-{phase}.complete"));
        assert_eq!(wait_file(&complete, 64).await, b"passed\n");
    }
    for terminal in terminals {
        terminal.close(&sessions).await;
    }
    drop(store);
    drop(lease);
    drop(device);
    local.close();
}

#[tokio::test]
async fn live_native_current_team_snippets() {
    let directory = std::env::var_os("SCOPLEN_LIVE_TEAM_SNIPPET_DIRECTORY")
        .expect("provide the private finite Team Snippet handoff directory");
    let directory = Path::new(&directory);
    assert!(directory.is_absolute() && directory.is_dir());
    tokio::time::timeout(Duration::from_secs(1800), roundtrip(directory))
        .await
        .expect("whole finite Team Snippet acceptance deadline");
}
