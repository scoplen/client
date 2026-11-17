// SPDX-License-Identifier: Apache-2.0
//! Native reviewed batches through public facades, SQLCipher and real TLS/DPoP.

use super::*;
use crate::personal_server::{
    TeamImportCandidate, TeamImportError, TeamImportPhase, TeamImportSource,
};
use scoplen_api::{
    ErrorCode, ProblemDetails,
    inventory_import::{InventoryImportPair, InventoryImportRequest, InventoryImportResult},
};
use std::collections::VecDeque;

const CSV: &[u8] = b"name,address,port,username,login_name\nFirst,one.example,,ops,Primary\nSecond,two.example,2202,deploy,\n";
const SSH: &[u8] = b"Host first\n HostName one.example\n User ops\nHost blocked\n User ops\n ProxyCommand do-not-execute\nHost second\n HostName two.example\n User deploy\n Port 2202\n";

#[derive(Default)]
enum Fault {
    #[default]
    None,
    Lost,
    Unknown,
    Denied,
    WrongId,
    Order,
    Partial,
    Malformed,
    Cache,
}

pub(super) struct ImportPeer {
    observer: Arc<Store>,
    faults: VecDeque<Fault>,
    sent: Vec<(uuid::Uuid, Vec<u8>)>,
    receipts: BTreeMap<uuid::Uuid, (Vec<u8>, Vec<u8>)>,
}

impl ImportPeer {
    pub(super) fn answer(
        &mut self,
        request: &http::Request<h2::RecvStream>,
        body: &[u8],
    ) -> Result<Reply, String> {
        if request.method() != http::Method::POST
            || request.uri().query().is_some()
            || request.headers().get_all("idempotency-key").iter().count() != 1
            || request.headers().contains_key("if-match")
            || request.headers().get("content-type").and_then(|v| v.to_str().ok())
                != Some("application/json")
        {
            return Err("invalid import request metadata".into());
        }
        let organization = request
            .uri()
            .path()
            .trim_start_matches("/api/v1/orgs/")
            .split('/')
            .next()
            .unwrap()
            .parse()
            .map_err(|_| "invalid import team")?;
        let key = request.headers()["idempotency-key"]
            .to_str()
            .unwrap()
            .parse()
            .map_err(|_| "invalid import key")?;
        let identity = record(&self.observer).unwrap();
        let pending = self
            .observer
            .team_import_pending(&identity, organization)
            .unwrap()
            .ok_or("missing durable import")?;
        if pending.operation != key
            || pending.phase != 1
            || pending.first_attempt_ms.is_none()
            || pending.payload.as_bytes() != body
        {
            return Err("network preceded exact durable import".into());
        }
        let parsed =
            InventoryImportRequest::from_json(body).map_err(|_| "invalid shared import")?;
        if parsed.to_json().unwrap() != body {
            return Err("noncanonical import".into());
        }
        self.sent.push((key, body.to_vec()));
        let fault = self.faults.pop_front().unwrap_or_default();
        if matches!(fault, Fault::Denied | Fault::Unknown) {
            let unknown = matches!(fault, Fault::Unknown);
            let status = if unknown { 503 } else { 403 };
            let problem = ProblemDetails::new(
                ErrorCode::new(if unknown {
                    "organization.commit_outcome_unknown"
                } else {
                    "policy.denied"
                })
                .unwrap(),
                status,
                "Fixture",
                "Fixture",
                "import-fixture",
                unknown,
                unknown,
            )
            .unwrap();
            return Ok(Reply {
                status,
                content_type: "application/problem+json",
                ..json(serde_json::to_vec(&problem).unwrap())
            });
        }
        let original = if let Some((old, reply)) = self.receipts.get(&key) {
            if old.as_slice() != body {
                return Err("replacement import body".into());
            }
            reply.clone()
        } else {
            let result = InventoryImportResult {
                items: parsed
                    .rows
                    .iter()
                    .map(|row| InventoryImportPair {
                        host_id: row.host_id,
                        access_profile_id: row.access_profile_id,
                    })
                    .collect(),
            }
            .to_json()
            .unwrap();
            self.receipts.insert(key, (body.to_vec(), result.clone()));
            result
        };
        let mut result = InventoryImportResult::from_json(&original).unwrap();
        match fault {
            Fault::WrongId => result.items[0].host_id = id(),
            Fault::Order => result.items.reverse(),
            Fault::Partial => {
                result.items.pop();
            }
            _ => {}
        }
        let mut reply = json(if matches!(fault, Fault::Malformed) {
            b"{\"items\":".to_vec()
        } else {
            result.to_json().unwrap()
        });
        reply.status = 201;
        reply.stall = matches!(fault, Fault::Lost);
        if matches!(fault, Fault::Cache) {
            reply.headers.clear();
        }
        Ok(reply)
    }
}

fn id() -> uuid::Uuid {
    scoplen_model::new_uuid_v7().unwrap()
}
fn json(body: Vec<u8>) -> Reply {
    Reply {
        status: 200,
        content_type: "application/json",
        headers: vec![
            ("cache-control", "no-store".into()),
            ("pragma", "no-cache".into()),
            ("x-request-id", "import-fixture".into()),
        ],
        body,
        stall: false,
    }
}
fn install(peer: &Peer, store: &Arc<Store>, faults: Vec<Fault>) {
    peer.state.lock().unwrap().team_import = Some(ImportPeer {
        observer: store.clone(),
        faults: faults.into(),
        sent: vec![],
        receipts: BTreeMap::new(),
    });
}
fn prepare(
    manager: &PersonalServer,
    store: &Arc<Store>,
    org: &str,
) -> crate::personal_server::TeamImportPending {
    let preview =
        manager.preview_team_inventory_import(store, org, TeamImportSource::Csv, CSV).unwrap();
    manager.prepare_team_inventory_import(store, org, &preview.preview_id, vec![2, 1]).unwrap()
}

#[tokio::test]
async fn native_import_complete_sources_explicit_selection_and_preview_ownership() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let org = id().to_string();
    let preview = manager
        .preview_team_inventory_import(&store, &org, TeamImportSource::OpenSsh, SSH)
        .unwrap();
    assert_eq!(preview.candidates.len(), 3);
    assert!(matches!(preview.candidates[1], TeamImportCandidate::Blocked { ordinal: 2, .. }));
    for selected in [vec![], vec![1, 1], vec![2], vec![0], vec![4]] {
        assert!(matches!(
            manager.prepare_team_inventory_import(&store, &org, &preview.preview_id, selected),
            Err(TeamImportError::InvalidSelection)
        ));
        assert!(manager.pending_team_inventory_import(&store, &org).unwrap().is_none());
    }
    let reopened = local(&dir);
    assert!(matches!(
        manager.prepare_team_inventory_import(&reopened, &org, &preview.preview_id, vec![1]),
        Err(TeamImportError::StalePreview)
    ));
    assert!(matches!(
        manager.prepare_team_inventory_import(
            &store,
            &id().to_string(),
            &preview.preview_id,
            vec![1]
        ),
        Err(TeamImportError::StalePreview)
    ));
    let pending = manager
        .prepare_team_inventory_import(&store, &org, &preview.preview_id, vec![3, 1])
        .unwrap();
    assert_eq!(
        pending.rows.iter().map(|row| row.fields.name.as_str()).collect::<Vec<_>>(),
        vec!["first", "second"]
    );
    assert!(
        pending.rows.iter().all(|row| uuid::Uuid::parse_str(&row.host_id)
            .unwrap()
            .get_version_num()
            == 7
            && uuid::Uuid::parse_str(&row.login_id).unwrap().get_version_num() == 7)
    );
    assert!(matches!(
        manager.prepare_team_inventory_import(&store, &org, &preview.preview_id, vec![1]),
        Err(TeamImportError::StalePreview)
    ));
    assert!(peer.state.lock().unwrap().paths.is_empty());
    let newer =
        manager.preview_team_inventory_import(&store, &org, TeamImportSource::Csv, CSV).unwrap();
    manager.clear_team_inventory_import_preview(&store, &preview.preview_id).unwrap();
    assert!(matches!(
        manager.prepare_team_inventory_import(&store, &org, &newer.preview_id, vec![1]),
        Err(TeamImportError::Pending)
    ));
    manager.discard_team_inventory_import(&store, &org, &pending.operation_id).unwrap();
    let invalid = b"name,address,port,username,login_name\nValid,one.example,22,ops,\nInvalid,two.example,0,ops,\n";
    assert!(matches!(
        manager.preview_team_inventory_import(&store, &org, TeamImportSource::Csv, invalid),
        Err(TeamImportError::Source(_))
    ));
    assert!(matches!(
        manager.prepare_team_inventory_import(&store, &org, &newer.preview_id, vec![1]),
        Err(TeamImportError::StalePreview)
    ));
    assert!(manager.pending_team_inventory_import(&store, &org).unwrap().is_none());
}

#[tokio::test]
async fn native_import_one_regular_bounded_file_and_source_free_diagnostics() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let org = id().to_string();
    let file = dir.path().join("selected-config");
    std::fs::write(&file, SSH).unwrap();
    assert_eq!(
        manager
            .preview_team_inventory_import_file(&store, &org, TeamImportSource::OpenSsh, &file)
            .unwrap()
            .candidates
            .len(),
        3
    );
    assert!(matches!(
        manager.preview_team_inventory_import_file(&store, &org, TeamImportSource::Csv, dir.path()),
        Err(TeamImportError::FileUnavailable)
    ));
    std::fs::write(&file, vec![b'x'; 1_048_577]).unwrap();
    assert!(matches!(
        manager.preview_team_inventory_import_file(&store, &org, TeamImportSource::Csv, &file),
        Err(TeamImportError::Source(_))
    ));
    let error = manager
        .preview_team_inventory_import(
            &store,
            &org,
            TeamImportSource::OpenSsh,
            b"Include sensitive-private-path\n",
        )
        .unwrap_err();
    assert!(!serde_json::to_string(&error).unwrap().contains("sensitive-private-path"));
    assert!(peer.state.lock().unwrap().paths.is_empty());
}

#[tokio::test]
async fn native_import_persists_original_ciphertext_and_confirms_after_reopen() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store, vec![Fault::Lost]);
    let org = id().to_string();
    let pending = prepare(&manager, &store, &org);
    assert_eq!(pending.rows[0].fields.name, "First");
    assert!(matches!(
        manager.submit_team_inventory_import(store.clone(), &org, &pending.operation_id).await,
        Err(TeamImportError::Unknown)
    ));
    let reopened = local(&dir);
    let restarted = peer.manager();
    let retained = restarted.pending_team_inventory_import(&reopened, &org).unwrap().unwrap();
    assert_eq!(retained.phase, TeamImportPhase::Unknown);
    assert_eq!(retained.operation_id, pending.operation_id);
    assert_eq!(retained.rows[0].host_id, pending.rows[0].host_id);
    let confirmed = restarted
        .submit_team_inventory_import(reopened.clone(), &org, &pending.operation_id)
        .await
        .unwrap();
    assert_eq!(confirmed.phase, TeamImportPhase::Confirmed);
    let state = peer.state.lock().unwrap();
    let sent = &state.team_import.as_ref().unwrap().sent;
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0], sent[1]);
    drop(state);
    let bytes = std::fs::read(dir.path().join("personal.db")).unwrap();
    assert!(!bytes.windows(b"one.example".len()).any(|part| part == b"one.example"));
    peer.assert_healthy();
}

#[tokio::test]
async fn native_import_every_incomplete_success_retains_unknown_original() {
    for fault in [Fault::WrongId, Fault::Order, Fault::Partial, Fault::Malformed, Fault::Cache] {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        let manager = peer.prepare(&store).await;
        install(&peer, &store, vec![fault, Fault::Denied]);
        let org = id().to_string();
        let pending = prepare(&manager, &store, &org);
        assert!(matches!(
            manager.submit_team_inventory_import(store.clone(), &org, &pending.operation_id).await,
            Err(TeamImportError::Unknown)
        ));
        assert!(
            manager
                .submit_team_inventory_import(store.clone(), &org, &pending.operation_id)
                .await
                .is_err()
        );
        assert_eq!(
            manager.pending_team_inventory_import(&store, &org).unwrap().unwrap().phase,
            TeamImportPhase::Unknown
        );
        assert!(matches!(
            manager.discard_team_inventory_import(&store, &org, &pending.operation_id),
            Err(TeamImportError::Unknown)
        ));
        peer.assert_healthy();
    }
}

#[tokio::test]
async fn native_import_first_denial_is_unchanged_but_prior_unknown_never_downgrades() {
    for faults in [vec![Fault::Denied], vec![Fault::Unknown, Fault::Denied]] {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        let manager = peer.prepare(&store).await;
        let unknown = faults.len() > 1;
        install(&peer, &store, faults);
        let org = id().to_string();
        let pending = prepare(&manager, &store, &org);
        if unknown {
            assert!(
                manager
                    .submit_team_inventory_import(store.clone(), &org, &pending.operation_id)
                    .await
                    .is_err()
            );
        }
        assert!(
            manager
                .submit_team_inventory_import(store.clone(), &org, &pending.operation_id)
                .await
                .is_err()
        );
        assert_eq!(
            manager.pending_team_inventory_import(&store, &org).unwrap().unwrap().phase,
            if unknown { TeamImportPhase::Unknown } else { TeamImportPhase::Prepared }
        );
        peer.assert_healthy();
    }
}

#[tokio::test]
async fn native_import_saved_destinations_are_paged_account_bound_and_body_free() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let mut expected = Vec::new();
    for _ in 0..102 {
        let org = id().to_string();
        prepare(&manager, &store, &org);
        expected.push(org);
    }
    expected.sort();
    let first = manager.retained_team_inventory_imports(&store, None).unwrap();
    assert_eq!(first.organization_ids, expected[..100]);
    let second =
        manager.retained_team_inventory_imports(&store, first.next_cursor.as_deref()).unwrap();
    assert_eq!(second.organization_ids, expected[100..]);
    assert!(second.next_cursor.is_none());
    let projection = serde_json::to_string(&first).unwrap();
    assert!(!projection.contains("one.example"));
    let other = tempfile::tempdir().unwrap();
    let other_store = local(&other);
    peer.prepare(&other_store).await;
    assert!(
        manager
            .retained_team_inventory_imports(&other_store, None)
            .unwrap()
            .organization_ids
            .is_empty()
    );
}

#[tokio::test]
async fn native_import_original_deadline_is_immutable_and_archive_requires_expired_review() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let org = id().to_string();
    let pending = prepare(&manager, &store, &org);
    let identity = record(&store).unwrap();
    let original = store.team_import_pending(&identity, org.parse().unwrap()).unwrap().unwrap();
    let access = store.personal_access_token(now().unwrap()).unwrap().unwrap();
    let current_ms =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()
            as u64;
    let first = current_ms - 86_400_000;
    assert!(store.dispatch_team_import(&identity, &original, &access, first).unwrap());
    let sent = store.team_import_pending(&identity, org.parse().unwrap()).unwrap().unwrap();
    assert_eq!(sent.first_attempt_ms, Some(first));
    assert!(store.dispatch_team_import(&identity, &sent, &access, first + 86_399_999).unwrap());
    assert!(!store.dispatch_team_import(&identity, &sent, &access, first + 86_400_000).unwrap());
    assert_eq!(
        manager.pending_team_inventory_import(&store, &org).unwrap().unwrap().phase,
        TeamImportPhase::Expired
    );
    assert!(matches!(
        manager.submit_team_inventory_import(store.clone(), &org, &pending.operation_id).await,
        Err(TeamImportError::Expired)
    ));
    assert!(matches!(
        manager.discard_team_inventory_import(&store, &org, &pending.operation_id),
        Err(TeamImportError::ReviewRequired)
    ));
    let review = manager
        .review_team_inventory_import(store.clone(), &org, &pending.operation_id)
        .await
        .unwrap();
    assert!(review.error.is_some());
    assert!(review.pending.can_archive);
    assert_eq!(review.pending.phase, TeamImportPhase::Expired);
    manager.discard_team_inventory_import(&store, &org, &pending.operation_id).unwrap();
    assert!(manager.pending_team_inventory_import(&store, &org).unwrap().is_none());
    peer.assert_healthy();
}

#[tokio::test]
async fn native_import_confirmation_survives_failed_current_inventory_review() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store, vec![]);
    let org = id().to_string();
    let pending = prepare(&manager, &store, &org);
    manager.submit_team_inventory_import(store.clone(), &org, &pending.operation_id).await.unwrap();
    let review = manager
        .review_team_inventory_import(store.clone(), &org, &pending.operation_id)
        .await
        .unwrap();
    assert!(review.error.is_some());
    assert_eq!(review.pending.phase, TeamImportPhase::Confirmed);
    assert_eq!(review.pending.rows[0].host_id, pending.rows[0].host_id);
    assert_eq!(peer.state.lock().unwrap().team_import.as_ref().unwrap().sent.len(), 1);
    peer.assert_healthy();
}

#[tokio::test]
async fn native_import_authentication_replacement_fences_preview_and_late_response() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = Arc::new(peer.prepare(&store).await);
    let org = id().to_string();
    let preview =
        manager.preview_team_inventory_import(&store, &org, TeamImportSource::Csv, CSV).unwrap();
    peer.install_token(&store, |_| {}, None);
    assert!(matches!(
        manager.prepare_team_inventory_import(&store, &org, &preview.preview_id, vec![1]),
        Err(TeamImportError::StalePreview)
    ));
    install(&peer, &store, vec![]);
    let pending = prepare(&manager, &store, &org);
    let reached = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    peer.state.lock().unwrap().pause =
        Some((format!("/api/v1/orgs/{org}/inventory/imports"), reached.clone(), resume.clone()));
    let sending = {
        let manager = manager.clone();
        let store = store.clone();
        let org = org.clone();
        let operation = pending.operation_id.clone();
        tokio::spawn(
            async move { manager.submit_team_inventory_import(store, &org, &operation).await },
        )
    };
    reached.notified().await;
    peer.install_token(&store, |_| {}, None);
    resume.notify_one();
    assert!(matches!(sending.await.unwrap(), Err(TeamImportError::Unknown)));
    assert_eq!(
        manager.pending_team_inventory_import(&store, &org).unwrap().unwrap().phase,
        TeamImportPhase::Unknown
    );
    let confirmed = manager
        .submit_team_inventory_import(store.clone(), &org, &pending.operation_id)
        .await
        .unwrap();
    assert_eq!(confirmed.phase, TeamImportPhase::Confirmed);
    assert_eq!(confirmed.rows[0].host_id, pending.rows[0].host_id);
    peer.assert_healthy();
}

#[cfg(feature = "live-server-integration")]
#[tokio::test]
async fn native_import_live_reply_discard_is_one_shot_and_only_consumes_verified_success() {
    use std::sync::atomic::Ordering;
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store, vec![Fault::Denied, Fault::WrongId, Fault::None, Fault::None]);
    let org = id().to_string();
    let pending = prepare(&manager, &store, &org);
    let control = &manager.transport.as_ref().unwrap().discard_next_import_reply;
    control.store(true, Ordering::SeqCst);
    for _ in 0..2 {
        assert!(
            manager
                .submit_team_inventory_import(store.clone(), &org, &pending.operation_id)
                .await
                .is_err()
        );
        assert!(control.load(Ordering::SeqCst));
    }
    assert!(matches!(
        manager.submit_team_inventory_import(store.clone(), &org, &pending.operation_id).await,
        Err(TeamImportError::Unknown)
    ));
    assert!(!control.load(Ordering::SeqCst));
    assert_eq!(
        manager
            .submit_team_inventory_import(store.clone(), &org, &pending.operation_id)
            .await
            .unwrap()
            .phase,
        TeamImportPhase::Confirmed
    );
    peer.assert_healthy();
}
