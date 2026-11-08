// SPDX-License-Identifier: Apache-2.0
//! Named team authoring through real TLS, DPoP and independent public shared codecs.

use super::*;
use crate::personal_server::{
    TeamAuthoringCollection as Collection, TeamAuthoringCreatePhase as Phase, TeamAuthoringData,
    TeamError, TeamFailure, TeamSimplePermission, TeamSimpleRuleInput, TeamSimpleRuleResource,
};
use scoplen_api::{
    ErrorCode, ProblemDetails,
    group_policy::{
        GroupCreateRequest, GroupReplaceRequest, GroupResource, GroupSource, PolicyCreateRequest,
        PolicyReplaceRequest, PolicyResource,
    },
    inventory::{
        InventoryCreateRequest, InventoryReplaceRequest, InventoryResource, InventoryType,
    },
};
use std::collections::VecDeque;

const TIME: &str = "2026-11-02T00:00:00Z";

#[derive(Default)]
enum Fault {
    #[default]
    None,
    Lost,
    Unknown,
    Denied,
    WrongId,
    WrongFields,
}

struct Sent {
    method: http::Method,
    path: String,
    key: Option<uuid::Uuid>,
    etag: Option<String>,
    body: Vec<u8>,
}

pub(super) struct AuthoringPeer {
    observer: Arc<Store>,
    resources: BTreeMap<(uuid::Uuid, String, uuid::Uuid), Vec<u8>>,
    receipts: BTreeMap<uuid::Uuid, (Vec<u8>, Vec<u8>)>,
    sent: Vec<Sent>,
    faults: VecDeque<Fault>,
}

impl AuthoringPeer {
    pub(super) fn answer(
        &mut self,
        request: &http::Request<h2::RecvStream>,
        body: &[u8],
    ) -> Result<Reply, String> {
        let path = request.uri().path();
        let parts = path
            .strip_prefix("/api/v1/orgs/")
            .ok_or("bad authoring prefix")?
            .split('/')
            .collect::<Vec<_>>();
        if !(2..=3).contains(&parts.len()) {
            return Err("bad authoring path".into());
        }
        let organization = uuid::Uuid::parse_str(parts[0]).map_err(|_| "bad organization")?;
        let collection = parts[1];
        let id = parts
            .get(2)
            .map(|value| uuid::Uuid::parse_str(value).map_err(|_| "bad resource id"))
            .transpose()?;
        let key = request
            .headers()
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok())
            .map(|value| uuid::Uuid::parse_str(value).map_err(|_| "bad operation key"))
            .transpose()?;
        let etag = request.headers().get("if-match").and_then(|value| value.to_str().ok());
        let method = request.method();
        if key.is_some() != (*method == http::Method::POST)
            || etag.is_some() != matches!(*method, http::Method::PUT | http::Method::DELETE)
            || request.headers().get_all("idempotency-key").iter().count() > 1
            || request.headers().get_all("if-match").iter().count() > 1
            || matches!(*method, http::Method::POST | http::Method::PUT)
                && request.headers().get("content-type").and_then(|value| value.to_str().ok())
                    != Some("application/json")
            || matches!(*method, http::Method::GET | http::Method::DELETE) && !body.is_empty()
        {
            return Err("bad authoring method/header/body".into());
        }
        self.sent.push(Sent {
            method: method.clone(),
            path: path.into(),
            key,
            etag: etag.map(str::to_owned),
            body: body.to_vec(),
        });
        let identity = record(&self.observer).unwrap();
        if *method == http::Method::POST {
            let pending = self
                .observer
                .team_authoring_pending(&identity, organization)
                .unwrap()
                .ok_or("no durable authoring request")?;
            if pending.phase != 1
                || pending.first_attempt_ms.is_none()
                || Some(pending.operation) != key
                || pending.payload.as_bytes() != body
                || pending.collection != collection
            {
                return Err("authoring dispatch preceded durable original request".into());
            }
            let fault = self.faults.pop_front().unwrap_or_default();
            if matches!(fault, Fault::Denied) {
                return Ok(problem(403, "policy.denied", false));
            }
            if matches!(fault, Fault::Unknown) {
                return Ok(problem(503, "organization.commit_outcome_unknown", true));
            }
            let key = key.unwrap();
            let response = if let Some((original, response)) = self.receipts.get(&key) {
                if original.as_slice() != body {
                    return Err("changed original authoring request".into());
                }
                response.clone()
            } else {
                let response = resource(
                    collection,
                    pending.resource,
                    body,
                    true,
                    &identity,
                    self.observer.device_id(),
                    "\"current\"",
                )?;
                self.resources
                    .insert((organization, collection.into(), pending.resource), response.clone());
                self.receipts.insert(key, (body.to_vec(), response.clone()));
                response
            };
            let mut response: serde_json::Value = serde_json::from_slice(&response).unwrap();
            if matches!(fault, Fault::WrongId) {
                response["id"] = serde_json::json!(id_new().to_string());
            }
            if matches!(fault, Fault::WrongFields) {
                response["data"]["fields"]["address"] = serde_json::json!("other.example");
            }
            let mut reply = resource_reply(serde_json::to_vec(&response).unwrap());
            reply.status = 201;
            reply.stall = matches!(fault, Fault::Lost);
            return Ok(reply);
        }
        if *method == http::Method::GET && id.is_none() {
            let query = scoplen_api::organization::OrganizationListQuery::from_parameters(
                request
                    .uri()
                    .query()
                    .unwrap_or("")
                    .split('&')
                    .filter(|part| !part.is_empty())
                    .map(|part| part.split_once('=').unwrap()),
            )
            .map_err(|_| "bad authoring page query")?;
            let items = self
                .resources
                .iter()
                .filter(|((org, kind, id), _)| {
                    *org == organization
                        && kind == collection
                        && query.cursor.is_none_or(|cursor| *id > cursor)
                })
                .map(|(_, body)| serde_json::from_slice::<serde_json::Value>(body).unwrap())
                .collect::<Vec<_>>();
            return Ok(json(
                serde_json::to_vec(&serde_json::json!({"items":items,"next_cursor":null})).unwrap(),
            ));
        }
        let Some(id) = id else { return Err("missing authoring id".into()) };
        let resource_key = (organization, collection.to_owned(), id);
        let Some(current) = self.resources.get(&resource_key) else {
            return Ok(problem(404, "organization.not_found", false));
        };
        if *method == http::Method::GET {
            return Ok(resource_reply(current.clone()));
        }
        let current: serde_json::Value = serde_json::from_slice(current).unwrap();
        if etag != current["etag"].as_str() {
            return Ok(problem(412, "organization.precondition_failed", false));
        }
        if matches!(self.faults.pop_front().unwrap_or_default(), Fault::Unknown) {
            return Ok(problem(503, "organization.commit_outcome_unknown", true));
        }
        if *method == http::Method::DELETE {
            self.resources.remove(&resource_key);
            let mut reply = json(vec![]);
            reply.status = 204;
            reply.content_type = "";
            return Ok(reply);
        }
        if *method != http::Method::PUT {
            return Err("unsupported authoring method".into());
        }
        let response = resource(
            collection,
            id,
            body,
            false,
            &identity,
            self.observer.device_id(),
            "\"updated\"",
        )?;
        self.resources.insert(resource_key, response.clone());
        Ok(resource_reply(response))
    }
}

fn id_new() -> uuid::Uuid {
    scoplen_model::new_uuid_v7().unwrap()
}

fn resource(
    collection: &str,
    id: uuid::Uuid,
    body: &[u8],
    create: bool,
    identity: &PersonalRecord,
    device: uuid::Uuid,
    etag: &str,
) -> Result<Vec<u8>, String> {
    if let Ok(kind) = InventoryType::from_segment(collection) {
        let mut fields = if create {
            let request = InventoryCreateRequest::from_json(kind, body)
                .map_err(|_| "bad shared inventory create")?;
            if request.id != id {
                return Err("wrong create id".into());
            }
            request.fields
        } else {
            InventoryReplaceRequest::from_json(kind, body)
                .map_err(|_| "bad shared inventory replace")?
                .fields
        };
        if kind == InventoryType::TrustRecord {
            fields = fields.with_trust_attribution(1, identity.account_id, device).unwrap();
        }
        return InventoryResource {
            id,
            etag: etag.into(),
            created_at: TIME.into(),
            updated_at: TIME.into(),
            fields,
        }
        .to_json()
        .map_err(|_| "bad shared inventory resource".into());
    }
    if collection == "groups" {
        let fields = if create {
            GroupCreateRequest::from_json(body).map_err(|_| "bad shared group create")?.fields
        } else {
            GroupReplaceRequest::from_json(body).map_err(|_| "bad shared group replace")?.fields
        };
        return GroupResource {
            id,
            etag: etag.into(),
            created_at: TIME.into(),
            updated_at: TIME.into(),
            fields,
            source: GroupSource::Local,
        }
        .to_json()
        .map_err(|_| "bad shared group resource".into());
    }
    let fields = if create {
        PolicyCreateRequest::from_json(body).map_err(|_| "bad shared policy create")?.fields
    } else {
        PolicyReplaceRequest::from_json(body).map_err(|_| "bad shared policy replace")?.fields
    };
    PolicyResource {
        id,
        etag: etag.into(),
        created_at: TIME.into(),
        updated_at: TIME.into(),
        fields,
    }
    .to_json()
    .map_err(|_| "bad shared policy resource".into())
}

fn json(body: Vec<u8>) -> Reply {
    Reply {
        content_type: "application/json",
        headers: vec![
            ("cache-control", "no-store".into()),
            ("pragma", "no-cache".into()),
            ("x-request-id", "authoring-fixture".into()),
        ],
        ..Reply::cbor(body)
    }
}
fn resource_reply(body: Vec<u8>) -> Reply {
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let mut reply = json(body);
    reply.headers.push(("etag", value["etag"].as_str().unwrap().into()));
    reply
}
fn problem(status: u16, code: &str, changed: bool) -> Reply {
    let value = ProblemDetails::new(
        ErrorCode::new(code).unwrap(),
        status,
        "Fixture",
        "Fixture",
        "authoring-fixture",
        changed,
        changed,
    )
    .unwrap();
    Reply {
        status,
        content_type: "application/problem+json",
        ..json(serde_json::to_vec(&value).unwrap())
    }
}

pub(super) fn install(peer: &Peer, store: &Arc<Store>) {
    peer.state.lock().unwrap().team_authoring = Some(AuthoringPeer {
        observer: store.clone(),
        resources: BTreeMap::new(),
        receipts: BTreeMap::new(),
        sent: vec![],
        faults: VecDeque::new(),
    });
}
fn data(kind: &str, fields: serde_json::Value) -> TeamAuthoringData {
    serde_json::from_value(serde_json::json!({"kind":kind,"fields":fields})).unwrap()
}
fn host() -> TeamAuthoringData {
    data(
        "host",
        serde_json::json!({"name":" Team host ","address":"host.example","tags":{"environment":" prod "}}),
    )
}

#[test]
fn optional_authoring_fields_accept_omission_and_null_without_serializing_placeholders() {
    let omitted = data("host", serde_json::json!({"address":"host.example"}));
    let nullable = data(
        "host",
        serde_json::json!({"address":"host.example","name":null,"tags":null,"default_profile":null}),
    );
    assert_eq!(serde_json::to_value(&omitted).unwrap(), serde_json::to_value(&nullable).unwrap());
    assert_eq!(
        serde_json::to_value(&nullable).unwrap(),
        serde_json::json!({"kind":"host","fields":{"address":"host.example"}})
    );
    let snippet = data(
        "snippet",
        serde_json::json!({"name":"Run","template":"echo","variables":{"argument":{"kind":1,"default":null,"choices":null}}}),
    );
    assert_eq!(
        serde_json::to_value(&snippet).unwrap(),
        serde_json::json!({"kind":"snippet","fields":{"name":"Run","template":"echo","variables":{"argument":{"kind":1}}}})
    );
    for fields in [serde_json::json!({}), serde_json::json!({"address":null})] {
        assert!(
            serde_json::from_value::<TeamAuthoringData>(
                serde_json::json!({"kind":"host","fields":fields})
            )
            .is_err()
        );
    }
}

#[tokio::test]
async fn all_nine_authoring_types_use_shared_canonical_crud_and_server_owned_trust_attribution() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store);
    let organization = id_new().to_string();
    let reference = id_new().to_string();
    let policy = manager
        .preview_team_simple_rule(
            &store,
            &organization,
            TeamSimpleRuleInput {
                membership_id: Some(reference.clone()),
                group_id: None,
                permission: TeamSimplePermission::View,
                remote_user: None,
                resources: vec![TeamSimpleRuleResource {
                    collection: Collection::Host,
                    id: reference.clone(),
                }],
            },
        )
        .unwrap()
        .source;
    let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[44; 32]));
    let public = key.public_key();
    let samples = [
        host(),
        data("login", serde_json::json!({"host":reference,"username":"deploy","route":0})),
        data("route", serde_json::json!({"name":"Jump","kind":1,"hops":[reference]})),
        data("hostGroup", serde_json::json!({"name":"Servers","defaults":{"username":"deploy"}})),
        data(
            "trustRecord",
            serde_json::json!({"host":reference,"key":public.to_openssh().unwrap(),"fingerprint":public.fingerprint(ssh_key::HashAlg::Sha256).to_string(),"provenance":1}),
        ),
        data(
            "snippet",
            serde_json::json!({"name":"Run","template":"echo hello","variables":{"password":{"kind":4}}}),
        ),
        data("gatewayNetwork", serde_json::json!({"name":"Gateway","description":" Team route "})),
        data("group", serde_json::json!({"name":"Operators","members":[reference]})),
        data("policy", serde_json::json!({"name":"View","enabled":true,"source":policy})),
    ];
    let before = record(&store).unwrap();
    for sample in samples {
        let collection = match &sample {
            TeamAuthoringData::Host(_) => Collection::Host,
            TeamAuthoringData::Login(_) => Collection::Login,
            TeamAuthoringData::Route(_) => Collection::Route,
            TeamAuthoringData::HostGroup(_) => Collection::HostGroup,
            TeamAuthoringData::TrustRecord(_) => Collection::TrustRecord,
            TeamAuthoringData::Snippet(_) => Collection::Snippet,
            TeamAuthoringData::GatewayNetwork(_) => Collection::GatewayNetwork,
            TeamAuthoringData::Group(_) => Collection::Group,
            TeamAuthoringData::Policy(_) => Collection::Policy,
        };
        let prepared =
            manager.prepare_team_authoring(&store, &organization, sample.clone()).unwrap();
        assert_eq!(prepared.phase, Phase::Prepared);
        let reopened = local(&dir);
        assert_eq!(
            manager.pending_team_authoring(&reopened, &organization).unwrap().unwrap().operation_id,
            prepared.operation_id
        );
        let confirmed = manager
            .submit_team_authoring(store.clone(), &organization, &prepared.operation_id)
            .await
            .unwrap();
        assert_eq!(confirmed.phase, Phase::Confirmed);
        let page = manager
            .team_authoring_page(store.clone(), &organization, collection, None)
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.organization_id, organization);
        let current = manager
            .team_authoring_resource(
                store.clone(),
                &organization,
                collection,
                &prepared.resource_id,
            )
            .await
            .unwrap();
        assert_eq!(current.etag, "\"current\"");
        if collection == Collection::TrustRecord {
            assert_eq!(
                current.trust_attribution.as_ref().unwrap().accepted_by_account,
                before.account_id.to_string()
            );
        }
        assert_eq!(
            serde_json::to_value(&current.data).unwrap(),
            serde_json::to_value(&confirmed.data).unwrap()
        );
        let updated = manager
            .update_team_authoring(
                store.clone(),
                &organization,
                &prepared.resource_id,
                &current.etag,
                sample,
            )
            .await
            .unwrap();
        assert_eq!(updated.etag, "\"updated\"");
        manager
            .delete_team_authoring(
                store.clone(),
                &organization,
                collection,
                &prepared.resource_id,
                &updated.etag,
            )
            .await
            .unwrap();
        assert!(
            store.get(uuid::Uuid::parse_str(&prepared.resource_id).unwrap()).unwrap().is_none()
        );
        manager.discard_team_authoring(&store, &organization, &prepared.operation_id).unwrap();
    }
    let after = record(&store).unwrap();
    assert!(before.private_material.as_bytes() == after.private_material.as_bytes());
    assert!(manager.pending_team_authoring(&store, &id_new().to_string()).unwrap().is_none());
    peer.assert_healthy();
}

#[tokio::test]
async fn lost_create_retries_only_the_original_key_and_body_and_a_later_denial_does_not_settle_it()
{
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store);
    let organization = id_new().to_string();
    peer.state.lock().unwrap().team_authoring.as_mut().unwrap().faults =
        [Fault::Lost, Fault::Denied, Fault::None].into();
    let prepared = manager.prepare_team_authoring(&store, &organization, host()).unwrap();
    assert!(matches!(
        manager.submit_team_authoring(store.clone(), &organization, &prepared.operation_id).await,
        Err(TeamError::Team(TeamFailure::AuthoringUnknown))
    ));
    assert_eq!(
        manager.pending_team_authoring(&store, &organization).unwrap().unwrap().phase,
        Phase::Unknown
    );
    assert!(manager.discard_team_authoring(&store, &organization, &prepared.operation_id).is_err());
    assert!(
        manager
            .submit_team_authoring(store.clone(), &organization, &prepared.operation_id)
            .await
            .is_err()
    );
    assert_eq!(
        manager.pending_team_authoring(&store, &organization).unwrap().unwrap().phase,
        Phase::Unknown
    );
    assert!(manager.prepare_team_authoring(&store, &organization, host()).is_err());
    assert_eq!(
        manager
            .submit_team_authoring(store.clone(), &organization, &prepared.operation_id)
            .await
            .unwrap()
            .phase,
        Phase::Confirmed
    );
    let state = peer.state.lock().unwrap();
    let fixture = state.team_authoring.as_ref().unwrap();
    assert_eq!(fixture.receipts.len(), 1);
    assert_eq!(fixture.sent.len(), 3);
    assert!(fixture.sent.iter().all(|sent| sent.method == http::Method::POST
        && sent.key == fixture.sent[0].key
        && sent.body == fixture.sent[0].body
        && sent.etag.is_none()
        && sent.path.ends_with("/hosts")));
    drop(state);
    peer.assert_healthy();
}

#[tokio::test]
async fn wrong_create_response_is_never_confirmed_and_conditional_edits_keep_the_original_etag() {
    for fault in [Fault::WrongId, Fault::WrongFields] {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        let manager = peer.prepare(&store).await;
        install(&peer, &store);
        let organization = id_new().to_string();
        peer.state.lock().unwrap().team_authoring.as_mut().unwrap().faults.push_back(fault);
        let prepared = manager.prepare_team_authoring(&store, &organization, host()).unwrap();
        assert!(
            manager
                .submit_team_authoring(store.clone(), &organization, &prepared.operation_id)
                .await
                .is_err()
        );
        assert_eq!(
            manager.pending_team_authoring(&store, &organization).unwrap().unwrap().phase,
            Phase::Unknown
        );
        assert_eq!(
            manager
                .submit_team_authoring(store.clone(), &organization, &prepared.operation_id)
                .await
                .unwrap()
                .phase,
            Phase::Confirmed
        );
        assert!(matches!(
            manager
                .update_team_authoring(
                    store.clone(),
                    &organization,
                    &prepared.resource_id,
                    "\"stale\"",
                    host()
                )
                .await,
            Err(TeamError::Team(TeamFailure::AuthoringConflict))
        ));
        peer.state
            .lock()
            .unwrap()
            .team_authoring
            .as_mut()
            .unwrap()
            .faults
            .push_back(Fault::Unknown);
        assert!(matches!(
            manager
                .update_team_authoring(
                    store.clone(),
                    &organization,
                    &prepared.resource_id,
                    "\"current\"",
                    host()
                )
                .await,
            Err(TeamError::Team(TeamFailure::AuthoringUnknown))
        ));
        assert_eq!(
            manager
                .team_authoring_resource(
                    store.clone(),
                    &organization,
                    Collection::Host,
                    &prepared.resource_id
                )
                .await
                .unwrap()
                .etag,
            "\"current\""
        );
        peer.assert_healthy();
    }
}

#[tokio::test]
async fn simple_rules_and_invalid_personal_fields_use_only_the_shared_supported_contract() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let organization = id_new().to_string();
    let host_id = id_new().to_string();
    let membership = id_new().to_string();
    let preview = manager
        .preview_team_simple_rule(
            &store,
            &organization,
            TeamSimpleRuleInput {
                membership_id: Some(membership),
                group_id: None,
                permission: TeamSimplePermission::Connect,
                remote_user: Some("deploy".into()),
                resources: vec![TeamSimpleRuleResource {
                    collection: Collection::Host,
                    id: host_id,
                }],
            },
        )
        .unwrap();
    assert!(preview.source.contains("deploy"));
    assert!(!preview.source.contains("Action::\"view\""));
    assert!(serde_json::from_value::<TeamAuthoringData>(serde_json::json!({"kind":"login","fields":{"host":id_new().to_string(),"username":"deploy","credential":id_new().to_string()}})).is_err());
    let invalid = data(
        "snippet",
        serde_json::json!({"name":"Secret","template":"echo","variables":{"password":{"kind":4,"default":"must reject"}}}),
    );
    assert!(manager.prepare_team_authoring(&store, &organization, invalid).is_err());
    assert!(peer.state.lock().unwrap().paths.is_empty());
}
