// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use scoplen_crypto::LocalDatabaseKey;
use scoplen_crypto::SecretVec;
use scoplen_model::{FieldPath, ObjectType, cbor::Value};
use uuid::Uuid;

use super::*;
use crate::store::{LocalWrite, Store};

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("local.db"), &LocalDatabaseKey::new([3; 32])).unwrap();
    (dir, store)
}

fn new_id() -> Uuid {
    scoplen_model::new_uuid_v7().unwrap()
}

fn add_host(store: &Store, name: &str) -> Host {
    Repository::<Host>::new(store)
        .create(HostChange {
            name: Some(name.into()),
            address: Some(format!("{name}.example")),
            ..Default::default()
        })
        .unwrap()
}

#[test]
fn hosts_round_trip_with_defaults_maps_and_clears() {
    let (_dir, store) = store();
    let hosts = Repository::<Host>::new(&store);
    let group = new_id();
    let profile = new_id();
    let host = hosts
        .create(HostChange {
            name: Some("db".into()),
            address: Some("10.0.0.7".into()),
            tags: BTreeMap::from([
                ("env".into(), Some("prod".into())),
                ("team".into(), Some("data".into())),
            ]),
            groups: BTreeMap::from([(group, true)]),
            notes: Edit::Set("primary".into()),
            default_profile: Edit::Set(profile),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(host.port, 22, "the port defaults to 22");
    assert_eq!(host.groups.iter().copied().collect::<Vec<_>>(), [group]);
    assert_eq!(host.default_profile, Some(profile));

    let updated = hosts
        .update(
            host.meta.id,
            HostChange {
                port: Edit::Set(2222),
                tags: BTreeMap::from([("team".into(), None)]),
                groups: BTreeMap::from([(group, false)]),
                notes: Edit::Clear,
                default_profile: Edit::Clear,
                favorite: Some(true),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(updated.name, "db", "unchanged fields stay");
    assert_eq!(updated.port, 2222);
    assert_eq!(updated.tags, BTreeMap::from([("env".into(), "prod".into())]));
    assert!(updated.groups.is_empty());
    assert_eq!(updated.notes, None);
    assert_eq!(updated.default_profile, None, "an optional field can be cleared (D-57)");
    assert!(updated.favorite);
    assert_eq!(hosts.get(host.meta.id).unwrap().unwrap(), updated);
}

#[test]
fn a_change_missing_required_fields_is_refused() {
    let (_dir, store) = store();
    let hosts = Repository::<Host>::new(&store);
    assert!(
        hosts.create(HostChange { name: Some("no address".into()), ..Default::default() }).is_err()
    );
    assert!(hosts.list().unwrap().is_empty());
}

#[test]
fn logins_choose_credentials_and_routes_and_can_go_back_to_defaults() {
    let (_dir, store) = store();
    let host = add_host(&store, "app");
    let logins = Repository::<AccessProfile>::new(&store);
    let credential = new_id();
    let route = new_id();
    let login = logins
        .create(AccessProfileChange {
            host: Some(host.meta.id),
            username: Some("deploy".into()),
            credential: Edit::Set(credential),
            route: Some(RouteChoice::Route(route)),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(login.credential, Some(credential));
    assert_eq!(login.route, RouteChoice::Route(route));

    let back = logins
        .update(
            login.meta.id,
            AccessProfileChange {
                credential: Edit::Clear,
                route: Some(RouteChoice::Direct),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(back.credential, None, "any usable credential on this device");
    assert_eq!(back.route, RouteChoice::Direct);
}

#[test]
fn credential_secrets_never_appear_in_records() {
    let (_dir, store) = store();
    let credentials = Repository::<Credential>::new(&store);
    let change = CredentialChange {
        name: Edit::Set("prod password".into()),
        kind: Some(CredentialKind::Password),
        binding: Some(CredentialBinding::Shared),
        secret: Edit::Set(SecretVec::new(b"hunter2".to_vec())),
        ..Default::default()
    };
    let formatted = format!("{change:?}");
    assert!(formatted.contains("[REDACTED]") && !formatted.contains("hunter2"), "{formatted}");
    let credential = credentials.create(change).unwrap();
    assert!(credential.has_secret);
    assert!(!format!("{credential:?}").contains("hunter2"));
    assert_eq!(
        credential_secret(&store, credential.meta.id).unwrap().unwrap().as_bytes(),
        b"hunter2"
    );

    let device = new_id();
    let device_bound = credentials
        .create(CredentialChange {
            kind: Some(CredentialKind::DeviceBoundKey),
            binding: Some(CredentialBinding::Device),
            devices: BTreeMap::from([(
                device,
                Some(DeviceKey {
                    public_key: "ssh-ed25519 AAAA test".into(),
                    label: "MacBook".into(),
                }),
            )]),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(device_bound.devices[&device].label, "MacBook");

    let refused = credentials.create(CredentialChange {
        kind: Some(CredentialKind::SecurityKey),
        binding: Some(CredentialBinding::Shared),
        secret: Edit::Set(SecretVec::new(vec![1])),
        ..Default::default()
    });
    assert!(refused.is_err(), "security keys cannot have shared secrets (04 §4.4)");
}

#[test]
fn changing_a_route_kind_leaves_no_fields_of_the_old_kind() {
    let (_dir, store) = store();
    let routes = Repository::<Route>::new(&store);
    let hop = new_id();
    let route = routes
        .create(RouteChange {
            name: Some("via jump".into()),
            kind: Some(RouteKind::Jump { hops: vec![hop] }),
        })
        .unwrap();
    assert_eq!(route.kind, RouteKind::Jump { hops: vec![hop] });

    let proxy = routes
        .update(
            route.meta.id,
            RouteChange {
                name: None,
                kind: Some(RouteKind::Socks5 {
                    proxy: "127.0.0.1:1080".into(),
                    credential: None,
                    username: None,
                }),
            },
        )
        .unwrap();
    assert_eq!(
        proxy.kind,
        RouteKind::Socks5 { proxy: "127.0.0.1:1080".into(), credential: None, username: None }
    );
    assert_eq!(proxy.name, "via jump");

    let credential = new_id();
    let authenticated = routes
        .update(
            route.meta.id,
            RouteChange {
                name: None,
                kind: Some(RouteKind::HttpConnect {
                    proxy: "127.0.0.1:8080".into(),
                    credential: Some(credential),
                    username: Some(" proxy-user ".into()),
                }),
            },
        )
        .unwrap();
    assert_eq!(
        authenticated.kind,
        RouteKind::HttpConnect {
            proxy: "127.0.0.1:8080".into(),
            credential: Some(credential),
            username: Some(" proxy-user ".into()),
        }
    );
    let cleared = routes
        .update(
            route.meta.id,
            RouteChange {
                name: None,
                kind: Some(RouteKind::Socks5 {
                    proxy: "127.0.0.1:1080".into(),
                    credential: None,
                    username: None,
                }),
            },
        )
        .unwrap();
    assert_eq!(cleared.kind, proxy.kind);
    let raw = store.get(route.meta.id).unwrap().unwrap();
    assert!(raw.set_field(5).is_none());
    assert!(raw.set_field(8).is_none());
}

#[test]
fn every_other_type_round_trips() {
    let (_dir, store) = store();
    let parent = Repository::<HostGroup>::new(&store)
        .create(HostGroupChange { name: Some("prod".into()), ..Default::default() })
        .unwrap();
    let child = Repository::<HostGroup>::new(&store)
        .create(HostGroupChange {
            name: Some("db".into()),
            parent: Edit::Set(parent.meta.id),
            defaults: BTreeMap::from([("username".into(), Some("postgres".into()))]),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(child.parent, Some(parent.meta.id));
    assert_eq!(child.defaults["username"], "postgres");

    let host = add_host(&store, "web");
    let trust = Repository::<TrustRecord>::new(&store)
        .create(TrustRecordChange {
            host: Edit::Set(host.meta.id),
            key: Edit::Set("ssh-ed25519 AAAA host".into()),
            fingerprint: Edit::Set("SHA256:abc".into()),
            provenance: Some(Provenance::Manual),
            accepted_at: Edit::Set(1_700_000_000_000),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(trust.provenance, Some(Provenance::Manual));
    assert!(!trust.revoked);

    let snippet = Repository::<Snippet>::new(&store)
        .create(SnippetChange {
            name: Some("tail".into()),
            template: Some("tail -n {{lines}} {{file}}".into()),
            variables: BTreeMap::from([
                (
                    "lines".into(),
                    Some(Variable {
                        kind: VariableKind::Integer,
                        default: Some("100".into()),
                        choices: vec![],
                    }),
                ),
                (
                    "file".into(),
                    Some(Variable {
                        kind: VariableKind::Choice,
                        default: None,
                        choices: vec!["a.log".into(), "b.log".into()],
                    }),
                ),
            ]),
            tags: BTreeMap::from([("logs".into(), true)]),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(snippet.variables["lines"].default.as_deref(), Some("100"));
    assert_eq!(snippet.variables["file"].choices, ["a.log", "b.log"]);
    assert!(snippet.tags.contains("logs"));

    let forward = Repository::<Forward>::new(&store)
        .create(ForwardChange {
            name: Some("pg".into()),
            kind: Some(ForwardKind::Local),
            bind_port: Edit::Set(5432),
            target_host: Edit::Set("localhost".into()),
            target_port: Edit::Set(5432),
            ..Default::default()
        })
        .unwrap();
    assert_eq!((forward.kind, forward.bind_port), (ForwardKind::Local, Some(5432)));

    let profile = new_id();
    let session = new_id();
    let workspace = Repository::<Workspace>::new(&store)
        .create(WorkspaceChange {
            name: Some("on call".into()),
            layout: Edit::Set(vec![1, 2, 3]),
            sessions: BTreeMap::from([(
                session,
                Some(SessionSpec {
                    profile,
                    kind: SessionKind::Terminal,
                    forward: None,
                    working_directory: Some("/var/log".into()),
                }),
            )]),
        })
        .unwrap();
    assert_eq!(workspace.sessions[&session].working_directory.as_deref(), Some("/var/log"));

    let preference = Repository::<Preference>::new(&store)
        .create(PreferenceChange {
            key: Some("terminal.font_size".into()),
            value: Edit::Set(Value::UInt(14)),
        })
        .unwrap();
    assert_eq!(preference.value, Some(Value::UInt(14)));
}

#[test]
fn gateway_networks_are_read_only_on_a_device() {
    let (_dir, store) = store();
    let networks = Repository::<GatewayNetwork>::new(&store);
    assert!(matches!(networks.create(NoChange), Err(RecordError::ReadOnly(_))));
    assert!(networks.list().unwrap().is_empty());
}

#[test]
fn records_are_checked_against_their_type() {
    let (_dir, store) = store();
    let host = add_host(&store, "a");
    let groups = Repository::<HostGroup>::new(&store);
    assert!(matches!(groups.get(host.meta.id), Err(RecordError::WrongType { .. })));
    assert!(matches!(
        groups
            .update(host.meta.id, HostGroupChange { name: Some("x".into()), ..Default::default() }),
        Err(RecordError::WrongType { .. })
    ));
    assert!(matches!(groups.delete(host.meta.id), Err(RecordError::WrongType { .. })));
}

#[test]
fn fields_this_build_does_not_know_survive_typed_changes() {
    let (_dir, store) = store();
    let host = add_host(&store, "future");
    store
        .write(LocalWrite {
            id: Some(host.meta.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(99), Value::Text("kept".into()))],
        })
        .unwrap();
    Repository::<Host>::new(&store)
        .update(host.meta.id, HostChange { name: Some("renamed".into()), ..Default::default() })
        .unwrap();
    let object = store.get(host.meta.id).unwrap().unwrap();
    assert_eq!(object.field(99).unwrap().value, Value::Text("kept".into()));
}

#[test]
fn deleted_records_disappear_and_a_later_change_restores_them() {
    let (_dir, store) = store();
    let hosts = Repository::<Host>::new(&store);
    let host = add_host(&store, "gone");
    hosts.delete(host.meta.id).unwrap();
    assert!(hosts.get(host.meta.id).unwrap().is_none());
    assert!(hosts.list().unwrap().is_empty());
    let restored = hosts
        .update(host.meta.id, HostChange { favorite: Some(true), ..Default::default() })
        .unwrap();
    assert!(restored.meta.restored);
    assert_eq!(hosts.list().unwrap().len(), 1);
}

#[test]
fn dynamic_forward_projection_ignores_irrelevant_fixed_target_fields_without_rewriting_them() {
    let (_dir, store) = store();
    let forward = Repository::<Forward>::new(&store)
        .create(ForwardChange {
            name: Some("SOCKS".into()),
            kind: Some(ForwardKind::Dynamic),
            bind_address: Edit::Set("127.0.0.1".into()),
            bind_port: Edit::Set(1080),
            ..Default::default()
        })
        .unwrap();
    store
        .write(LocalWrite {
            id: Some(forward.meta.id),
            object_type: ObjectType::FORWARD,
            fields: vec![
                (FieldPath::Field(5), Value::Text("unused.example".into())),
                (FieldPath::Field(6), Value::UInt(65536)),
            ],
        })
        .unwrap();
    let raw = store.get(forward.meta.id).unwrap().unwrap();
    let projected = Repository::<Forward>::new(&store).get(forward.meta.id).unwrap().unwrap();
    assert_eq!(projected.target_host, None);
    assert_eq!(projected.target_port, None);
    assert_eq!(store.get(forward.meta.id).unwrap().unwrap(), raw);
    assert_eq!(raw.field(6).unwrap().value, Value::UInt(65536));
}
