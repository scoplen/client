// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::repository::{Forward, ForwardChange, ForwardKind};

fn saved(store: &Store, kind: ForwardKind, default: Option<Uuid>) -> Uuid {
    Repository::<Forward>::new(store)
        .create(ForwardChange {
            name: Some(format!("{kind:?} tunnel")),
            kind: Some(kind),
            bind_address: Edit::Set("127.0.0.1".into()),
            bind_port: Edit::Set(1080),
            target_host: if kind == ForwardKind::Dynamic {
                Edit::Clear
            } else {
                Edit::Set("service.example".into())
            },
            target_port: if kind == ForwardKind::Dynamic { Edit::Clear } else { Edit::Set(443) },
            profile: default.map_or(Edit::Clear, Edit::Set),
        })
        .unwrap()
        .meta
        .id
}

fn selection(id: Uuid, profile: Uuid) -> WorkspaceForwardInput {
    WorkspaceForwardInput { forward_id: id.to_string(), profile_id: profile.to_string() }
}

fn foreign(directory: &tempfile::TempDir, id: Uuid) {
    let conn = rusqlite::Connection::open(directory.path().join("workspaces.db")).unwrap();
    conn.pragma_update(None, "key", format!("x'{}'", "05".repeat(32))).unwrap();
    conn.execute(
        "UPDATE objects SET vault=?1 WHERE id=?2",
        rusqlite::params![Uuid::now_v7().as_bytes().as_slice(), id.as_bytes().as_slice()],
    )
    .unwrap();
}

#[test]
fn mixed_reopen_preserves_order_explicit_logins_references_and_deterministic_bytes() {
    let (directory, store, workspaces, first) = fixture();
    let second = login(&store, "Staging");
    let unused = login(&store, "Unused default");
    foreign(&directory, unused);
    let ids = [ForwardKind::Remote, ForwardKind::Local, ForwardKind::Dynamic]
        .map(|kind| saved(&store, kind, Some(unused)));
    let mut draft = input(&[first, second], Some(1));
    draft.forwards = ids.iter().map(|id| selection(*id, second)).collect();
    let saved = workspaces.create(draft).unwrap();
    assert_eq!((saved.tab_count, saved.forward_count), (2, 3));
    assert_eq!(store.object_vault(Uuid::parse_str(&saved.id).unwrap()).unwrap(), None);
    let object = store.get(Uuid::parse_str(&saved.id).unwrap()).unwrap().unwrap();
    let (record, layout) = definition(&object).unwrap();
    assert_eq!(record.sessions.len(), 5);
    assert_eq!(
        record.layout.as_ref().unwrap(),
        &encode_layout(&layout.tabs, layout.active, &layout.forwards).unwrap()
    );
    let Value::Map(fields) = cbor::decode(record.layout.as_ref().unwrap()).unwrap() else {
        panic!()
    };
    assert_eq!(fields[0], (Value::UInt(1), Value::UInt(3)));
    assert_eq!(fields.len(), 4);
    for (slot, id) in layout.forwards.iter().zip(ids) {
        let session = &record.sessions[slot];
        assert_eq!(session.kind, SessionKind::Forward);
        assert_eq!(session.profile, second);
        assert_eq!(session.forward, Some(id));
        assert_eq!(session.working_directory, None);
        assert_eq!(slot.get_version_num(), 7);
    }
    let before = workspaces.open(&saved.id).unwrap();
    assert_eq!(
        before.forwards.iter().map(|item| item.forward_id.clone()).collect::<Vec<_>>(),
        ids.map(|id| id.to_string())
    );
    assert!(before.forwards.iter().all(|item| item.profile_id == second.to_string() && item.label == "Staging · operator"));
    assert_eq!(before.active, Some(1));
    assert!(workspaces.list().unwrap()[0].issue.is_none());
    Repository::<Forward>::new(&store)
        .update(ids[0], ForwardChange { profile: Edit::Set(first), ..Default::default() })
        .unwrap();
    store.delete(unused).unwrap();
    drop(workspaces);
    drop(store);
    let reopened_store = Arc::new(
        Store::open(&directory.path().join("workspaces.db"), &LocalDatabaseKey::new([5; 32]))
            .unwrap(),
    );
    let reopened = Workspaces::new(reopened_store.clone());
    let after = reopened.open(&saved.id).unwrap();
    assert_eq!(after.forwards, before.forwards);
    assert_eq!(after.active, before.active);
    assert!(
        terminals(&after)
            .iter()
            .all(|pane| terminals(&before).iter().all(|old| pane.session_id != old.session_id))
    );
    assert_eq!(
        reopened_store.get(object.id).unwrap().unwrap().encode().unwrap(),
        object.encode().unwrap()
    );
    assert_eq!(reopened_store.list(ObjectType::FORWARD).unwrap().len(), 3);
    assert!(reopened_store.recent_sessions(10).unwrap().is_empty());
}

#[test]
fn tunnel_only_and_combined_limits_require_explicit_unique_saved_definitions() {
    let (_directory, store, workspaces, profile) = fixture();
    let ids: Vec<_> = (0..17).map(|_| saved(&store, ForwardKind::Dynamic, None)).collect();
    let mut draft = input(&[], None);
    draft.forwards = ids[..16].iter().map(|id| selection(*id, profile)).collect();
    let view = workspaces.create(draft.clone()).unwrap();
    assert_eq!((view.tab_count, view.forward_count), (0, 16));
    let opened = workspaces.open(&view.id).unwrap();
    assert!(opened.tabs.is_empty());
    assert_eq!(opened.active, None);
    assert_eq!(opened.forwards.len(), 16);
    draft.active = Some(0);
    assert_eq!(workspaces.create(draft.clone()), Err(WorkspaceIssue::InvalidActive));
    draft.active = None;
    draft.forwards.push(selection(ids[16], profile));
    assert_eq!(workspaces.create(draft.clone()), Err(WorkspaceIssue::DefinitionTooLarge));
    draft.forwards.pop();
    draft.forwards[1] = selection(ids[0], profile);
    assert_eq!(workspaces.create(draft), Err(WorkspaceIssue::UnsupportedLayout));
    let mut combined = input(&[profile; 48], Some(47));
    combined.forwards = ids[..16].iter().map(|id| selection(*id, profile)).collect();
    let full = workspaces.create(combined.clone()).unwrap();
    assert_eq!(workspaces.open(&full.id).unwrap().forwards.len(), 16);
    combined.tabs.push(WorkspaceTabInput {
        tree: WorkspaceTreeInput::Terminal { profile_id: profile.to_string() },
        focused: 0,
    });
    assert_eq!(workspaces.create(combined), Err(WorkspaceIssue::DefinitionTooLarge));
    let mut unknown = input(&[], None);
    unknown.forwards.push(selection(Uuid::now_v7(), profile));
    assert_eq!(workspaces.create(unknown), Err(WorkspaceIssue::MissingDependency));
    assert_eq!(store.list(ObjectType::WORKSPACE).unwrap().len(), 2);
}

#[test]
fn actual_forward_dependencies_refuse_the_entire_mixed_open_without_mutation() {
    for target in [
        ObjectType::FORWARD,
        ObjectType::ACCESS_PROFILE,
        ObjectType::HOST,
        ObjectType::CREDENTIAL,
        ObjectType::ROUTE,
    ] {
        for foreign_owner in [false, true] {
            let (directory, store, workspaces, terminal) = fixture();
            let profile = login(&store, "Selected tunnel Login");
            let route = Repository::<Route>::new(&store)
                .create(RouteChange {
                    name: Some("Proxy".into()),
                    kind: Some(RouteKind::Command { command: "proxy %h %p".into() }),
                })
                .unwrap();
            let login = Repository::<AccessProfile>::new(&store)
                .update(
                    profile,
                    AccessProfileChange {
                        route: Some(RouteChoice::Route(route.meta.id)),
                        ..Default::default()
                    },
                )
                .unwrap();
            let forward = saved(&store, ForwardKind::Local, None);
            let mut draft = input(&[terminal], Some(0));
            draft.forwards.push(selection(forward, profile));
            let view = workspaces.create(draft).unwrap();
            let before =
                store.get(Uuid::parse_str(&view.id).unwrap()).unwrap().unwrap().encode().unwrap();
            let id = match target {
                ObjectType::FORWARD => forward,
                ObjectType::ACCESS_PROFILE => profile,
                ObjectType::HOST => login.host,
                ObjectType::CREDENTIAL => login.credential.unwrap(),
                _ => route.meta.id,
            };
            if foreign_owner {
                foreign(&directory, id);
            } else {
                store.delete(id).unwrap();
            }
            assert!(matches!(
                workspaces.open(&view.id),
                Err(WorkspaceIssue::MissingDependency | WorkspaceIssue::ForeignDependency)
            ));
            assert!(workspaces.list().unwrap()[0].issue.is_some());
            assert_eq!(
                store.get(Uuid::parse_str(&view.id).unwrap()).unwrap().unwrap().encode().unwrap(),
                before
            );
            assert!(store.recent_sessions(10).unwrap().is_empty());
        }
    }
}

#[test]
fn unusable_actual_saved_configuration_refuses_capture_and_all_opening_intents() {
    let (_directory, store, workspaces, profile) = fixture();
    let forward = saved(&store, ForwardKind::Local, None);
    let mut draft = input(&[profile], Some(0));
    draft.forwards.push(selection(forward, profile));
    let view = workspaces.create(draft.clone()).unwrap();
    Repository::<Forward>::new(&store)
        .update(
            forward,
            ForwardChange {
                bind_address: Edit::Set("not-an-address".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(workspaces.open(&view.id), Err(WorkspaceIssue::MissingDependency));
    assert_eq!(workspaces.list().unwrap()[0].issue, Some(WorkspaceIssue::MissingDependency));
    assert_eq!(workspaces.create(draft), Err(WorkspaceIssue::MissingDependency));
    assert_eq!(store.list(ObjectType::WORKSPACE).unwrap().len(), 1);
}

#[test]
fn distinct_slots_cannot_reference_the_same_saved_forward_twice() {
    let (_directory, store, workspaces, profile) = fixture();
    let first = saved(&store, ForwardKind::Local, None);
    let second = saved(&store, ForwardKind::Remote, None);
    let mut draft = input(&[], None);
    draft.forwards = vec![selection(first, profile), selection(second, profile)];
    let view = workspaces.create(draft).unwrap();
    let id = Uuid::parse_str(&view.id).unwrap();
    let (_, layout) = definition(&store.get(id).unwrap().unwrap()).unwrap();
    Repository::<Workspace>::new(&store)
        .update(
            id,
            WorkspaceChange {
                sessions: BTreeMap::from([(
                    layout.forwards[1],
                    Some(SessionSpec {
                        profile,
                        kind: SessionKind::Forward,
                        forward: Some(first),
                        working_directory: None,
                    }),
                )]),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(workspaces.open(&view.id), Err(WorkspaceIssue::UnsupportedLayout));
    assert_eq!(workspaces.list().unwrap()[0].issue, Some(WorkspaceIssue::UnsupportedLayout));
}

#[test]
fn unavailable_forward_shapes_and_slot_mismatches_stay_byte_identical() {
    let (_directory, store, workspaces, profile) = fixture();
    let forward = saved(&store, ForwardKind::Dynamic, None);
    let mut draft = input(&[profile], Some(0));
    draft.forwards.push(selection(forward, profile));
    let view = workspaces.create(draft).unwrap();
    let id = Uuid::parse_str(&view.id).unwrap();
    let object = store.get(id).unwrap().unwrap();
    let (record, layout) = definition(&object).unwrap();
    let bytes = record.layout.unwrap();
    let Value::Map(fields) = cbor::decode(&bytes).unwrap() else { panic!() };
    let terminal = layout.tabs[0].focused;
    let tunnel = layout.forwards[0];
    for slots in [
        vec![],
        vec![Value::Bytes(tunnel.as_bytes().to_vec()); 2],
        vec![Value::Bytes(terminal.as_bytes().to_vec())],
        vec![Value::Bytes(Uuid::now_v7().as_bytes().to_vec())],
        vec![Value::Text(tunnel.to_string())],
        vec![Value::Bytes(vec![0; 15])],
        vec![Value::Bytes(tunnel.as_bytes().to_vec()); 17],
    ] {
        let mut broken = fields.clone();
        broken[3].1 = Value::Array(slots);
        rewrite(
            &store,
            &view.id,
            vec![(FieldPath::Field(2), Value::Bytes(cbor::encode(&Value::Map(broken)).unwrap()))],
        );
        let before = store.get(id).unwrap().unwrap().encode().unwrap();
        assert_eq!(workspaces.open(&view.id), Err(WorkspaceIssue::UnsupportedLayout));
        assert_eq!(store.get(id).unwrap().unwrap().encode().unwrap(), before);
    }
    rewrite(&store, &view.id, vec![(FieldPath::Field(2), Value::Bytes(bytes))]);
    for (kind, forward, directory) in [
        (SessionKind::Terminal, None, None),
        (SessionKind::Files, None, None),
        (SessionKind::Forward, Some(forward), Some("/srv".into())),
    ] {
        Repository::<Workspace>::new(&store)
            .update(
                id,
                WorkspaceChange {
                    sessions: BTreeMap::from([(
                        tunnel,
                        Some(SessionSpec { profile, kind, forward, working_directory: directory }),
                    )]),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(workspaces.open(&view.id), Err(WorkspaceIssue::UnsupportedLayout));
    }
    workspaces.delete(&view.id).unwrap();
    assert!(store.get(id).unwrap().unwrap().is_tombstoned());
}
