// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::repository::{
    AccessProfileChange, CredentialBinding, CredentialChange, CredentialKind, HostChange,
    RouteChange,
};
use crate::store::LocalWrite;
use scoplen_crypto::LocalDatabaseKey;
use scoplen_model::{FieldPath, MapKey};

fn fixture() -> (tempfile::TempDir, Arc<Store>, Workspaces, Uuid) {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::open(&directory.path().join("workspaces.db"), &LocalDatabaseKey::new([5; 32]))
            .unwrap(),
    );
    let profile = login(&store, "Production");
    let workspaces = Workspaces::new(store.clone());
    (directory, store, workspaces, profile)
}

fn login(store: &Store, name: &str) -> Uuid {
    let host = Repository::<Host>::new(store)
        .create(HostChange {
            name: Some(name.into()),
            address: Some("host.example".into()),
            ..Default::default()
        })
        .unwrap();
    let credential = Repository::<Credential>::new(store)
        .create(CredentialChange {
            kind: Some(CredentialKind::KeyboardInteractive),
            binding: Some(CredentialBinding::None),
            ..Default::default()
        })
        .unwrap();
    Repository::<AccessProfile>::new(store)
        .create(AccessProfileChange {
            host: Some(host.meta.id),
            username: Some("operator".into()),
            credential: Edit::Set(credential.meta.id),
            ..Default::default()
        })
        .unwrap()
        .meta
        .id
}

fn input(profiles: &[Uuid], active: Option<u32>) -> WorkspaceInput {
    WorkspaceInput {
        name: "Operations".into(),
        tabs: profiles
            .iter()
            .map(|id| WorkspaceTabInput {
                tree: WorkspaceTreeInput::Terminal { profile_id: id.to_string() },
                focused: 0,
            })
            .collect(),
        active,
    }
}

fn terminals(opened: &OpenedWorkspace) -> Vec<&WorkspaceTerminal> {
    fn collect<'a>(tree: &'a WorkspaceTree, output: &mut Vec<&'a WorkspaceTerminal>) {
        match tree {
            WorkspaceTree::Terminal { terminal } => output.push(terminal),
            WorkspaceTree::Split { first, second, .. } => {
                collect(first, output);
                collect(second, output);
            }
        }
    }
    let mut output = Vec::new();
    for tab in &opened.tabs {
        collect(&tab.tree, &mut output);
    }
    output
}

fn saved_leaf(id: Uuid) -> SavedTab {
    SavedTab { tree: SavedTree::Leaf(id), focused: id }
}

fn balanced(profile: Uuid, depth: usize) -> WorkspaceTreeInput {
    if depth == 0 {
        return WorkspaceTreeInput::Terminal { profile_id: profile.to_string() };
    }
    WorkspaceTreeInput::Split {
        direction: if depth.is_multiple_of(2) {
            WorkspaceSplitDirection::Vertical
        } else {
            WorkspaceSplitDirection::Horizontal
        },
        first: Box::new(balanced(profile, depth - 1)),
        second: Box::new(balanced(profile, depth - 1)),
    }
}

#[test]
fn split_trees_keep_both_directions_all_tab_focus_and_fresh_sessions_after_reopen() {
    let (directory, store, workspaces, profile) = fixture();
    let saved = workspaces
        .create(WorkspaceInput {
            name: "Split operations".into(),
            tabs: vec![
                WorkspaceTabInput { tree: balanced(profile, 2), focused: 2 },
                WorkspaceTabInput { tree: balanced(profile, 1), focused: 1 },
            ],
            active: Some(0),
        })
        .unwrap();
    let record = store.get(Uuid::parse_str(&saved.id).unwrap()).unwrap().unwrap();
    let (workspace, tabs, active) = definition(&record).unwrap();
    assert_eq!(active, Some(0));
    assert_eq!(workspace.sessions.len(), 6);
    assert_eq!(workspace.layout.as_ref().unwrap(), &encode_layout(&tabs, active).unwrap());
    let first = workspaces.open(&saved.id).unwrap();
    let panes = terminals(&first);
    assert_eq!(first.tabs[0].focused_session_id, panes[2].session_id);
    assert_eq!(first.tabs[1].focused_session_id, panes[5].session_id);
    assert!(panes.iter().all(|pane| pane.profile_id == profile.to_string()));
    assert!(matches!(
        first.tabs[0].tree,
        WorkspaceTree::Split { direction: WorkspaceSplitDirection::Vertical, .. }
    ));
    assert!(matches!(
        first.tabs[1].tree,
        WorkspaceTree::Split { direction: WorkspaceSplitDirection::Horizontal, .. }
    ));
    drop(workspaces);
    drop(store);
    let reopened_store = Arc::new(
        Store::open(&directory.path().join("workspaces.db"), &LocalDatabaseKey::new([5; 32]))
            .unwrap(),
    );
    let reopened = Workspaces::new(reopened_store.clone());
    let second = reopened.open(&saved.id).unwrap();
    assert_eq!(second.active, Some(0));
    assert_eq!(terminals(&second).len(), 6);
    assert!(
        terminals(&second)
            .iter()
            .all(|pane| panes.iter().all(|old| old.session_id != pane.session_id))
    );
    assert!(reopened_store.recent_sessions(10).unwrap().is_empty());
    assert_eq!(
        reopened_store.get(record.id).unwrap().unwrap().encode().unwrap(),
        record.encode().unwrap()
    );
}

#[test]
fn pane_depth_count_focus_and_definition_bounds_are_enforced_before_persistence() {
    let (_directory, store, workspaces, profile) = fixture();
    let full_tab = WorkspaceTabInput { tree: balanced(profile, 3), focused: 7 };
    let full = workspaces
        .create(WorkspaceInput {
            name: "Full".into(),
            tabs: vec![full_tab.clone(); 8],
            active: Some(7),
        })
        .unwrap();
    assert_eq!(terminals(&workspaces.open(&full.id).unwrap()).len(), 64);
    assert_eq!(
        workspaces.create(WorkspaceInput {
            name: "Too many".into(),
            tabs: vec![full_tab.clone(); 9],
            active: None
        }),
        Err(WorkspaceIssue::DefinitionTooLarge)
    );
    assert_eq!(
        workspaces.create(WorkspaceInput {
            name: "Too deep".into(),
            tabs: vec![WorkspaceTabInput { tree: balanced(profile, 4), focused: 0 }],
            active: None
        }),
        Err(WorkspaceIssue::DefinitionTooLarge)
    );
    assert_eq!(
        workspaces.create(WorkspaceInput {
            name: "Bad focus".into(),
            tabs: vec![WorkspaceTabInput { focused: 8, ..full_tab }],
            active: None
        }),
        Err(WorkspaceIssue::InvalidActive)
    );
    assert_eq!(store.list(ObjectType::WORKSPACE).unwrap().len(), 1);
}

#[test]
fn exact_v2_shapes_and_old_v1_layouts_remain_unchanged_unavailable_and_deletable() {
    let (_directory, store, workspaces, profile) = fixture();
    let saved = workspaces.create(input(&[profile], None)).unwrap();
    let id = Uuid::parse_str(&saved.id).unwrap();
    let object = store.get(id).unwrap().unwrap();
    let (_, tabs, _) = definition(&object).unwrap();
    let slot = tabs[0].focused;
    let leaf = Value::Bytes(slot.as_bytes().to_vec());
    let foreign = Value::Bytes(Uuid::now_v7().as_bytes().to_vec());
    let envelope = |tab: Value, active: Value| {
        Value::Map(vec![
            (Value::UInt(1), Value::UInt(2)),
            (Value::UInt(2), Value::Array(vec![tab])),
            (Value::UInt(3), active),
        ])
    };
    let mut layouts = vec![
        Value::Map(vec![
            (Value::UInt(1), Value::UInt(1)),
            (Value::UInt(2), Value::Array(vec![leaf.clone()])),
            (Value::UInt(3), Value::Null),
        ]),
        envelope(Value::Array(vec![leaf.clone(), foreign]), Value::Null),
        envelope(Value::Array(vec![leaf.clone(), leaf.clone(), Value::Null]), Value::Null),
        envelope(Value::Array(vec![leaf.clone()]), Value::Null),
        envelope(Value::Array(vec![leaf.clone(), leaf.clone()]), Value::UInt(1)),
        envelope(Value::Array(vec![leaf.clone(), leaf.clone()]), Value::Bytes(vec![0; 16])),
    ];
    for branch in [
        vec![Value::UInt(2), leaf.clone(), leaf.clone()],
        vec![Value::UInt(0), leaf.clone()],
        vec![Value::UInt(1), leaf.clone(), leaf.clone(), leaf.clone()],
        vec![Value::UInt(0), leaf.clone(), leaf.clone()],
    ] {
        layouts.push(envelope(Value::Array(vec![Value::Array(branch), leaf.clone()]), Value::Null));
    }
    for malformed_leaf in [
        Value::Bytes(vec![0; 16]),
        Value::Bytes(vec![0; 15]),
        Value::Text(slot.to_string()),
        Value::Null,
    ] {
        layouts.push(envelope(Value::Array(vec![malformed_leaf, leaf.clone()]), Value::Null));
    }
    for layout in layouts {
        rewrite(
            &store,
            &saved.id,
            vec![(FieldPath::Field(2), Value::Bytes(cbor::encode(&layout).unwrap()))],
        );
        let before = store.get(id).unwrap().unwrap().encode().unwrap();
        assert_eq!(workspaces.open(&saved.id), Err(WorkspaceIssue::UnsupportedLayout));
        assert_eq!(workspaces.list().unwrap()[0].issue, Some(WorkspaceIssue::UnsupportedLayout));
        assert_eq!(store.get(id).unwrap().unwrap().encode().unwrap(), before);
    }
    workspaces.delete(&saved.id).unwrap();
    assert!(store.get(id).unwrap().unwrap().is_tombstoned());
}

#[test]
fn stored_complete_definitions_enforce_depth_and_total_leaf_limits() {
    let (_directory, store, workspaces, profile) = fixture();
    let deep = workspaces.create(input(&[profile; 8], None)).unwrap();
    let object = store.get(Uuid::parse_str(&deep.id).unwrap()).unwrap().unwrap();
    let (_, tabs, _) = definition(&object).unwrap();
    let focused = tabs[0].focused;
    let mut skewed = tabs[7].tree.clone();
    for tab in tabs[..7].iter().rev() {
        skewed = SavedTree::Split(
            WorkspaceSplitDirection::Horizontal,
            Box::new(tab.tree.clone()),
            Box::new(skewed),
        );
    }
    rewrite(
        &store,
        &deep.id,
        vec![(
            FieldPath::Field(2),
            Value::Bytes(encode_layout(&[SavedTab { tree: skewed, focused }], None).unwrap()),
        )],
    );
    assert_eq!(workspaces.open(&deep.id), Err(WorkspaceIssue::UnsupportedLayout));

    let full = workspaces.create(input(&[profile; 64], None)).unwrap();
    let object = store.get(Uuid::parse_str(&full.id).unwrap()).unwrap().unwrap();
    let (_, mut tabs, _) = definition(&object).unwrap();
    let extra = Uuid::now_v7();
    tabs.push(saved_leaf(extra));
    Repository::<Workspace>::new(&store)
        .update(
            object.id,
            WorkspaceChange {
                layout: Edit::Set(encode_layout(&tabs, None).unwrap()),
                sessions: BTreeMap::from([(
                    extra,
                    Some(SessionSpec {
                        profile,
                        kind: SessionKind::Terminal,
                        forward: None,
                        working_directory: None,
                    }),
                )]),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(workspaces.open(&full.id), Err(WorkspaceIssue::UnsupportedLayout));
    let views = workspaces.list().unwrap();
    assert!(views.iter().all(|view| view.issue == Some(WorkspaceIssue::UnsupportedLayout)));
}

fn rewrite(store: &Store, id: &str, fields: Vec<(FieldPath, Value)>) {
    store
        .write(LocalWrite {
            id: Some(Uuid::parse_str(id).unwrap()),
            object_type: ObjectType::WORKSPACE,
            fields,
        })
        .unwrap();
}

#[test]
fn facade_retains_order_duplicates_and_hosts_selection_across_sqlcipher_reopen() {
    let (directory, store, workspaces, first) = fixture();
    let second = login(&store, "Staging");
    let saved = workspaces.create(input(&[second, first, second], Some(1))).unwrap();
    let hosts = workspaces.create(input(&[first], None)).unwrap();
    let object = store.get(Uuid::parse_str(&saved.id).unwrap()).unwrap().unwrap();
    let (record, order, active) = definition(&object).unwrap();
    let slots = order.iter().map(|tab| tab.focused).collect::<Vec<_>>();
    assert_eq!(active, Some(1));
    assert_eq!(
        slots.iter().map(|slot| record.sessions[slot].profile).collect::<Vec<_>>(),
        [second, first, second]
    );
    let encoded = record.layout.unwrap();
    assert_eq!(encoded, encode_layout(&order, active).unwrap());
    assert_eq!(&encoded[..7], &[0xa3, 0x01, 0x02, 0x02, 0x83, 0x82, 0x50]);
    let before = workspaces.open(&saved.id).unwrap();
    assert_eq!(before.active, Some(1));
    assert_eq!(terminals(&before)[0].label, "Staging · operator");
    assert!(
        terminals(&before)
            .iter()
            .all(|tab| !slots.iter().any(|slot| slot.to_string() == tab.session_id))
    );
    assert!(store.recent_sessions(10).unwrap().is_empty());
    drop(workspaces);
    drop(store);
    let reopened_store = Arc::new(
        Store::open(&directory.path().join("workspaces.db"), &LocalDatabaseKey::new([5; 32]))
            .unwrap(),
    );
    let reopened = Workspaces::new(reopened_store.clone());
    assert_eq!(reopened.list().unwrap().len(), 2);
    let after = reopened.open(&saved.id).unwrap();
    assert_eq!(
        terminals(&after).iter().map(|tab| tab.profile_id.clone()).collect::<Vec<_>>(),
        [second.to_string(), first.to_string(), second.to_string()]
    );
    assert_eq!(after.active, Some(1));
    assert!(
        terminals(&after)
            .iter()
            .all(|tab| terminals(&before).iter().all(|old| old.session_id != tab.session_id))
    );
    assert_eq!(reopened.open(&hosts.id).unwrap().active, None);
    assert!(reopened_store.recent_sessions(10).unwrap().is_empty());
    reopened.delete(&saved.id).unwrap();
    assert_eq!(reopened.open(&saved.id), Err(WorkspaceIssue::NotFound));
    assert!(
        reopened_store.get(Uuid::parse_str(&saved.id).unwrap()).unwrap().unwrap().is_tombstoned()
    );
}

#[test]
fn save_refuses_offline_output_empty_tabs_bad_indices_names_ids_and_existing_limits() {
    let (_directory, store, workspaces, profile) = fixture();
    assert_eq!(workspaces.create(input(&[], None)), Err(WorkspaceIssue::EmptyTabs));
    let mut draft = input(&[profile], None);
    draft.tabs.push(WorkspaceTabInput { tree: WorkspaceTreeInput::SavedOutput, focused: 0 });
    assert_eq!(workspaces.create(draft), Err(WorkspaceIssue::SavedOutputUnsupported));
    assert_eq!(workspaces.create(input(&[profile], Some(1))), Err(WorkspaceIssue::InvalidActive));
    for name in [" ".into(), "a".repeat(MAX_TEXT_BYTES + 1)] {
        let mut draft = input(&[profile], None);
        draft.name = name;
        assert_eq!(workspaces.create(draft), Err(WorkspaceIssue::InvalidName));
    }
    let mut draft = input(&[profile], None);
    draft.tabs = vec![WorkspaceTabInput {
        tree: WorkspaceTreeInput::Terminal { profile_id: "bad".into() },
        focused: 0,
    }];
    assert_eq!(workspaces.create(draft), Err(WorkspaceIssue::InvalidId));
    assert_eq!(
        encode_layout(&vec![saved_leaf(profile); MAX_WORKSPACE_LAYOUT_BYTES / 16], None),
        Err(WorkspaceIssue::DefinitionTooLarge)
    );
    assert!(store.list(ObjectType::WORKSPACE).unwrap().is_empty());
}

#[test]
fn unsupported_layouts_stay_byte_identical_and_deletable_without_hiding_good_entries() {
    let (_directory, store, workspaces, profile) = fixture();
    let good = workspaces.create(input(&[profile], None)).unwrap();
    let bad = workspaces.create(input(&[profile], None)).unwrap();
    let valid = store.get(Uuid::parse_str(&bad.id).unwrap()).unwrap().unwrap();
    let (_, slots, _) = definition(&valid).unwrap();
    let Value::Bytes(layout_bytes) = &valid.set_field(2).unwrap().value else { panic!() };
    let canonical = cbor::decode(layout_bytes).unwrap();
    let Value::Map(mut future) = canonical.clone() else { panic!() };
    future[0].1 = Value::UInt(3);
    let Value::Map(mut unknown) = canonical.clone() else { panic!() };
    unknown.push((Value::UInt(4), Value::Null));
    let mut cases = vec![
        Value::Null,
        Value::Bytes(Vec::new()),
        Value::Bytes(vec![0xff]),
        Value::Bytes(cbor::encode(&Value::Map(future)).unwrap()),
        Value::Bytes(cbor::encode(&Value::Map(unknown)).unwrap()),
        Value::Bytes(encode_layout(&[slots[0].clone(), slots[0].clone()], None).unwrap()),
        Value::Bytes(encode_layout(&[saved_leaf(Uuid::now_v7())], None).unwrap()),
        Value::Bytes(encode_layout(&slots, Some(1)).unwrap()),
        Value::Bytes(encode_layout(&[], None).unwrap()),
    ];
    for layout in cases.drain(..) {
        rewrite(&store, &bad.id, vec![(FieldPath::Field(2), layout)]);
        let id = Uuid::parse_str(&bad.id).unwrap();
        let before = store.get(id).unwrap().unwrap().encode().unwrap();
        let listed = workspaces.list().unwrap();
        assert!(listed.iter().any(|view| view.id == good.id && view.issue.is_none()));
        assert_eq!(
            listed.iter().find(|view| view.id == bad.id).unwrap().issue,
            Some(WorkspaceIssue::UnsupportedLayout)
        );
        assert_eq!(workspaces.open(&bad.id), Err(WorkspaceIssue::UnsupportedLayout));
        assert_eq!(store.get(id).unwrap().unwrap().encode().unwrap(), before);
    }
    workspaces.delete(&bad.id).unwrap();
    assert!(store.get(Uuid::parse_str(&bad.id).unwrap()).unwrap().unwrap().is_tombstoned());
}

#[test]
fn session_kinds_and_any_forward_or_cwd_are_retained_unavailable() {
    let (_directory, store, workspaces, profile) = fixture();
    for (kind, directory) in [
        (SessionKind::Files, None),
        (SessionKind::Forward, None),
        (SessionKind::Terminal, Some("")),
        (SessionKind::Terminal, Some("/srv")),
    ] {
        let saved = workspaces.create(input(&[profile], None)).unwrap();
        let object = store.get(Uuid::parse_str(&saved.id).unwrap()).unwrap().unwrap();
        let (_, slots, _) = definition(&object).unwrap();
        let mut fields = vec![
            (Value::UInt(1), Value::Bytes(profile.as_bytes().to_vec())),
            (Value::UInt(2), Value::UInt(kind as u64)),
        ];
        if kind == SessionKind::Forward {
            fields.push((Value::UInt(3), Value::Bytes(Uuid::now_v7().as_bytes().to_vec())));
        }
        if let Some(directory) = directory {
            fields.push((Value::UInt(4), Value::Text(directory.into())));
        }
        rewrite(
            &store,
            &saved.id,
            vec![(
                FieldPath::map_entry(3, MapKey::Bytes(slots[0].focused.as_bytes().to_vec()))
                    .unwrap(),
                Value::Map(fields),
            )],
        );
        assert_eq!(workspaces.open(&saved.id), Err(WorkspaceIssue::UnsupportedLayout));
        assert_eq!(
            workspaces.list().unwrap().iter().find(|view| view.id == saved.id).unwrap().issue,
            Some(WorkspaceIssue::UnsupportedLayout)
        );
        workspaces.delete(&saved.id).unwrap();
    }
}

#[test]
fn missing_tombstoned_and_wrong_type_dependencies_never_partially_open_or_fallback() {
    for target in
        [ObjectType::ACCESS_PROFILE, ObjectType::HOST, ObjectType::CREDENTIAL, ObjectType::ROUTE]
    {
        let (_directory, store, workspaces, first) = fixture();
        let second = login(&store, "Other");
        let route = Repository::<Route>::new(&store)
            .create(RouteChange {
                name: Some("Proxy".into()),
                kind: Some(RouteKind::Command { command: "proxy %h %p".into() }),
            })
            .unwrap();
        let profile = Repository::<AccessProfile>::new(&store)
            .update(
                second,
                AccessProfileChange {
                    route: Some(RouteChoice::Route(route.meta.id)),
                    ..Default::default()
                },
            )
            .unwrap();
        let saved = workspaces.create(input(&[first, second], Some(0))).unwrap();
        let lost = match target {
            ObjectType::ACCESS_PROFILE => second,
            ObjectType::HOST => profile.host,
            ObjectType::CREDENTIAL => profile.credential.unwrap(),
            _ => route.meta.id,
        };
        store.delete(lost).unwrap();
        assert_eq!(workspaces.open(&saved.id), Err(WorkspaceIssue::MissingDependency));
        assert_eq!(workspaces.list().unwrap()[0].issue, Some(WorkspaceIssue::MissingDependency));
        assert!(store.recent_sessions(10).unwrap().is_empty());
    }
    let (_directory, store, workspaces, profile) = fixture();
    let saved = workspaces.create(input(&[profile], None)).unwrap();
    let host = Repository::<AccessProfile>::new(&store).get(profile).unwrap().unwrap().host;
    Repository::<AccessProfile>::new(&store)
        .update(profile, AccessProfileChange { credential: Edit::Set(host), ..Default::default() })
        .unwrap();
    assert_eq!(workspaces.open(&saved.id), Err(WorkspaceIssue::MissingDependency));
}

#[test]
fn foreign_inventory_dependencies_are_unavailable_and_new_saves_are_local() {
    for target in
        [ObjectType::ACCESS_PROFILE, ObjectType::HOST, ObjectType::CREDENTIAL, ObjectType::ROUTE]
    {
        let (directory, store, workspaces, profile) = fixture();
        let route = Repository::<Route>::new(&store)
            .create(RouteChange {
                name: Some("Proxy".into()),
                kind: Some(RouteKind::Command { command: "proxy %h %p".into() }),
            })
            .unwrap();
        let profile_record = Repository::<AccessProfile>::new(&store)
            .update(
                profile,
                AccessProfileChange {
                    route: Some(RouteChoice::Route(route.meta.id)),
                    ..Default::default()
                },
            )
            .unwrap();
        let saved = workspaces.create(input(&[profile], None)).unwrap();
        assert_eq!(store.object_vault(Uuid::parse_str(&saved.id).unwrap()).unwrap(), None);
        let foreign = match target {
            ObjectType::ACCESS_PROFILE => profile,
            ObjectType::HOST => profile_record.host,
            ObjectType::CREDENTIAL => profile_record.credential.unwrap(),
            _ => route.meta.id,
        };
        let conn = rusqlite::Connection::open(directory.path().join("workspaces.db")).unwrap();
        conn.pragma_update(None, "key", format!("x'{}'", "05".repeat(32))).unwrap();
        conn.execute(
            "UPDATE objects SET vault=?1 WHERE id=?2",
            rusqlite::params![Uuid::now_v7().as_bytes().as_slice(), foreign.as_bytes().as_slice()],
        )
        .unwrap();
        assert_eq!(workspaces.open(&saved.id), Err(WorkspaceIssue::ForeignDependency));
        assert_eq!(workspaces.list().unwrap()[0].issue, Some(WorkspaceIssue::ForeignDependency));
        assert_eq!(
            workspaces.create(input(&[profile], None)),
            Err(WorkspaceIssue::ForeignDependency)
        );
    }
}

#[test]
fn ordinary_login_without_selected_credential_keeps_existing_connection_semantics() {
    let (_directory, store, workspaces, profile) = fixture();
    Repository::<AccessProfile>::new(&store)
        .update(profile, AccessProfileChange { credential: Edit::Clear, ..Default::default() })
        .unwrap();
    let saved = workspaces.create(input(&[profile], None)).unwrap();
    assert_eq!(terminals(&workspaces.open(&saved.id).unwrap())[0].profile_id, profile.to_string());
}

#[test]
fn foreign_workspace_metadata_is_hidden_and_open_and_delete_are_refused() {
    let (directory, store, workspaces, profile) = fixture();
    let saved = workspaces.create(input(&[profile], Some(0))).unwrap();
    let id = Uuid::parse_str(&saved.id).unwrap();
    let conn = rusqlite::Connection::open(directory.path().join("workspaces.db")).unwrap();
    conn.pragma_update(None, "key", format!("x'{}'", "05".repeat(32))).unwrap();
    conn.execute(
        "UPDATE objects SET vault=?1 WHERE id=?2",
        rusqlite::params![Uuid::now_v7().as_bytes().as_slice(), id.as_bytes().as_slice()],
    )
    .unwrap();
    let before = store.get(id).unwrap().unwrap().encode().unwrap();
    assert!(workspaces.list().unwrap().is_empty());
    assert_eq!(workspaces.open(&saved.id), Err(WorkspaceIssue::ForeignDependency));
    assert_eq!(workspaces.delete(&saved.id), Err(WorkspaceIssue::ForeignDependency));
    assert_eq!(store.get(id).unwrap().unwrap().encode().unwrap(), before);
}
