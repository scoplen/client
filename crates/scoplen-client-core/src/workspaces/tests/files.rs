// SPDX-License-Identifier: Apache-2.0

use super::*;

fn open(profile: Uuid, path: Vec<u8>) -> WorkspaceTreeInput {
    WorkspaceTreeInput::Terminal {
        profile_id: profile.to_string(),
        files: WorkspaceFilesInput::Open { path },
    }
}

#[test]
fn files_intent_preserves_opaque_directories_and_closed_panes_across_store_reopen() {
    let (directory, store, workspaces, profile) = fixture();
    let opaque = vec![b'.', b'/', 0xff, b'<', 0x1b, b'>'];
    let mut draft = input(&[profile, profile], Some(1));
    draft.tabs[0].tree = WorkspaceTreeInput::Split {
        direction: WorkspaceSplitDirection::Horizontal,
        first: Box::new(open(profile, opaque.clone())),
        second: Box::new(open(profile, b"./not-present".to_vec())),
    };
    draft.tabs[0].focused = 1;
    let saved = workspaces.create(draft).unwrap();
    let object = store.get(Uuid::parse_str(&saved.id).unwrap()).unwrap().unwrap();
    let (record, layout) = definition(&object).unwrap();
    assert_eq!(layout.files.len(), 3);
    assert!(record.sessions.values().all(|session| session.kind == SessionKind::Terminal
        && session.forward.is_none()
        && session.working_directory.is_none()));
    let first = workspaces.open(&saved.id).unwrap();
    assert_eq!(first.active, Some(1));
    let panes = terminals(&first);
    assert_eq!(panes[0].files.as_ref().unwrap().path, opaque);
    assert!(!panes[0].files.as_ref().unwrap().label.contains('\u{1b}'));
    assert_eq!(panes[1].files.as_ref().unwrap().path, b"./not-present");
    assert!(panes[2].files.is_none());
    assert!(store.recent_sessions(10).unwrap().is_empty());
    drop(workspaces);
    drop(store);
    let reopened = Arc::new(
        Store::open(&directory.path().join("workspaces.db"), &LocalDatabaseKey::new([5; 32]))
            .unwrap(),
    );
    let restored = Workspaces::new(reopened.clone()).open(&saved.id).unwrap();
    for (before, after) in panes.iter().zip(terminals(&restored)) {
        assert_eq!(before.files, after.files);
        assert_ne!(before.session_id, after.session_id);
    }
    assert_eq!(
        reopened.get(object.id).unwrap().unwrap().encode().unwrap(),
        object.encode().unwrap()
    );
    assert!(reopened.recent_sessions(10).unwrap().is_empty());
}

#[test]
fn files_paths_are_required_bounded_and_validated_before_persistence() {
    let (_directory, store, workspaces, profile) = fixture();
    assert!(
        serde_json::from_value::<WorkspaceTreeInput>(serde_json::json!({
            "kind": "terminal", "profileId": profile.to_string()
        }))
        .is_err()
    );
    for path in [vec![], vec![0], b"./bad\0name".to_vec(), vec![b'a'; 4097]] {
        let mut draft = input(&[profile], None);
        draft.tabs[0].tree = open(profile, path);
        assert_eq!(workspaces.create(draft), Err(WorkspaceIssue::UnsupportedLayout));
    }
    assert!(store.list(ObjectType::WORKSPACE).unwrap().is_empty());
    let mut draft = input(&[profile], None);
    draft.tabs[0].tree = open(profile, vec![b'a'; 4096]);
    let saved = workspaces.create(draft).unwrap();
    assert_eq!(
        terminals(&workspaces.open(&saved.id).unwrap())[0].files.as_ref().unwrap().path.len(),
        4096
    );
    let mut oversized = input(&[profile; 64], None);
    for tab in &mut oversized.tabs {
        tab.tree = open(profile, vec![b'a'; 4096]);
    }
    assert_eq!(workspaces.create(oversized), Err(WorkspaceIssue::DefinitionTooLarge));
    assert_eq!(store.list(ObjectType::WORKSPACE).unwrap().len(), 1);
}

#[test]
fn malformed_files_maps_are_retained_unavailable_without_partial_opening() {
    let (_directory, store, workspaces, profile) = fixture();
    let saved = workspaces.create(input(&[profile], None)).unwrap();
    let id = Uuid::parse_str(&saved.id).unwrap();
    let object = store.get(id).unwrap().unwrap();
    let record = Workspace::read(&object).unwrap();
    let Value::Map(fields) = cbor::decode(record.layout.as_ref().unwrap()).unwrap() else {
        panic!()
    };
    let slot = record.sessions.keys().next().unwrap();
    let key = Value::Bytes(slot.as_bytes().to_vec());
    let maps = [
        Value::Null,
        Value::Map(vec![]),
        Value::Map(vec![(Value::Bytes(Uuid::now_v7().as_bytes().to_vec()), Value::Null)]),
        Value::Map(vec![
            (key.clone(), Value::Null),
            (Value::Bytes(Uuid::now_v7().as_bytes().to_vec()), Value::Null),
        ]),
        Value::Map(vec![(key.clone(), Value::Text("./directory".into()))]),
        Value::Map(vec![(key.clone(), Value::Bytes(vec![]))]),
        Value::Map(vec![(key.clone(), Value::Bytes(vec![0]))]),
        Value::Map(vec![(key, Value::Bytes(vec![b'a'; 4097]))]),
    ];
    for files in maps {
        let mut fields = fields.clone();
        fields[4].1 = files;
        rewrite(
            &store,
            &saved.id,
            vec![(FieldPath::Field(2), Value::Bytes(cbor::encode(&Value::Map(fields)).unwrap()))],
        );
        let before = store.get(id).unwrap().unwrap().encode().unwrap();
        assert_eq!(workspaces.open(&saved.id), Err(WorkspaceIssue::UnsupportedLayout));
        assert_eq!(workspaces.list().unwrap()[0].issue, Some(WorkspaceIssue::UnsupportedLayout));
        assert_eq!(store.get(id).unwrap().unwrap().encode().unwrap(), before);
    }
    let mut repeated = record.layout.unwrap();
    let map = repeated.len() - 19;
    assert_eq!(repeated[map], 0xa1);
    let entry = repeated[map + 1..].to_vec();
    repeated[map] = 0xa2;
    repeated.extend_from_slice(&entry);
    rewrite(&store, &saved.id, vec![(FieldPath::Field(2), Value::Bytes(repeated))]);
    let before = store.get(id).unwrap().unwrap().encode().unwrap();
    assert_eq!(workspaces.open(&saved.id), Err(WorkspaceIssue::UnsupportedLayout));
    assert_eq!(store.get(id).unwrap().unwrap().encode().unwrap(), before);
    workspaces.delete(&saved.id).unwrap();
    assert!(store.get(id).unwrap().unwrap().is_tombstoned());
}
