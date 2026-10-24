// SPDX-License-Identifier: Apache-2.0
//! Retained versions from two genuine devices are restored only by an explicit local intent.

use super::*;
use crate::personal_inventory::PersonalInventoryError;
use scoplen_model::Object;

pub(super) async fn verify(
    manager: &PersonalServer,
    store: Arc<Store>,
    original: &Object,
) -> Object {
    let settings = PersonalInventorySettings::default();
    let before = settings.status(&store).expect("progress before history query");
    let current = store.get(original.id).unwrap().expect("current paired-device edit");
    let history = settings
        .query_history(manager, store.clone(), original.id.to_string())
        .await
        .expect("verify complete real HTTPS history signed by both admitted devices");
    assert_eq!(history.object_id, original.id.to_string());
    assert_eq!(history.versions.len(), 3);
    assert_eq!(history.versions[0].object.name.as_deref(), Some("Live Personal host"));
    assert_eq!(history.versions[1].object.name.as_deref(), Some("Edited live Personal host"));
    assert_eq!(history.versions[2].object.name.as_deref(), Some("Edited on paired device"));
    let metadata = serde_json::to_string(&history).unwrap();
    assert!(!metadata.contains("host.example.com"), "addresses never cross the history facade");
    let queried = settings.status(&store).expect("progress after read-only history query");
    assert_eq!(queried.objects, before.objects);
    assert_eq!(queried.pending, before.pending);
    assert_eq!(queried.applied_cursor, before.applied_cursor);
    assert_eq!(queried.acknowledged_cursor, before.acknowledged_cursor);

    let sequence = history.versions[0].sequence.clone();
    let offline = PersonalServer::default();
    settings
        .restore_history(&offline, store.clone(), history.token.clone(), sequence.clone())
        .expect("explicit confirmation creates a local copy without network access");
    assert_eq!(store.get(original.id).unwrap(), Some(current));
    let restored = settings.status(&store).expect("progress after local copy creation");
    assert_eq!(restored.pending, before.pending);
    assert_eq!(restored.applied_cursor, before.applied_cursor);
    assert_eq!(restored.acknowledged_cursor, before.acknowledged_cursor);
    let copies: Vec<_> = restored
        .objects
        .iter()
        .filter(|candidate| !before.objects.iter().any(|old| old.id == candidate.id))
        .collect();
    assert_eq!(copies.len(), 1);
    assert!(!copies[0].personal, "history restoration never adopts an object");
    let copy = store
        .get(copies[0].id.parse().expect("fresh local copy UUID"))
        .unwrap()
        .expect("durable local copy");
    assert_ne!(copy.id, original.id);
    assert_eq!(copy.required_text(1).unwrap(), original.required_text(1).unwrap());
    assert_eq!(copy.required_text(2).unwrap(), original.required_text(2).unwrap());
    assert!(copy.field(1).unwrap().clock > original.field(1).unwrap().clock);
    assert!(copy.tombstone.is_none());
    assert_eq!(
        settings.restore_history(&offline, store.clone(), history.token, sequence),
        Err(PersonalInventoryError::PreviewExpired)
    );
    assert_eq!(store.list(ObjectType::HOST).unwrap().len(), restored.objects.len());

    let unchanged = settings
        .query_history(manager, store, original.id.to_string())
        .await
        .expect("local restoration leaves the server's retained versions unchanged");
    assert_eq!(
        unchanged.versions.iter().map(|version| &version.sequence).collect::<Vec<_>>(),
        history.versions.iter().map(|version| &version.sequence).collect::<Vec<_>>()
    );
    copy
}
