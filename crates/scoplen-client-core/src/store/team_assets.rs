// SPDX-License-Identifier: Apache-2.0
//! Complete source-bound Organization projections, outside the Personal object namespace.

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use scoplen_model::Object;
use uuid::Uuid;

use super::{Store, StoreError, personal::PersonalRecord};

pub(crate) struct TeamAssetRecord {
    pub phase: i64,
    pub vault: Option<Uuid>,
    pub revision: Option<u64>,
    pub acknowledged: bool,
    pub objects: Vec<Object>,
}

pub(crate) struct TeamAssetPublication {
    pub organization: Uuid,
    pub generation: Uuid,
    pub vault: Uuid,
    pub revision: u64,
    pub cursor: u64,
}

impl Store {
    pub(crate) fn team_asset_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.team_changes.subscribe()
    }

    pub(crate) fn begin_team_asset_pull(
        &self,
        identity: &PersonalRecord,
        organization: Uuid,
    ) -> Result<Uuid, StoreError> {
        if self.personal_admission(identity)?.is_none() {
            return Err(StoreError::AccountContext);
        }
        let generation = scoplen_model::new_uuid_v7()?;
        self.conn().execute(
            "INSERT INTO team_asset_views(origin,account_id,organization_id,generation,cursor,phase,acknowledged)
             VALUES(?1,?2,?3,?4,zeroblob(8),0,0)
             ON CONFLICT(origin,account_id,organization_id) DO UPDATE
             SET generation=excluded.generation,phase=0,acknowledged=0",
            params![identity.origin, identity.account_id.as_bytes().as_slice(),
                organization.as_bytes().as_slice(), generation.as_bytes().as_slice()],
        )?;
        Ok(generation)
    }

    pub(crate) fn team_asset_pull_current(
        &self,
        identity: &PersonalRecord,
        organization: Uuid,
        generation: Uuid,
    ) -> Result<bool, StoreError> {
        Ok(self.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM team_asset_views WHERE origin=?1 AND account_id=?2
             AND organization_id=?3 AND generation=?4 AND phase=0)",
            params![
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                organization.as_bytes().as_slice(),
                generation.as_bytes().as_slice()
            ],
            |row| row.get(0),
        )?)
    }

    pub(crate) fn finish_team_asset_pull(
        &self,
        identity: &PersonalRecord,
        organization: Uuid,
        generation: Uuid,
        phase: i64,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE team_asset_views SET phase=?5,acknowledged=0 WHERE origin=?1 AND account_id=?2
             AND organization_id=?3 AND generation=?4",
            params![
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                organization.as_bytes().as_slice(),
                generation.as_bytes().as_slice(),
                phase
            ],
        )?;
        Ok(())
    }

    pub(crate) fn publish_team_assets(
        &self,
        identity: &PersonalRecord,
        publication: &TeamAssetPublication,
        objects: &[Object],
    ) -> Result<(), StoreError> {
        let TeamAssetPublication { organization, generation, vault, revision, cursor } =
            publication;
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE team_asset_views SET vault_id=?5,revision=?6,cursor=?7,phase=1,acknowledged=0
             WHERE origin=?1 AND account_id=?2 AND organization_id=?3 AND generation=?4 AND phase=0
             AND EXISTS(SELECT 1 FROM personal_server WHERE singleton=1 AND auth_generation=?8
                 AND refresh_claimed=0 AND access_token IS NOT NULL)",
            params![
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                organization.as_bytes().as_slice(),
                generation.as_bytes().as_slice(),
                vault.as_bytes().as_slice(),
                revision.to_be_bytes().as_slice(),
                cursor.to_be_bytes().as_slice(),
                identity.auth_generation
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::SyncChanged);
        }
        tx.execute("DELETE FROM team_asset_objects WHERE origin=?1 AND account_id=?2 AND organization_id=?3",
            params![identity.origin, identity.account_id.as_bytes().as_slice(), organization.as_bytes().as_slice()])?;
        for object in objects {
            tx.execute("INSERT INTO team_asset_objects(origin,account_id,organization_id,object_id,payload)
                VALUES(?1,?2,?3,?4,?5)",
                params![identity.origin, identity.account_id.as_bytes().as_slice(), organization.as_bytes().as_slice(),
                    object.id.as_bytes().as_slice(), object.encode()?])?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn acknowledge_team_assets(
        &self,
        identity: &PersonalRecord,
        organization: Uuid,
        generation: Uuid,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE team_asset_views SET acknowledged=1
            WHERE origin=?1 AND account_id=?2 AND organization_id=?3 AND generation=?4 AND phase=1",
            params![
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                organization.as_bytes().as_slice(),
                generation.as_bytes().as_slice()
            ],
        )?;
        Ok(())
    }

    pub(crate) fn team_assets_record(
        &self,
        identity: &PersonalRecord,
        organization: Uuid,
    ) -> Result<Option<TeamAssetRecord>, StoreError> {
        if self.personal_admission(identity)?.is_none() {
            return Err(StoreError::AccountContext);
        }
        let conn = self.conn();
        let scope = params![
            identity.origin,
            identity.account_id.as_bytes().as_slice(),
            organization.as_bytes().as_slice()
        ];
        let Some(mut record) = conn
            .query_row(
                "SELECT phase,vault_id,revision,cursor,acknowledged FROM team_asset_views
             WHERE origin=?1 AND account_id=?2 AND organization_id=?3",
                scope,
                |row| {
                    let vault = row
                        .get::<_, Option<Vec<u8>>>(1)?
                        .map(|bytes| {
                            Uuid::from_slice(&bytes).map_err(|_| rusqlite::Error::InvalidQuery)
                        })
                        .transpose()?;
                    let revision = row
                        .get::<_, Option<Vec<u8>>>(2)?
                        .map(|bytes| {
                            bytes
                                .try_into()
                                .map(u64::from_be_bytes)
                                .map_err(|_| rusqlite::Error::InvalidQuery)
                        })
                        .transpose()?;
                    Ok(TeamAssetRecord {
                        phase: row.get(0)?,
                        vault,
                        revision,
                        acknowledged: row.get(4)?,
                        objects: Vec::new(),
                    })
                },
            )
            .optional()?
        else {
            return Ok(None);
        };
        if record.phase == 1 {
            let mut query = conn.prepare_cached(
                "SELECT payload FROM team_asset_objects
                WHERE origin=?1 AND account_id=?2 AND organization_id=?3 ORDER BY object_id",
            )?;
            let bytes = query.query_map(scope, |row| row.get::<_, Vec<u8>>(0))?;
            for payload in bytes {
                record.objects.push(Object::decode(&payload?)?);
            }
        }
        Ok(Some(record))
    }

    pub(crate) fn tracked_team_assets(
        &self,
        identity: &PersonalRecord,
    ) -> Result<Vec<Uuid>, StoreError> {
        let conn = self.conn();
        let mut query = conn.prepare_cached(
            "SELECT organization_id FROM team_asset_views
            WHERE origin=?1 AND account_id=?2 ORDER BY organization_id",
        )?;
        Ok(query
            .query_map(
                params![identity.origin, identity.account_id.as_bytes().as_slice()],
                |row| {
                    Uuid::from_slice(&row.get::<_, Vec<u8>>(0)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)
                },
            )?
            .collect::<Result<_, _>>()?)
    }

    pub(crate) fn invalidate_team_assets(
        &self,
        identity: &PersonalRecord,
        organization: Uuid,
        vault: Option<Uuid>,
    ) -> Result<(), StoreError> {
        let changed = self.conn().execute("UPDATE team_asset_views SET phase=2,acknowledged=0,generation=?4
            WHERE origin=?1 AND account_id=?2 AND organization_id=?3 AND (?5 IS NULL OR vault_id=?5)",
            params![identity.origin, identity.account_id.as_bytes().as_slice(), organization.as_bytes().as_slice(),
                scoplen_model::new_uuid_v7()?.as_bytes().as_slice(), vault.map(|id| id.as_bytes().to_vec())])?;
        if changed > 0 {
            self.team_changes.send_modify(|generation| *generation = generation.wrapping_add(1));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use scoplen_crypto::SymmetricKey;
    use scoplen_model::{FieldEntry, FieldPath, Hlc, ObjectType, cbor::Value};

    use super::*;

    fn host(name: &str) -> Object {
        let id = scoplen_model::new_uuid_v7().unwrap();
        let mut object = Object::new(id, ObjectType::HOST, 1).unwrap();
        for (field, value) in [(1, name), (2, "host.example")] {
            object
                .insert(
                    FieldPath::Field(field),
                    FieldEntry::new(Value::Text(value.into()), Hlc::at(1).unwrap(), id).unwrap(),
                )
                .unwrap();
        }
        object
    }

    #[test]
    fn failed_publication_rolls_back_withdrawals_and_keeps_other_team_rows() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Store::open(&dir.path().join("teams.db"), &SymmetricKey::new([19; 32])).unwrap();
        let identity =
            crate::personal_server::tests::fixture_profile(&store, "https://sync.example", true)
                .record;
        store.conn().execute("UPDATE personal_server SET access_token=X'01'", []).unwrap();
        let organization = scoplen_model::new_uuid_v7().unwrap();
        let other = scoplen_model::new_uuid_v7().unwrap();
        let object = host("Original team asset");
        let mut publication = TeamAssetPublication {
            organization,
            generation: store.begin_team_asset_pull(&identity, organization).unwrap(),
            vault: scoplen_model::new_uuid_v7().unwrap(),
            revision: 1,
            cursor: 50,
        };
        store.publish_team_assets(&identity, &publication, std::slice::from_ref(&object)).unwrap();
        let other_publication = TeamAssetPublication {
            organization: other,
            generation: store.begin_team_asset_pull(&identity, other).unwrap(),
            vault: scoplen_model::new_uuid_v7().unwrap(),
            revision: 1,
            cursor: 50,
        };
        store
            .publish_team_assets(&identity, &other_publication, std::slice::from_ref(&object))
            .unwrap();
        publication.generation = store.begin_team_asset_pull(&identity, organization).unwrap();
        publication.revision = 2;
        store
            .conn()
            .execute_batch(
                "CREATE TEMP TRIGGER reject_team_publication BEFORE INSERT ON team_asset_objects
             BEGIN SELECT RAISE(ABORT, 'fixture publication failure'); END;",
            )
            .unwrap();
        let replacement = host("Replacement team asset");
        assert!(store.publish_team_assets(&identity, &publication, &[replacement]).is_err());
        let retained: Vec<u8> = store
            .conn()
            .query_row(
                "SELECT payload FROM team_asset_objects WHERE organization_id=?1",
                params![organization.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(Object::decode(&retained).unwrap(), object);
        let failed = store.team_assets_record(&identity, organization).unwrap().unwrap();
        assert_eq!(failed.phase, 0);
        assert_eq!(failed.revision, Some(1));
        assert!(failed.objects.is_empty());
        let other_view = store.team_assets_record(&identity, other).unwrap().unwrap();
        assert_eq!(other_view.phase, 1);
        assert_eq!(other_view.objects, vec![object]);
    }
}
