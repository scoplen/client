// SPDX-License-Identifier: Apache-2.0
//! Device-local team signers and source-bound, previously authorized certificates.

use rusqlite::{OptionalExtension, Transaction, params};
use scoplen_crypto::SecretVec;
use uuid::Uuid;

use super::{Store, StoreError, personal::PersonalRecord, team_assets::TeamAssetPublication};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TeamSshOwner {
    pub origin: String,
    pub account: Uuid,
    pub organization: Uuid,
    pub device: Uuid,
}

#[derive(Debug)]
pub(crate) struct TeamSshSignerRecord {
    pub seed: SecretVec,
    pub generation: Uuid,
    pub active: bool,
    pub vault: Option<Uuid>,
    pub revision: Option<u64>,
}

pub(crate) struct TeamSshCertificateRecord {
    pub generation: Uuid,
    pub ca: SecretVec,
    pub request: SecretVec,
    pub response: SecretVec,
}

impl Store {
    pub(crate) fn team_ssh_signer(
        &self,
        owner: &TeamSshOwner,
    ) -> Result<Option<TeamSshSignerRecord>, StoreError> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                "SELECT seed,generation,active,vault_id,revision FROM team_ssh_signers
             WHERE origin=?1 AND account_id=?2 AND organization_id=?3 AND device_id=?4",
                owner_params(owner),
                |row| {
                    let seed: Vec<u8> = row.get(0)?;
                    if seed.len() != 32 {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                    Ok(TeamSshSignerRecord {
                        seed: SecretVec::new(seed),
                        generation: read_uuid(row, 1)?,
                        active: row.get(2)?,
                        vault: row
                            .get::<_, Option<Vec<u8>>>(3)?
                            .map(|bytes| {
                                Uuid::from_slice(&bytes).map_err(|_| rusqlite::Error::InvalidQuery)
                            })
                            .transpose()?,
                        revision: row
                            .get::<_, Option<Vec<u8>>>(4)?
                            .map(|bytes| {
                                bytes
                                    .try_into()
                                    .map(u64::from_be_bytes)
                                    .map_err(|_| rusqlite::Error::InvalidQuery)
                            })
                            .transpose()?,
                    })
                },
            )
            .optional()?)
    }

    pub(crate) fn create_team_ssh_signer(
        &self,
        owner: &TeamSshOwner,
        seed: &SecretVec,
    ) -> Result<TeamSshSignerRecord, StoreError> {
        if seed.as_bytes().len() != 32 || owner.device != self.device_id() {
            return Err(StoreError::InvalidIdentifier);
        }
        let generation = scoplen_model::new_uuid_v7()?;
        {
            let conn = self.conn();
            conn.pragma_update(None, "synchronous", "FULL")?;
            let changed = conn.execute(
                "INSERT INTO team_ssh_signers(origin,account_id,organization_id,device_id,
                    seed,generation,active,vault_id,revision)
                 SELECT ?1,?2,?3,?4,?5,?6,1,v.vault_id,v.revision FROM team_asset_views v
                 WHERE v.origin=?1 AND v.account_id=?2 AND v.organization_id=?3 AND v.phase=1
                    AND EXISTS(SELECT 1 FROM personal_admission a WHERE a.singleton=1
                        AND a.origin=?1 AND a.account_id=?2 AND a.device_id=?4)
                 ON CONFLICT(origin,account_id,organization_id,device_id) DO NOTHING",
                params![
                    owner.origin,
                    owner.account.as_bytes().as_slice(),
                    owner.organization.as_bytes().as_slice(),
                    owner.device.as_bytes().as_slice(),
                    seed.as_bytes(),
                    generation.as_bytes().as_slice()
                ],
            )?;
            if changed == 0
                && !conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM team_ssh_signers WHERE origin=?1
                    AND account_id=?2 AND organization_id=?3 AND device_id=?4)",
                    owner_params(owner),
                    |row| row.get::<_, bool>(0),
                )?
            {
                return Err(StoreError::SyncChanged);
            }
        }
        self.team_ssh_signer(owner)?.ok_or(StoreError::SyncChanged)
    }

    pub(crate) fn team_ssh_certificate(
        &self,
        owner: &TeamSshOwner,
        host: Uuid,
        remote_user: &str,
    ) -> Result<Option<TeamSshCertificateRecord>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT c.generation,c.ca,c.request,c.response,length(c.ca),length(c.request),
                length(c.response) FROM team_ssh_certificates c JOIN team_ssh_signers s
                USING(origin,account_id,organization_id,device_id)
             WHERE c.origin=?1 AND c.account_id=?2 AND c.organization_id=?3 AND c.device_id=?4
                AND c.host_id=?5 AND c.remote_user=?6 AND s.active=1 AND c.generation=s.generation",
                params![
                    owner.origin,
                    owner.account.as_bytes().as_slice(),
                    owner.organization.as_bytes().as_slice(),
                    owner.device.as_bytes().as_slice(),
                    host.as_bytes().as_slice(),
                    remote_user
                ],
                |row| {
                    for (column, bound) in [(4, 16_384), (5, 16_384), (6, 131_072)] {
                        if !(1..=bound).contains(&row.get::<_, i64>(column)?) {
                            return Err(rusqlite::Error::InvalidQuery);
                        }
                    }
                    Ok(TeamSshCertificateRecord {
                        generation: read_uuid(row, 0)?,
                        ca: SecretVec::new(row.get(1)?),
                        request: SecretVec::new(row.get(2)?),
                        response: SecretVec::new(row.get(3)?),
                    })
                },
            )
            .optional()?)
    }

    pub(crate) fn save_team_ssh_certificate(
        &self,
        owner: &TeamSshOwner,
        host: Uuid,
        remote_user: &str,
        certificate: &TeamSshCertificateRecord,
    ) -> Result<(), StoreError> {
        if !(1..=16_384).contains(&certificate.ca.as_bytes().len())
            || !(1..=16_384).contains(&certificate.request.as_bytes().len())
            || !(1..=131_072).contains(&certificate.response.as_bytes().len())
        {
            return Err(StoreError::InvalidIdentifier);
        }
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        if conn.execute(
            "INSERT INTO team_ssh_certificates(origin,account_id,organization_id,device_id,
                host_id,remote_user,generation,ca,request,response)
             SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10 FROM team_ssh_signers s
             WHERE s.origin=?1 AND s.account_id=?2 AND s.organization_id=?3 AND s.device_id=?4
                AND s.active=1 AND s.generation=?7
                AND EXISTS(SELECT 1 FROM team_asset_views v WHERE v.origin=s.origin
                    AND v.account_id=s.account_id AND v.organization_id=s.organization_id
                    AND v.phase=1 AND v.vault_id=s.vault_id AND v.revision=s.revision)
             ON CONFLICT(origin,account_id,organization_id,device_id,host_id,remote_user)
                DO UPDATE SET generation=excluded.generation,ca=excluded.ca,
                    request=excluded.request,response=excluded.response",
            params![
                owner.origin,
                owner.account.as_bytes().as_slice(),
                owner.organization.as_bytes().as_slice(),
                owner.device.as_bytes().as_slice(),
                host.as_bytes().as_slice(),
                remote_user,
                certificate.generation.as_bytes().as_slice(),
                certificate.ca.as_bytes(),
                certificate.request.as_bytes(),
                certificate.response.as_bytes()
            ],
        )? != 1
        {
            return Err(StoreError::SyncChanged);
        }
        Ok(())
    }
}

pub(super) fn publish_authority(
    tx: &Transaction<'_>,
    identity: &PersonalRecord,
    publication: &TeamAssetPublication,
) -> Result<bool, StoreError> {
    let next = scoplen_model::new_uuid_v7()?;
    let changed = tx.execute(
        "UPDATE team_ssh_signers SET generation=?6,
            active=1,vault_id=?4,revision=?5 WHERE origin=?1 AND account_id=?2 AND organization_id=?3
                AND (active=0 OR vault_id IS NOT ?4 OR revision IS NOT ?5)",
        params![identity.origin, identity.account_id.as_bytes().as_slice(),
            publication.organization.as_bytes().as_slice(), publication.vault.as_bytes().as_slice(),
            publication.revision.to_be_bytes().as_slice(), next.as_bytes().as_slice()],
    )?;
    tx.execute(
        "DELETE FROM team_ssh_certificates WHERE origin=?1 AND account_id=?2 AND organization_id=?3
            AND NOT EXISTS(SELECT 1 FROM team_ssh_signers s WHERE s.origin=team_ssh_certificates.origin
                AND s.account_id=team_ssh_certificates.account_id
                AND s.organization_id=team_ssh_certificates.organization_id
                AND s.device_id=team_ssh_certificates.device_id AND s.generation=team_ssh_certificates.generation)",
        params![identity.origin, identity.account_id.as_bytes().as_slice(),
            publication.organization.as_bytes().as_slice()],
    )?;
    Ok(changed > 0)
}

pub(super) fn invalidate_authority(
    tx: &Transaction<'_>,
    identity: &PersonalRecord,
    organization: Uuid,
) -> Result<bool, StoreError> {
    let next = scoplen_model::new_uuid_v7()?;
    let changed = tx.execute(
        "UPDATE team_ssh_signers SET active=0,generation=?4
            WHERE origin=?1 AND account_id=?2 AND organization_id=?3 AND active=1",
        params![
            identity.origin,
            identity.account_id.as_bytes().as_slice(),
            organization.as_bytes().as_slice(),
            next.as_bytes().as_slice()
        ],
    )?;
    tx.execute(
        "DELETE FROM team_ssh_certificates WHERE origin=?1 AND account_id=?2 AND organization_id=?3",
        params![identity.origin, identity.account_id.as_bytes().as_slice(), organization.as_bytes().as_slice()],
    )?;
    Ok(changed > 0)
}

fn owner_params(owner: &TeamSshOwner) -> [&dyn rusqlite::ToSql; 4] {
    [
        &owner.origin,
        owner.account.as_bytes(),
        owner.organization.as_bytes(),
        owner.device.as_bytes(),
    ]
}

fn read_uuid(row: &rusqlite::Row<'_>, column: usize) -> rusqlite::Result<Uuid> {
    Uuid::from_slice(&row.get::<_, Vec<u8>>(column)?).map_err(|_| rusqlite::Error::InvalidQuery)
}

#[cfg(test)]
mod tests {
    use scoplen_crypto::SymmetricKey;

    use super::*;

    #[test]
    fn periodic_pull_and_outage_preserve_cache_but_real_view_loss_invalidates_only_its_team() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("team.db"), &SymmetricKey::new([29; 32])).unwrap();
        let identity =
            crate::personal_server::tests::fixture_profile(&store, "https://sync.example", true)
                .record;
        store.conn().execute("UPDATE personal_server SET access_token=X'01'", []).unwrap();
        let organization = scoplen_model::new_uuid_v7().unwrap();
        let owner = TeamSshOwner {
            origin: identity.origin.clone(),
            account: identity.account_id,
            organization,
            device: store.device_id(),
        };
        let mut publication = TeamAssetPublication {
            organization,
            generation: store.begin_team_asset_pull(&identity, organization).unwrap(),
            vault: scoplen_model::new_uuid_v7().unwrap(),
            revision: 1,
            cursor: 0,
        };
        store.publish_team_assets(&identity, &publication, &[]).unwrap();
        let seed = SecretVec::new(vec![17; 32]);
        let signer = store.create_team_ssh_signer(&owner, &seed).unwrap();
        let host = scoplen_model::new_uuid_v7().unwrap();
        store
            .save_team_ssh_certificate(
                &owner,
                host,
                "root",
                &TeamSshCertificateRecord {
                    generation: signer.generation,
                    ca: SecretVec::new(vec![1]),
                    request: SecretVec::new(vec![2]),
                    response: SecretVec::new(vec![3]),
                },
            )
            .unwrap();
        publication.generation = store.begin_team_asset_pull(&identity, organization).unwrap();
        store.publish_team_assets(&identity, &publication, &[]).unwrap();
        assert_eq!(store.team_ssh_signer(&owner).unwrap().unwrap().generation, signer.generation);
        let generation = store.begin_team_asset_pull(&identity, organization).unwrap();
        store.finish_team_asset_pull(&identity, organization, generation, 4, false).unwrap();
        assert!(store.team_ssh_signer(&owner).unwrap().unwrap().active);
        assert!(store.team_ssh_certificate(&owner, host, "root").unwrap().is_some());
        assert!(
            store
                .team_ssh_snapshot(&identity, organization, publication.vault, 1)
                .unwrap()
                .is_some()
        );
        store.finish_team_asset_pull(&identity, organization, generation, 3, true).unwrap();
        assert!(!store.team_ssh_signer(&owner).unwrap().unwrap().active);
        assert!(store.team_ssh_certificate(&owner, host, "root").unwrap().is_none());
        assert_eq!(store.team_assets_record(&identity, organization).unwrap().unwrap().phase, 3);
        publication.generation = store.begin_team_asset_pull(&identity, organization).unwrap();
        store.publish_team_assets(&identity, &publication, &[]).unwrap();
        let restored = store.team_ssh_signer(&owner).unwrap().unwrap();
        assert_ne!(restored.generation, signer.generation);
        assert_eq!(restored.seed, seed);
        assert!(restored.active);
        assert!(
            store
                .team_ssh_snapshot(&identity, organization, publication.vault, 2)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .team_ssh_snapshot(
                    &identity,
                    scoplen_model::new_uuid_v7().unwrap(),
                    publication.vault,
                    1
                )
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn stale_pull_failure_cannot_invalidate_replacement_authority() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("team.db"), &SymmetricKey::new([29; 32])).unwrap();
        let identity =
            crate::personal_server::tests::fixture_profile(&store, "https://sync.example", true)
                .record;
        store.conn().execute("UPDATE personal_server SET access_token=X'01'", []).unwrap();
        let organization = scoplen_model::new_uuid_v7().unwrap();
        let mut publication = TeamAssetPublication {
            organization,
            generation: store.begin_team_asset_pull(&identity, organization).unwrap(),
            vault: scoplen_model::new_uuid_v7().unwrap(),
            revision: 1,
            cursor: 0,
        };
        store.publish_team_assets(&identity, &publication, &[]).unwrap();
        let owner = TeamSshOwner {
            origin: identity.origin.clone(),
            account: identity.account_id,
            organization,
            device: store.device_id(),
        };
        let signer = store.create_team_ssh_signer(&owner, &SecretVec::new(vec![18; 32])).unwrap();
        let stale = store.begin_team_asset_pull(&identity, organization).unwrap();
        publication.generation = store.begin_team_asset_pull(&identity, organization).unwrap();
        store.publish_team_assets(&identity, &publication, &[]).unwrap();
        store.finish_team_asset_pull(&identity, organization, stale, 3, true).unwrap();
        let current = store.team_ssh_signer(&owner).unwrap().unwrap();
        assert!(current.active);
        assert_eq!(current.generation, signer.generation);
    }
}
