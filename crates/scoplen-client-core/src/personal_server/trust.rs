// SPDX-License-Identifier: Apache-2.0
//! Offline device provenance. A known revocation dominates every saved active list.

use std::collections::{BTreeMap, HashSet};

use scoplen_api::{account_devices::AccountDeviceStatements, sync::SyncAccountKeyBundle};
use scoplen_crypto::{DeviceCertificate, RevocationStatement, verify_device_list};
use uuid::Uuid;

use super::{PersonalServerError, retained::RetainedAccount, storage};
use crate::store::Store;

pub(crate) struct PersonalTrustDevices {
    pub account: Uuid,
    pub certificates: BTreeMap<Uuid, DeviceCertificate>,
    pub revoked: HashSet<Uuid>,
}

impl PersonalTrustDevices {
    pub fn load(store: &Store) -> Result<Option<Self>, PersonalServerError> {
        let Some(identity) = store.personal_record().map_err(storage)? else {
            return Ok(None);
        };
        let retained = match RetainedAccount::load(store, &identity) {
            Ok(retained) => retained,
            Err(PersonalServerError::RetiredEntry) => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut devices = Self {
            account: identity.account_id,
            certificates: [(store.device_id(), retained.certificate)].into_iter().collect(),
            revoked: HashSet::new(),
        };
        if let Some(snapshot) = store.personal_sync_record().map_err(storage)? {
            let bundle = SyncAccountKeyBundle::from_cbor(snapshot.account_keys.as_bytes())
                .map_err(|_| PersonalServerError::Identity)?;
            devices.merge(&bundle.certificates, &bundle.revocations, &retained.signing_public)?;
        }
        if let Some(snapshot) = store.personal_account_snapshot(&identity).map_err(storage)? {
            let statements = AccountDeviceStatements::from_json(snapshot.devices.as_bytes())
                .map_err(|_| PersonalServerError::Identity)?;
            if statements.account_id != identity.account_id {
                return Err(PersonalServerError::Identity);
            }
            devices.merge(
                &statements.certificates,
                &statements.revocations,
                &retained.signing_public,
            )?;
        }
        Ok(Some(devices))
    }

    fn merge(
        &mut self,
        certificates: &[Vec<u8>],
        revocations: &[Vec<u8>],
        account_key: &[u8; 32],
    ) -> Result<(), PersonalServerError> {
        let certificates = certificates
            .iter()
            .map(|encoded| DeviceCertificate::decode(encoded).map_err(invalid))
            .collect::<Result<Vec<_>, _>>()?;
        let revocations = revocations
            .iter()
            .map(|encoded| RevocationStatement::decode(encoded).map_err(invalid))
            .collect::<Result<Vec<_>, _>>()?;
        verify_device_list(&certificates, &revocations, account_key).map_err(invalid)?;
        for certificate in certificates {
            if certificate.account_id != self.account
                || self
                    .certificates
                    .get(&certificate.device_id)
                    .is_some_and(|known| known != &certificate)
            {
                return Err(PersonalServerError::Identity);
            }
            self.certificates.insert(certificate.device_id, certificate);
        }
        self.revoked.extend(revocations.into_iter().map(|revocation| revocation.device_id));
        Ok(())
    }
}

fn invalid(_: impl std::fmt::Debug) -> PersonalServerError {
    PersonalServerError::Identity
}

pub(super) fn preserves_revocations(previous: &[Vec<u8>], next: &[Vec<u8>]) -> bool {
    let ids = |statements: &[Vec<u8>]| {
        statements
            .iter()
            .map(|encoded| {
                RevocationStatement::decode(encoded).map(|statement| statement.device_id)
            })
            .collect::<Result<HashSet<_>, _>>()
    };
    match (ids(previous), ids(next)) {
        (Ok(previous), Ok(next)) => previous.is_subset(&next),
        _ => false,
    }
}
