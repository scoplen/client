// SPDX-License-Identifier: Apache-2.0
//! Read-only historical completion evidence; no pairing mutation or credential is usable.

use rusqlite::OptionalExtension as _;
use scoplen_crypto::SecretVec;
use uuid::Uuid;

use super::{Store, StoreError};
use crate::store::uuid_from;

pub(crate) struct PairingRecord {
    pub generation: i64,
    pub side: u8,
    pub origin: String,
    pub pairing_id: Uuid,
    pub peer_id: Option<Uuid>,
    pub phase: String,
    pub certificate: Option<SecretVec>,
}

impl Store {
    pub(crate) fn pairing_record(&self) -> Result<Option<PairingRecord>, StoreError> {
        let row = self
            .conn()
            .query_row(
                "SELECT side, origin, pairing_id, peer_id, phase, certificate, generation
             FROM personal_pairing WHERE singleton=1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                        row.get(4)?,
                        row.get::<_, Option<Vec<u8>>>(5)?.map(SecretVec::new),
                        row.get(6)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(side, origin, id, peer, phase, certificate, generation)| {
            Ok(PairingRecord {
                generation,
                side,
                origin,
                pairing_id: uuid_from(&id)?,
                peer_id: peer.map(|value| uuid_from(&value)).transpose()?,
                phase,
                certificate,
            })
        })
        .transpose()
    }
}
