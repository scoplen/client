// SPDX-License-Identifier: Apache-2.0
//! Durable one-attempt pairing checkpoints and atomic paired account publication.

use rusqlite::{OptionalExtension as _, TransactionBehavior, params};
use scoplen_crypto::SecretVec;
use uuid::Uuid;

use super::{PersonalRecord, Store, StoreError};
use crate::store::uuid_from;

pub(crate) struct PairingDeviceRecord {
    pub origin: String,
    pub device_name: String,
    pub signing: SecretVec,
    pub kem: SecretVec,
    pub created_at: u64,
}

pub(crate) struct PairingRecord {
    pub generation: i64,
    pub side: u8,
    pub origin: String,
    pub pairing_id: Uuid,
    pub peer_id: Option<Uuid>,
    pub expires_at: u64,
    pub local_expires_at: u64,
    pub attempt_started: bool,
    pub phase: String,
    pub capability: Option<SecretVec>,
    pub transcript: SecretVec,
    pub certificate: Option<SecretVec>,
    pub key_update: Option<SecretVec>,
    pub handoff: Option<SecretVec>,
    pub acceptance: Option<SecretVec>,
    pub approval_request: Option<SecretVec>,
}

impl Store {
    pub(crate) fn claim_pairing_attempt(&self, record: &PairingRecord) -> Result<bool, StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "INSERT INTO personal_pairing_attempts (pairing_id, origin, side)
            SELECT pairing_id, origin, side FROM personal_pairing WHERE singleton=1
                AND generation=?1 AND pairing_id=?2 AND attempt_started=0
            ON CONFLICT (pairing_id) DO NOTHING",
            params![record.generation, record.pairing_id.as_bytes().as_slice()],
        )?;
        if changed != 1 {
            return Ok(false);
        }
        tx.execute(
            "UPDATE personal_pairing SET attempt_started=1, generation=generation+1
            WHERE singleton=1",
            [],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub(crate) fn pairing_device(&self) -> Result<Option<PairingDeviceRecord>, StoreError> {
        Ok(self.conn().query_row(
            "SELECT origin, device_name, signing, kem, created_at FROM personal_pairing_device WHERE singleton = 1",
            [], |row| Ok(PairingDeviceRecord {
                origin: row.get(0)?, device_name: row.get(1)?,
                signing: SecretVec::new(row.get(2)?), kem: SecretVec::new(row.get(3)?),
                created_at: row.get::<_, i64>(4)? as u64,
            }),
        ).optional()?)
    }

    pub(crate) fn insert_pairing_device(
        &self,
        device: &PairingDeviceRecord,
    ) -> Result<bool, StoreError> {
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn.execute(
            "INSERT INTO personal_pairing_device (singleton, origin, device_name, signing, kem, created_at)
             SELECT 1, ?1, ?2, ?3, ?4, ?5
             WHERE NOT EXISTS (SELECT 1 FROM personal_server)
             AND NOT EXISTS (SELECT 1 FROM device_key_pair)
             ON CONFLICT (singleton) DO NOTHING",
            params![device.origin, device.device_name, device.signing.as_bytes(), device.kem.as_bytes(),
                i64::try_from(device.created_at).map_err(|_| StoreError::InvalidIdentifier)?],
        )? == 1)
    }

    pub(crate) fn pairing_record(&self) -> Result<Option<PairingRecord>, StoreError> {
        let raw = self
            .conn()
            .query_row(
                "SELECT generation, side, origin, pairing_id, peer_id, expires_at, attempt_started,
                phase, capability, transcript, certificate, key_update, handoff, acceptance,
                local_expires_at, approval_request
             FROM personal_pairing WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get::<_, Option<Vec<u8>>>(8)?.map(SecretVec::new),
                        SecretVec::new(row.get(9)?),
                        row.get::<_, Option<Vec<u8>>>(10)?.map(SecretVec::new),
                        row.get::<_, Option<Vec<u8>>>(11)?.map(SecretVec::new),
                        row.get::<_, Option<Vec<u8>>>(12)?.map(SecretVec::new),
                        row.get::<_, Option<Vec<u8>>>(13)?.map(SecretVec::new),
                        row.get::<_, i64>(14)?,
                        row.get::<_, Option<Vec<u8>>>(15)?.map(SecretVec::new),
                    ))
                },
            )
            .optional()?;
        raw.map(
            |(
                generation,
                side,
                origin,
                pairing_id,
                peer_id,
                expires_at,
                attempt_started,
                phase,
                capability,
                transcript,
                certificate,
                key_update,
                handoff,
                acceptance,
                local_expires_at,
                approval_request,
            )| {
                Ok(PairingRecord {
                    generation,
                    side,
                    origin,
                    pairing_id: uuid_from(&pairing_id)?,
                    peer_id: peer_id.map(|id| uuid_from(&id)).transpose()?,
                    expires_at: u64::try_from(expires_at)
                        .map_err(|_| StoreError::InvalidIdentifier)?,
                    local_expires_at: u64::try_from(local_expires_at)
                        .map_err(|_| StoreError::InvalidIdentifier)?,
                    attempt_started,
                    phase,
                    capability,
                    transcript,
                    certificate,
                    key_update,
                    handoff,
                    acceptance,
                    approval_request,
                })
            },
        )
        .transpose()
    }

    pub(crate) fn save_pairing(
        &self,
        expected: Option<i64>,
        record: &PairingRecord,
    ) -> Result<bool, StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = tx
            .query_row("SELECT generation FROM personal_pairing WHERE singleton = 1", [], |row| {
                row.get(0)
            })
            .optional()?;
        if current != expected {
            return Ok(false);
        }
        let next = current.unwrap_or(0).checked_add(1).ok_or(StoreError::InvalidIdentifier)?;
        tx.execute(
            "INSERT INTO personal_pairing (singleton, generation, side, origin, pairing_id, peer_id,
                expires_at, attempt_started, phase, capability, transcript, certificate, key_update, handoff, acceptance,
                local_expires_at, approval_request)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
             ON CONFLICT (singleton) DO UPDATE SET generation=excluded.generation, side=excluded.side,
                origin=excluded.origin, pairing_id=excluded.pairing_id, peer_id=excluded.peer_id,
                expires_at=excluded.expires_at, attempt_started=excluded.attempt_started, phase=excluded.phase,
                capability=excluded.capability, transcript=excluded.transcript, certificate=excluded.certificate,
                key_update=excluded.key_update, handoff=excluded.handoff, acceptance=excluded.acceptance,
                local_expires_at=excluded.local_expires_at, approval_request=excluded.approval_request",
            params![next, record.side, record.origin, record.pairing_id.as_bytes().as_slice(),
                record.peer_id.as_ref().map(|id| id.as_bytes().as_slice()),
                i64::try_from(record.expires_at).map_err(|_| StoreError::InvalidIdentifier)?,
                record.attempt_started, record.phase, record.capability.as_ref().map(SecretVec::as_bytes),
                record.transcript.as_bytes(), record.certificate.as_ref().map(SecretVec::as_bytes),
                record.key_update.as_ref().map(SecretVec::as_bytes), record.handoff.as_ref().map(SecretVec::as_bytes),
                record.acceptance.as_ref().map(SecretVec::as_bytes),
                i64::try_from(record.local_expires_at).map_err(|_| StoreError::InvalidIdentifier)?,
                record.approval_request.as_ref().map(SecretVec::as_bytes)],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub(crate) fn save_paired_identity(
        &self,
        expected: &PairingRecord,
        identity: &PersonalRecord,
        acceptance: &[u8; 64],
        transcript: &SecretVec,
    ) -> Result<bool, StoreError> {
        let (signing, kem) = identity.device_secrets()?;
        let handoff = identity.paired_handoff.as_ref().ok_or(StoreError::InvalidIdentifier)?;
        if identity.enrollment_request.is_some()
            || identity.enrollment_attempted
            || identity.private_material.as_bytes().first() != Some(&2)
        {
            return Err(StoreError::InvalidIdentifier);
        }
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let matches: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM personal_pairing WHERE singleton=1 AND generation=?1
                AND side=2 AND origin=?2 AND pairing_id=?3 AND attempt_started=1)
             AND EXISTS (SELECT 1 FROM personal_pairing_device WHERE singleton=1
                AND origin=?2 AND signing=?4 AND kem=?5)
             AND NOT EXISTS (SELECT 1 FROM personal_server)",
            params![
                expected.generation,
                identity.origin,
                expected.pairing_id.as_bytes().as_slice(),
                signing,
                kem
            ],
            |row| row.get(0),
        )?;
        if !matches {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO personal_server (singleton, origin, account_id, personal_vault_id,
            device_name, private_material, paired_handoff) VALUES (1,?1,?2,?3,?4,?5,?6)",
            params![
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                identity.personal_vault_id.as_bytes().as_slice(),
                identity.device_name,
                identity.private_material.as_bytes(),
                handoff.as_bytes()
            ],
        )?;
        tx.execute(
            "INSERT INTO device_key_pair (singleton, signing, kem, created_at)
             SELECT singleton, signing, kem, created_at FROM personal_pairing_device WHERE singleton=1",
            [],
        )?;
        tx.execute(
            "UPDATE personal_pairing SET generation=generation+1, acceptance=?1, transcript=?2,
            handoff=?3, certificate=?4, phase='admission_unconfirmed' WHERE singleton=1",
            params![
                acceptance.as_slice(),
                transcript.as_bytes(),
                expected.handoff.as_ref().map(SecretVec::as_bytes),
                expected.certificate.as_ref().map(SecretVec::as_bytes)
            ],
        )?;
        tx.commit()?;
        Ok(true)
    }
}
