// SPDX-License-Identifier: Apache-2.0
//! Personal provenance controls adoption independently of encrypted replication.

use std::collections::HashSet;

use serde::Serialize;
use specta::Type;
use uuid::Uuid;

use super::{HostKeyPresentation, HostKeyStatus};
use crate::personal_server::trust::PersonalTrustDevices;
use crate::repository::{Provenance, Repository, TrustRecord};
use crate::store::Store;

/// A local confirmation or provenance verified against signed Personal device statements.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyTrustSource {
    /// Device identifier, absent only on older local-only confirmations.
    pub device_id: Option<String>,
    /// Account-signed display name; local-only names are not invented.
    pub device_name: Option<String>,
    /// Recorded confirmation time, in Unix milliseconds without precision loss.
    pub accepted_at: Option<String>,
    /// This record originated from an OpenSSH known_hosts import.
    pub imported: bool,
    /// The confirmation belongs to this installation.
    pub current: bool,
}

/// Why an otherwise matching saved key needs explicit confirmation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum HostKeyReview {
    /// Its source device has a verified revocation.
    RevokedDevice,
    /// Its provenance is unavailable or outside the supported Personal policy.
    UnverifiedSource,
}

/// A read-only trust decision for the actual key presented by SSH.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostKeyAssessment {
    /// Trusted permits authentication; every other result requires confirmation.
    pub status: HostKeyStatus,
    /// Verified provenance, including a revoked source when reconfirmation is needed.
    pub source: Option<HostKeyTrustSource>,
    /// A matching key may still require review because of its source.
    pub review: Option<HostKeyReview>,
}

/// Evaluate saved host-specific trust without network I/O or a trust write.
pub fn assess_host_key(
    store: &Store,
    host: Uuid,
    key: &HostKeyPresentation,
) -> Result<HostKeyAssessment, String> {
    let records = Repository::<TrustRecord>::new(store).list().map_err(|e| e.to_string())?;
    Ok(TrustPolicy::load(store, &records)?.assess(host, key, &records))
}

pub(super) struct TrustPolicy {
    device: Uuid,
    personal: Option<PersonalTrustDevices>,
    local: HashSet<Uuid>,
}

impl TrustPolicy {
    pub fn load(store: &Store, records: &[TrustRecord]) -> Result<Self, String> {
        let mut local = HashSet::new();
        for record in records.iter().filter(|record| record.accepted_by_account.is_none()) {
            if store.object_vault(record.meta.id).map_err(|e| e.to_string())?.is_none() {
                local.insert(record.meta.id);
            }
        }
        // Invalid account metadata cannot authorize a remote source. Local-only SSH
        // remains usable while account authentication or key state is repaired.
        let personal = PersonalTrustDevices::load(store).ok().flatten();
        Ok(Self { device: store.device_id(), personal, local })
    }

    pub fn acceptance_account(&self) -> Option<Uuid> {
        self.personal.as_ref().and_then(|personal| {
            (!personal.revoked.contains(&self.device)).then_some(personal.account)
        })
    }

    pub fn assess(
        &self,
        host: Uuid,
        key: &HostKeyPresentation,
        records: &[TrustRecord],
    ) -> HostKeyAssessment {
        let mut decision =
            HostKeyAssessment { status: HostKeyStatus::New, source: None, review: None };
        for record in records.iter().filter(|r| r.host == Some(host) && !r.revoked && !r.ca) {
            if decision.status == HostKeyStatus::New {
                decision.status = HostKeyStatus::Changed;
            }
            if record.key.as_deref() != Some(&key.key)
                || record.fingerprint.as_deref() != Some(&key.fingerprint)
            {
                continue;
            }
            let imported = record.provenance == Some(Provenance::Imported);
            let supported = imported || record.provenance == Some(Provenance::Manual);
            let local = supported
                && record.accepted_by_account.is_none()
                && (record.accepted_by_device == Some(self.device)
                    || record.accepted_by_device.is_none() && self.local.contains(&record.meta.id));
            let certificate = self.personal.as_ref().and_then(|personal| {
                (record.accepted_by_account == Some(personal.account))
                    .then(|| personal.certificates.get(&record.accepted_by_device?))
                    .flatten()
            });
            let revoked = certificate.is_some_and(|certificate| {
                self.personal
                    .as_ref()
                    .is_some_and(|personal| personal.revoked.contains(&certificate.device_id))
            });
            let source =
                (local || supported && certificate.is_some()).then(|| HostKeyTrustSource {
                    device_id: record.accepted_by_device.map(|device| device.to_string()),
                    device_name: certificate.map(|certificate| certificate.display_name.clone()),
                    accepted_at: record
                        .accepted_at
                        .filter(|time| *time <= 253_402_300_799_999)
                        .map(|time| time.to_string()),
                    imported,
                    current: record.accepted_by_device.is_none_or(|device| device == self.device),
                });
            if local || supported && certificate.is_some() && !revoked {
                return HostKeyAssessment { status: HostKeyStatus::Trusted, source, review: None };
            }
            // A matching key is not a changed key. Explain the required review
            // without projecting names or times from unverified provenance.
            decision.status = HostKeyStatus::New;
            if revoked || decision.review.is_none() {
                decision.source = source;
                decision.review = Some(if revoked {
                    HostKeyReview::RevokedDevice
                } else {
                    HostKeyReview::UnverifiedSource
                });
            }
        }
        if decision.review.is_some() {
            decision.status = HostKeyStatus::New;
        }
        decision
    }
}
