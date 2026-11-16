// SPDX-License-Identifier: Apache-2.0
//! Secret-free native portable archive reports and Rust-owned confirmation reviews.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex, Weak};

use scoplen_crypto::PortableExportPassphrase;
use serde::{Deserialize, Serialize};
use specta::Type;

use crate::store::Store;

/// The selected namespace; portable archives never authorize team inventory writes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(tag = "scope", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ArchiveDestination {
    /// Device-local objects in the Local profile.
    Local,
    /// The selected Account's Personal vault.
    Personal {
        /// Current Account identity, never a file-supplied identity.
        owner_id: String,
        /// The current Account's Personal vault.
        vault_id: String,
    },
}

/// Including portable secrets requires an authenticated passphrase container.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum ArchiveSecretMode {
    /// Omit portable secrets and report their exact omission pointers.
    #[default]
    Omitted,
    /// Include shared software keys, passwords and Snippet secret defaults.
    Included,
}

/// Explicit export choices. The caller publishes its new output only after success.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportOptions {
    /// Secrets are omitted by default.
    pub secrets: ArchiveSecretMode,
}

/// A completed stream, after JSON and any encryption finalization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct ExportResult {
    /// The selected authorized namespace.
    pub destination: ArchiveDestination,
    /// Number of live entries written.
    pub objects: u32,
    /// The explicit export secret policy.
    pub secrets: ArchiveSecretMode,
}

/// Complete-state effect of confirming an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum ImportAction {
    /// Allocate a fresh destination UUIDv7.
    Create,
    /// Replace the receipt-owned target's source-owned field state.
    Replace,
    /// Preserve all destination fields and their clocks.
    Unchanged,
    /// Repair the source or destination before confirming the whole archive.
    Blocked,
}

/// A fixed, input-free explanation for an entry which cannot be imported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum ImportProblem {
    /// Include the referenced source object or restore its live receipt target.
    MissingReference,
    /// A new or incompatible redacted shared Credential has no usable secret.
    MissingSecret,
    /// The existing target has another type, binding or owner.
    IncompatibleTarget,
    /// A deleted receipt-owned target cannot be resurrected by import.
    DeletedTarget,
    /// Another destination Preference already owns this key.
    PreferenceConflict,
    /// Managed/team inventory is outside this initial destination path.
    UnsupportedData,
    /// The supplied host key or fingerprint cannot be verified.
    InvalidTrust,
}

/// Only the algorithm and full computed fingerprint are projected from a public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct ImportTrustPreview {
    /// The parsed SSH public key algorithm.
    pub algorithm: String,
    /// The complete SHA-256 fingerprint calculated from the parsed key.
    pub fingerprint: String,
    /// Explicit acceptance of this source row is required.
    pub requires_consent: bool,
    /// This key remains a host CA rather than an ordinary host-specific key.
    pub is_ca: bool,
    /// The source explicitly marks this key as revoked.
    pub revoked: bool,
}

/// One safe display row, with no decrypted fields, passwords or keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct ImportEntryPreview {
    /// Original UUIDv7 used by the destination-bound durable receipt.
    pub source_id: String,
    /// Existing receipt-owned destination, absent for a new source identity.
    pub target_id: Option<String>,
    /// Exact K-1 type name.
    pub object_type: String,
    /// Effect on this source identity.
    pub action: ImportAction,
    /// Redacted field pointers supplied by the codec.
    pub omitted_secrets: Vec<String>,
    /// Explicit choice may preserve compatible receipt-owned omitted secrets.
    pub retain_secret_available: bool,
    /// Device bindings require setup on this device; no local secret is imported.
    pub requires_device_setup: bool,
    /// Verified algorithm and full fingerprint for a TrustRecord.
    pub trust: Option<ImportTrustPreview>,
    /// Whole-batch blocker, if present.
    pub problem: Option<ImportProblem>,
}

/// A source- and destination-bound review retained by Rust until confirmation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    /// Opaque Rust review identifier.
    pub id: String,
    /// SHA-256 of the exact source bytes consumed.
    pub source_revision: String,
    /// Revision of the destination's inventory, receipts and Account context.
    pub destination_revision: String,
    /// The explicitly selected destination namespace.
    pub destination: ArchiveDestination,
    /// Safe rows in source order.
    pub entries: Vec<ImportEntryPreview>,
    /// Every entry is eligible; required explicit choices remain separate.
    pub can_import: bool,
}

/// Explicit per-source choices; unknown, duplicated or unnecessary choices are rejected.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportConsent {
    /// Preserve only compatible omitted secrets already owned by these receipts.
    pub retain_secret_source_ids: Vec<String>,
    /// Accept the exact key fingerprint and state displayed for these source rows.
    pub trust_source_ids: Vec<String>,
}

/// Counts are returned only after the entire SQLCipher transaction commits.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    /// New destination objects.
    pub created: u32,
    /// Existing receipt targets changed.
    pub updated: u32,
    /// Existing targets whose fields and clocks were preserved.
    pub unchanged: u32,
}

/// Archive failures do not embed private inputs or internal database messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type, thiserror::Error)]
#[serde(rename_all = "camelCase")]
pub enum PortableArchiveError {
    /// The strict named archive profile failed validation.
    #[error("The archive is invalid or incomplete. No inventory was changed.")]
    InvalidArchive,
    /// Including or reading secrets needs the dedicated passphrase path.
    #[error("An export passphrase is required for this archive.")]
    PassphraseRequired,
    /// Container authentication failed, including its final chunk.
    #[error("The archive could not be decrypted or verified. No inventory was changed.")]
    Decryption,
    /// The encrypted output did not finalize successfully.
    #[error("The encrypted archive could not be completed.")]
    Encryption,
    /// Unknown or unsupported data must not be silently dropped.
    #[error("The archive contains unsupported data. Its original data was retained.")]
    UnsupportedData,
    /// This path supports only Local and the current Account's Personal inventory.
    #[error("Select Local or the current Account's Personal inventory.")]
    UnsupportedDestination,
    /// Reopen and preview in the current Account/profile.
    #[error("The selected Account or destination changed. Preview the archive again.")]
    ContextChanged,
    /// No Rust-owned review matches this request.
    #[error("This archive preview is no longer available. Preview the archive again.")]
    PreviewExpired,
    /// The source bytes no longer match the preview.
    #[error("The archive changed after preview. Preview the archive again.")]
    SourceChanged,
    /// A target, receipt or relevant local state changed after preview.
    #[error("The destination changed after preview. Preview the archive again.")]
    DestinationChanged,
    /// Confirm the exact listed trust and secret-retention choices.
    #[error("Review the archive's trust and omitted-secret choices before importing.")]
    ConsentRequired,
    /// Resolve all preview problems before importing any entry.
    #[error("Resolve the archive preview's blocked entries before importing.")]
    Blocked,
    /// An encrypted local transaction failed and was rolled back.
    #[error("The archive could not be saved. Its original inventory was retained.")]
    Storage,
    /// A source/output stream could not be read/written completely.
    #[error("The archive file could not be read or written completely.")]
    Io,
    /// Native publication never overwrites an existing output file.
    #[error("Choose a new output filename. Existing files are not overwritten.")]
    DestinationExists,
}

struct Review {
    store: Weak<Store>,
    preview: ImportPreview,
}

/// Retains only safe review metadata; source files and passphrases remain with the caller.
#[derive(Default)]
pub struct PortableArchives {
    review: Mutex<Option<Review>>,
}

impl PortableArchives {
    /// Discard the previous review, including on explicit cancel or destination switch.
    pub fn clear(&self) {
        self.review.lock().unwrap_or_else(|error| error.into_inner()).take();
    }

    /// Stream a consistent selected-context snapshot; the caller owns final file publication.
    ///
    /// # Errors
    /// Rejects unsupported destinations/data, absent required passphrases or failed streams.
    pub fn export(
        &self,
        store: &Store,
        writer: impl Write,
        options: ExportOptions,
        passphrase: Option<&PortableExportPassphrase>,
    ) -> Result<ExportResult, PortableArchiveError> {
        store.portable_export(writer, options, passphrase)
    }

    /// Fully read and authenticate one archive, retaining safe metadata for confirmation.
    ///
    /// # Errors
    /// Rejects invalid, unsupported, unauthenticated or secret-bearing plaintext input.
    pub fn preview(
        &self,
        store: &Arc<Store>,
        reader: impl Read,
        passphrase: Option<&PortableExportPassphrase>,
    ) -> Result<ImportPreview, PortableArchiveError> {
        let mut review = self.review.lock().unwrap_or_else(|error| error.into_inner());
        *review = None;
        let preview = store.portable_preview(reader, passphrase)?;
        *review = Some(Review { store: Arc::downgrade(store), preview: preview.clone() });
        Ok(preview)
    }

    /// Re-read the reviewed source and atomically apply every entry and receipt.
    /// The native caller holds its captured profile-use guard for the entire operation.
    ///
    /// # Errors
    /// All source/context/target changes, missing consent and late failures roll back.
    pub fn import(
        &self,
        store: &Arc<Store>,
        reader: impl Read,
        passphrase: Option<&PortableExportPassphrase>,
        preview_id: &str,
        consent: ImportConsent,
    ) -> Result<ImportResult, PortableArchiveError> {
        let mut review = self.review.lock().unwrap_or_else(|error| error.into_inner());
        let current = review.as_ref().ok_or(PortableArchiveError::PreviewExpired)?;
        if current.preview.id != preview_id {
            return Err(PortableArchiveError::PreviewExpired);
        }
        if !current.store.upgrade().is_some_and(|saved| Arc::ptr_eq(&saved, store)) {
            return Err(PortableArchiveError::ContextChanged);
        }
        let result = store.portable_import(reader, passphrase, &current.preview, &consent)?;
        *review = None;
        Ok(result)
    }
}
