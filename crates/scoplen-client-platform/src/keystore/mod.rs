// SPDX-License-Identifier: Apache-2.0

//! Storage of the local database key in the operating system's keystore
//! (`scoplen-docs/11-client-architecture.md` §3, `05-cryptography-and-keys.md` §9).
//!
//! | Platform | Keystore |
//! |---|---|
//! | macOS | Keychain: the data-protection keychain, readable after first unlock and only on this device; the login keychain for builds without the keychain entitlement |
//! | Windows | A key held in the TPM through the Platform Crypto Provider where one is available; DPAPI for the current user otherwise |

use std::path::Path;
use uuid::Uuid;

use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

/// A failure of the platform keystore.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// The keystore refused or failed the operation.
    #[error("the {keystore} could not {operation} the protected secret: {detail}")]
    Platform {
        /// Which keystore failed.
        keystore: &'static str,
        /// What was being done.
        operation: &'static str,
        /// The platform's own description of the failure.
        detail: String,
    },
    /// The stored key exists but cannot be read back on this device, for
    /// example because the TPM was cleared.
    #[error("the {keystore} holds a protected secret but can no longer unwrap it")]
    Unrecoverable {
        /// Which keystore failed.
        keystore: &'static str,
    },
    /// Reading or writing the keystore's file failed.
    #[error("the keystore file could not be {operation}")]
    File {
        /// What was being done.
        operation: &'static str,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
}

/// A protected slot for one secret: the local database key or its
/// passphrase envelope.
pub trait Keystore: Send + Sync {
    /// A short name for messages, such as "macOS Keychain".
    fn name(&self) -> &'static str;
    /// Returns the stored secret, or `None` if nothing is stored.
    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeystoreError>;
    /// Stores `secret`, replacing any previous one.
    fn store(&self, secret: &[u8]) -> Result<(), KeystoreError>;
    /// Removes the stored secret. Removing nothing is not an error.
    /// Windows checks the exact current-user native slot even when its blob
    /// is absent or uses DPAPI. A device-not-ready probe permits software cleanup
    /// only when TBS confirms no TPM and the blob is valid DPAPI or absent.
    /// Other native errors preserve the blob and are returned.
    fn delete(&self) -> Result<(), KeystoreError>;
}

/// The platform keystore for the store in `data_dir`, or `None` on a
/// platform without one, in which case the key must be protected by a
/// passphrase alone.
pub fn local_key_store(data_dir: &Path) -> Option<Box<dyn Keystore>> {
    #[cfg(target_os = "macos")]
    {
        Some(Box::new(macos::Keychain::for_data_dir(data_dir)))
    }
    #[cfg(windows)]
    {
        Some(Box::new(windows::WindowsKeystore::for_data_dir(data_dir)))
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = data_dir;
        None
    }
}

/// Returns a device-credential slot in the platform keystore.
///
/// Each credential gets a separate slot. The returned handle is deliberately
/// opaque to the core: it is only persisted in the encrypted device-local
/// table and is resolved by the platform adapter when a connection needs the
/// key material.
pub fn credential_key_store(data_dir: &Path, credential: Uuid) -> Option<Box<dyn Keystore>> {
    #[cfg(target_os = "macos")]
    {
        Some(Box::new(macos::Keychain::for_credential(data_dir, credential)))
    }
    #[cfg(windows)]
    {
        Some(Box::new(windows::WindowsKeystore::for_credential(data_dir, credential)))
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = (data_dir, credential);
        None
    }
}

#[cfg(all(test, any(target_os = "macos", windows)))]
mod tests {
    use super::local_key_store;

    /// Exercises the real platform keystore with a slot unique to this test run.
    #[test]
    fn the_platform_keystore_stores_replaces_and_deletes() {
        // Retain failed fixtures with their exact slot binding for inspection.
        let dir = tempfile::Builder::new()
            .prefix("scoplen-keystore-")
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let data = dir.path().canonicalize().unwrap();
        let keystore = local_key_store(&data).expect("macOS and Windows have a keystore");
        assert!(keystore.load().unwrap().is_none(), "a new slot is empty");

        keystore.store(&[7u8; 32]).unwrap();
        assert_eq!(keystore.load().unwrap().unwrap().as_slice(), &[7u8; 32]);

        keystore.store(&[9u8; 61]).unwrap();
        assert_eq!(keystore.load().unwrap().unwrap().as_slice(), &[9u8; 61], "storing replaces");

        keystore.delete().unwrap();
        assert!(keystore.load().unwrap().is_none());
        keystore.delete().unwrap();
        dir.close().unwrap();
    }

    #[test]
    fn slots_for_different_stores_are_separate() {
        let mut directories = tempfile::Builder::new();
        directories.prefix("scoplen-keystore-").disable_cleanup(true);
        let (a, b) = (directories.tempdir().unwrap(), directories.tempdir().unwrap());
        let (a_data, b_data) = (a.path().canonicalize().unwrap(), b.path().canonicalize().unwrap());
        let (first, second) =
            (local_key_store(&a_data).unwrap(), local_key_store(&b_data).unwrap());
        first.store(b"first").unwrap();
        assert!(second.load().unwrap().is_none());
        first.delete().unwrap();
        second.delete().unwrap();
        a.close().unwrap();
        b.close().unwrap();
    }
}
