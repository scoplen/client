// SPDX-License-Identifier: Apache-2.0

//! The macOS Keychain.

use std::path::Path;
use uuid::Uuid;

use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::passwords::{
    PasswordOptions, delete_generic_password_options, generic_password,
    set_generic_password_options,
};
use zeroize::Zeroizing;

use super::{Keystore, KeystoreError};

const SERVICE: &str = "com.scoplen.client";
const NAME: &str = "macOS Keychain";
/// `errSecItemNotFound`.
const ITEM_NOT_FOUND: i32 = -25300;
/// `errSecInteractionNotAllowed`.
const INTERACTION_NOT_ALLOWED: i32 = -25308;
/// `errSecMissingEntitlement`: the data-protection keychain needs a signed
/// build with the keychain entitlement.
const MISSING_ENTITLEMENT: i32 = -34018;

/// Suppress Keychain dialogs for the lifetime of a noninteractive console command.
/// This policy is process-wide and is intended only for the standalone helper.
///
/// # Errors
/// Returns an error if the system cannot read or set the prompt policy.
pub fn suppress_keychain_prompts() -> Result<Option<impl Drop>, KeystoreError> {
    let policy_error = |error| Keychain::platform("set the interaction policy for", error);
    if SecKeychain::user_interaction_allowed().map_err(policy_error)? {
        Ok(Some(SecKeychain::disable_user_interaction().map_err(policy_error)?))
    } else {
        Ok(None)
    }
}

/// A generic-password item, one per store location.
pub(super) struct Keychain {
    account: String,
}

impl Keychain {
    pub(super) fn for_data_dir(data_dir: &Path) -> Keychain {
        Keychain { account: format!("local-database-key:{}", data_dir.display()) }
    }

    pub(super) fn for_credential(data_dir: &Path, credential: Uuid) -> Keychain {
        Keychain {
            account: format!(
                "device-credential:{}:{}",
                data_dir.display(),
                credential.hyphenated()
            ),
        }
    }

    /// The data-protection keychain item, readable after the first unlock
    /// since boot, never synchronized and never restored to another device.
    fn protected(&self) -> PasswordOptions {
        let mut options = PasswordOptions::new_generic_password(SERVICE, &self.account);
        options.use_protected_keychain();
        options
    }

    /// The login keychain item, used when the build lacks the entitlement.
    fn login(&self) -> PasswordOptions {
        PasswordOptions::new_generic_password(SERVICE, &self.account)
    }

    fn platform(operation: &'static str, error: security_framework::base::Error) -> KeystoreError {
        KeystoreError::Platform { keystore: NAME, operation, detail: error.to_string() }
    }
}

impl Keystore for Keychain {
    fn name(&self) -> &'static str {
        NAME
    }

    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeystoreError> {
        for options in [self.protected(), self.login()] {
            match generic_password(options) {
                Ok(secret) => return Ok(Some(Zeroizing::new(secret))),
                Err(e) if e.code() == ITEM_NOT_FOUND || e.code() == MISSING_ENTITLEMENT => continue,
                Err(e) if e.code() == INTERACTION_NOT_ALLOWED => {
                    return Err(KeystoreError::InteractionRequired);
                }
                Err(e) => return Err(Self::platform("read", e)),
            }
        }
        Ok(None)
    }

    fn store(&self, secret: &[u8]) -> Result<(), KeystoreError> {
        let mut protected = self.protected();
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
            0,
        )
        .map_err(|e| Self::platform("store", e))?;
        protected.set_access_control(access);
        protected.set_label("Scoplen local database key");
        match set_generic_password_options(secret, protected) {
            Ok(()) => {
                // A copy left in the login keychain by an earlier unsigned build
                // must not outlive the protected one.
                let _ = delete_generic_password_options(self.login());
                Ok(())
            }
            Err(e) if e.code() == MISSING_ENTITLEMENT => {
                let mut login = self.login();
                login.set_label("Scoplen local database key");
                set_generic_password_options(secret, login).map_err(|e| Self::platform("store", e))
            }
            Err(e) => Err(Self::platform("store", e)),
        }
    }

    fn delete(&self) -> Result<(), KeystoreError> {
        for options in [self.protected(), self.login()] {
            match delete_generic_password_options(options) {
                Ok(()) => {}
                Err(e) if e.code() == ITEM_NOT_FOUND || e.code() == MISSING_ENTITLEMENT => {}
                Err(e) => return Err(Self::platform("delete", e)),
            }
        }
        Ok(())
    }
}
