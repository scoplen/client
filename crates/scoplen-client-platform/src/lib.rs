// SPDX-License-Identifier: Apache-2.0

//! Platform integration of the Scoplen desktop client.
//!
//! Keystores, hardware keys, system agents, notifications, and background
//! execution differ between macOS and Windows; this crate gives the rest of
//! the client one safe interface to each (`scoplen-docs/11-client-architecture.md` §3).
//! Unsafe code is denied except in the modules that call platform APIs, where
//! every block states why it is sound.

pub mod credentials;
pub mod keystore;
pub mod ssh_agent;

/// The user's preferred languages as the operating system reports them, most
/// preferred first, as BCP 47 or POSIX tags.
///
/// Returns an empty list when the system reports none.
pub fn preferred_languages() -> Vec<String> {
    sys_locale::get_locales().collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn preferred_languages_are_non_empty_tags() {
        for tag in super::preferred_languages() {
            assert!(!tag.trim().is_empty());
        }
    }
}
