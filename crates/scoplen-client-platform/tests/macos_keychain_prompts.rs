// SPDX-License-Identifier: Apache-2.0

//! Keep the process-wide prompt policy test isolated from other native keystore tests.
#![cfg(target_os = "macos")]

use scoplen_client_platform::keystore::suppress_keychain_prompts;
use security_framework::os::macos::keychain::SecKeychain;

#[test]
fn unattended_command_suppresses_prompts_and_restores_the_previous_policy() {
    let previous = SecKeychain::user_interaction_allowed().unwrap();
    let command = suppress_keychain_prompts().unwrap();
    assert!(!SecKeychain::user_interaction_allowed().unwrap());
    assert!(suppress_keychain_prompts().unwrap().is_none());
    assert!(!SecKeychain::user_interaction_allowed().unwrap());
    drop(command);
    assert_eq!(SecKeychain::user_interaction_allowed().unwrap(), previous);
}
