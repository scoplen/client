# Changelog

All notable changes to the Scoplen desktop client are recorded here.

## Unreleased

- Fixed terminal profile and theme changes restarting the same source subscription and opening a duplicate SSH connection.
- Connected real SSH attempts to device-local Recent history, recording normal completion, errors, and cancelled connection tasks, and releasing transport registrations when a task is cancelled.
- Upgraded the shared SSH contract and connected OpenSSH ECDSA P-384/P-521 keys and bounded RSA `server-sig-algs` selection. SHA-256-only and SHA-512 servers authenticate with their advertised SHA-2 algorithm; SHA-1-only servers fail closed without a fallback.
- Connected saved unencrypted OpenSSH Ed25519, ECDSA P-256, and RSA software keys to direct SSH public-key authentication, with explicit encrypted, invalid, unsupported-key, and RSA-SHA2-512 rejection errors and unchanged host-key trust checks.
- Fixed silent SSH shells remaining on the connecting screen: the desktop receives an explicit shell-ready notification independently of terminal output, and ignores late notifications after the connection ends.
- Added the first live direct SSH path: password authentication through the shared `scoplen-ssh` engine, host-specific trust-record verification, bounded command/terminal frames, and fail-closed lifecycle errors for unsupported routes and credentials.
- Added the application shell: a Tauri 2 application for macOS and Windows with the Scoplen icon, a typed IPC surface generated from Rust, a binary frame channel for streams, and a launch smoke test.
- Added `@scoplen/ui`: the Scoplen design tokens in light and dark with increased-contrast and reduced-motion support, bundled Inter, Lora, JetBrains Mono, and a Chinese heading subset of Noto Serif SC, the mark and lockup, buttons, a keyboard-navigable toolbar, a skip link, and ICU localization.
- Added the about screen in English and Simplified Chinese, with the interface language chosen from the system's preferences.
- Added the encrypted local store: SQLCipher with versioned migrations, a device identity and clock, field-by-field merging of local writes, change notifications, and the per-vault object limit.
- Added protection of the local database key in the macOS Keychain and, on Windows, the TPM or DPAPI, with an optional local passphrase, a passphrase-only mode for systems without a keystore, and recovery by starting with empty data when the key is lost.
- Added typed repositories for every object type, with field-level changes, clearing of optional fields, redacted credential secrets, and a `storeChanged` event to the interface after every committed change.
- Added device-local records: this device's credential secrets and keystore handles, the device key pair, a bounded session history, scrollback, and window geometry, which the main window now uses to reopen where it was.
- Added platform-keystore-backed `DeviceBoundKey` creation and resolution: each credential gets an opaque device-local handle and a per-device OpenSSH public key, while private material is resolved only at connection time and zeroized after use. `SecurityKey` remains an explicit unsupported capability until FIDO2/WebAuthn support is implemented; native non-exportable hardware signing remains a later platform outcome.
- Added a macOS check that the application makes no network connection while sync is disabled.
- Fixed Windows test executables failing to start because they lacked the Common Controls manifest.
