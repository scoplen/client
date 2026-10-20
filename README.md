# Scoplen client

> The Scoplen desktop client for macOS and Windows: an SSH client that connects to hosts directly or through a self-hosted Scoplen bastion.

Scoplen is a Plystra project. The full Plystra philosophy applies; this repository's review record is [PROJECT_PRINCIPLES.md](PROJECT_PRINCIPLES.md), which links to the project record in `scoplen-docs`.

Owner and operator: Plystra LLC. Responsible maintainer: Plystra LLC.

## Status

Maturity: Exploration. Maintenance: Active.

The application shell is in place: a Tauri 2 application for macOS and Windows, the Scoplen identity and design tokens, typed IPC generated from Rust with a binary channel transport, and a design system foundation with keyboard navigation, screen-reader labels, light and dark themes, increased-contrast and reduced-motion support, and ICU localization in English and Simplified Chinese. It keeps an encrypted local store: a SQLCipher database whose key is held in the macOS Keychain or, on Windows, by the TPM or DPAPI, optionally with a local passphrase. The desktop can manage local hosts, groups, tags, favorites, notes, and credentials. An empty inventory can preview and import simple literal OpenSSH `Host` blocks, reporting skipped hosts and unsupported directives without modifying the source file. SSH connects directly, through a saved SOCKS5 or HTTP CONNECT proxy with optional username/password authentication, through an explicit saved Jump chain, or through a saved local ProxyCommand. Each SSH host uses its saved password, OpenSSH Ed25519, ECDSA P-256/P-384/P-521, or RSA software key, or an explicitly selected key in the system SSH agent, after independent host-key review. The target opens an interactive terminal with ANSI rendering, keyboard input, and close handling. Encrypted private keys prompt for a one-time passphrase after that host's review. New or changed keys require explicit acceptance; wildcard-only and CA records do not authorize raw host keys. Other credential kinds, automatic reconnect, and sync follow the client track of [`scoplen-docs/17-implementation-roadmap.md`](../scoplen-docs/17-implementation-roadmap.md).

To use Jump, create a Jump route containing the ordered Logins for the jump
hosts, then assign that route to the target Login. Every jump Login must select
Direct. The client rejects nested Jump, proxy, or command routes on a jump
Login, missing references, and repeated Logins or Hosts, including the target,
before network or agent access. Each dialog identifies the jump or target,
position, Host, Login, and endpoint. Trust acceptance applies only to the exact
key on the retained connection; authentication and the next hop wait for it.
Changed keys require a separate review. Forwarded connection setup has a
ten-second deadline. Cancellation or failure closes the current connection and
its parents in reverse order; the target owns that chain until the session ends.

To use ProxyCommand, create that kind of Route and assign it to the target Login.
Enter a program followed by arguments; quote paths or arguments containing spaces.
Space and tab separate arguments outside single or double quotes. Outside single
quotes, a backslash escapes a quote, backslash, space, or tab; other backslashes
remain literal for Windows paths. `%h`, `%p`, `%r`, and `%%` expand to the target
address, port, Login username, and a literal percent after parsing, without
splitting or interpreting the inserted text. No shell, environment, home, wildcard,
pipeline, or redirection expansion is added. The program and each expanded argument
must fit 4,096 UTF-8 bytes, with at most 64 arguments and 16,384 bytes of saved text.
Malformed commands fail before starting a helper, accessing an SSH agent, or decrypting
a private key. On Windows, `.bat`/`.cmd` programs are rejected because they would
invoke an implicit shell; an explicitly configured command processor is allowed.
Native helpers start without opening a console window. The target's usual
host-key review precedes authentication, handshake setup is bounded
to ten seconds, and cancelling or ending the connection releases its helper.

RSA private-key authentication selects `rsa-sha2-512` or `rsa-sha2-256` from the
server's advertised `server-sig-algs`. When the advertisement is unavailable or
unrecognized, it tries SHA-512 once; a SHA-1-only advertisement fails before
authentication. A rejected SHA-2 attempt does not retry another hash or fall
back to SHA-1 or a password.

Saved Agent Credentials can authenticate through the system SSH agent. In the
credential editor choose Agent, paste the exact OpenSSH public key, and assign
that credential to the host's Login. The key must already be loaded in the
agent; comments do not affect identity matching. An agent credential without
a public key fails before dialing. The client never selects the first agent
identity, imports a private key from the agent, or falls back to a password.
Unix uses `SSH_AUTH_SOCK`; Windows uses that variable when it names a local
pipe, otherwise the standard OpenSSH pipe when the variable is absent.
Pageant discovery and agent forwarding remain later outcomes.

Host-key review completes before querying or signing with the agent. A single
ten-second deadline covers local agent connection, identities, signing, and SSH
authentication, including partial reads. At most four agent authentication
workers run concurrently. Closing a pending connection cancels local agent I/O
and discards the authentication result; no shell is opened by the cancelled task.
Missing keys, locked or unavailable agents, signing refusal, and timeouts are
explicit failures. Agent RSA keys use the same SHA-2 selection policy as software keys.

Saved encrypted OpenSSH keys use bcrypt-pbkdf for this connection only. The
passphrase is never saved and is cleared from the input after submission;
incorrect entry can be retried. Before decryption the client enforces a 64 KiB
key-file limit, a 4 KiB passphrase limit, a nonempty bcrypt salt of at most 64
bytes, and 1–256 bcrypt rounds. Larger or malformed work parameters fail
without running the KDF. Each encrypted key in a Jump chain gets an independent
blank prompt, and a wrong passphrase can be retried on the same reviewed
connection. Cancellation closes the whole chain and records the accepted
connection attempt as closed in Recent.
If a running connection is canceled while bcrypt is deriving, its bounded
blocking task may finish before releasing the passphrase; its result is ignored.

Interactive SSH sessions become ready after authentication and shell setup,
even when the server sends no initial output. Terminal input and PTY resizing
are available without waiting for a welcome message or prompt.

When a session closes or fails, choose Reconnect in its header to connect again
in the same tab. Its displayed terminal output stays available. Reconnect waits
for the previous connection task to finish, rechecks the host key, resolves the
current saved login, and prompts again when a one-time key passphrase is needed.
Each attempt uses a new transport identifier and records a separate Recent
entry. Closing the tab cancels its pending connection.

Accepted SSH connection attempts appear in Recent using device-local history.
Normal completion and an explicit close during connection preparation record
`Closed`; connection errors and externally dropped connection tasks record
`Failed`. Closing a tab releases its transport registration.
An ended terminal in Recent can be started again through the normal Connect
entry point using its current saved login. The lookup opens no connection and
does not write history; the new attempt runs the usual host-key checks and
records its own lifecycle. Active sessions and Files/Forward entries do not
offer this action. Automatic reconnect and restoring scrollback after closing a tab remain later
session-management outcomes.

## What it does not do

- It sends nothing to the vendor: no telemetry, update server, or crash-report endpoint in Phase 1.
- It does not run on Linux, iOS, or Android in Phase 1.
- It does not contain the server, host agent, or web console; those are in `server`.

## Repository shape

| Path | Purpose |
| --- | --- |
| `crates/scoplen-client-core` | Platform-independent client logic |
| `crates/scoplen-client-platform` | macOS and Windows integration; the only place `unsafe` code is allowed |
| `crates/scoplen-mosh` | Mosh client protocol (roadmap C12) |
| `src-tauri/` | Tauri 2 application shell and the typed command surface |
| `web/app/` | The client frontend (React, TypeScript) |
| `web/ui/` | `@scoplen/ui`, the design system: tokens, components, localization |

The terminal component package `@scoplen/terminal` is added in `web/terminal/` under roadmap C4. See [docs/architecture.md](docs/architecture.md) for the boundaries and [docs/development.md](docs/development.md) for everyday work.

## Development

Requirements: read access to `scoplen/proto` (Cargo fetches it through the git CLI, so set `CARGO_NET_GIT_FETCH_WITH_CLI=true`), the Rust toolchain pinned in `rust-toolchain.toml` (installed by rustup), Node.js 24.16.0 (`.nvmrc`), pnpm 11, and the Tauri prerequisites for your platform (Xcode Command Line Tools on macOS; Microsoft C++ Build Tools and WebView2 on Windows). Python 3 with Pillow and fontTools is needed only to regenerate the icon or the Chinese heading font.

```bash
pnpm install
pnpm dev
```

Checks run before every change:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cargo deny check
cargo machete
pnpm lint
pnpm typecheck
pnpm test
pnpm license-check
```

With PowerShell 7, Docker, and `ssh-keygen` available, `scripts/test-ssh-private-key.ps1`
starts disposable OpenSSH servers and verifies Ed25519, P-256/P-384/P-521, and RSA key
authentication, encrypted-key passphrases, constrained RSA-SHA2-256/512
selection, SHA-1-only refusal, wrong-key rejection, invalid-key errors, and
fail-closed host-key trust.
It removes its containers and temporary keys when finished.
CI runs this fixture on Linux in addition to the macOS and Windows Rust checks.

`scripts/test-ssh-proxy-route.ps1` builds public-API smoke examples, starts a
disposable OpenSSH server, and checks direct, SOCKS5, and HTTP CONNECT command
execution through unauthenticated and authenticated proxies. It also checks proxy authentication
rejection, proxy refusal, stalled proxy timeouts, and target
host-key mismatch for both proxy types. Saved ProxyCommand cases resolve real encrypted-store
objects and verify literal argument expansion, first-use trust, trust rejection, SSH
authentication failure, early child exit, setup timeout, cancellation, close/drop cleanup
through a child-held socket, invalid-command and invalid-username preflight, and a fresh
successful connection. It requires PowerShell 7, Docker, and
`ssh-keygen`; the script removes its container and temporary key when finished.
CI runs the same proxy fixture on Linux.

`scripts/test-ssh-agent-unix.ps1` runs the saved Credential resolver and platform
Unix socket transport against a disposable real OpenSSH agent and server in
Docker. It checks exact key selection with an unrelated identity loaded first,
missing identities, host-key rejection, unavailable agents, signing refusal,
disconnect, timeout, cancellation, and successful controls after failures.
`scripts/test-ssh-agent-pipe.ps1` exercises an isolated Windows mock agent pipe
against a disposable OpenSSH server without touching the user's system agent.
`scripts/test-ssh-jump.ps1` checks three independent OpenSSH hosts, saved ordered
routes, new and changed trust at every position, password/software-key/Agent
authentication, wrong-passphrase retries, refusal, timeout, cancellation, and a
fresh successful connection after failures.
`scripts/test-ssh-agent-windows.ps1` is restricted to an isolated Windows GitHub
runner and checks the complete saved-key path through the real Microsoft agent,
using a disposable loopback Rust SSH protocol peer. That peer does not establish
Windows OpenSSH-server interoperability. Each fixture cleans up its own resources.

On macOS, `scripts/check-offline.sh target/release/bundle/macos/Scoplen.app` verifies that a built application makes no network connection while sync is disabled.

To see every screen and state with sample data, run `pnpm --dir web/app dev` and open `/gallery.html`; see [docs/interface.md](docs/interface.md).

To build the application and confirm that it launches:

```bash
pnpm tauri build --bundles app
SPL_SMOKE_TEST=1 target/release/bundle/macos/Scoplen.app/Contents/MacOS/scoplen
```

## Data and privacy

Everything Scoplen keeps is stored on the device, in the application data directory (`~/Library/Application Support/com.scoplen.client` on macOS, `%APPDATA%\com.scoplen.client` on Windows). The store is a SQLCipher database encrypted with a random 256-bit key. That key is held in the macOS Keychain (only on this device, after the first unlock) or, on Windows, wrapped by a TPM-held key or by DPAPI for the current user. With a local passphrase, the key is additionally wrapped with a key derived from the passphrase by Argon2id; forgetting the passphrase makes the data unrecoverable. If the key is lost, Scoplen keeps the unreadable store under a new name and can start with empty data. Network access is initiated only by an explicit SSH session command; there is no background sync or telemetry in this build.

## Security

Report vulnerabilities privately to `scoplen-security@plystra.com`; see [SECURITY.md](SECURITY.md). Do not open public issues for vulnerabilities.

## License

The source code is licensed under the Apache License 2.0; see [LICENSE](LICENSE). Bundled fonts (Inter, Lora, JetBrains Mono, and the Noto Serif SC subset) are under the SIL Open Font License 1.1.
