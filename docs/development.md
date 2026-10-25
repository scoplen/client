# Development

## Setup

Install rustup, Node.js 24.16.0, pnpm 11, and the Tauri prerequisites for your platform. Then:

```bash
pnpm install
pnpm dev
```

On Windows, open a new PowerShell after installing Rust so `%USERPROFILE%\.cargo\bin` is present in `PATH`. Verify with `cargo --version`; an existing terminal can be repaired for the current session with `$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"`.

`pnpm dev` starts the frontend on port 5192 and opens the application window against it. The frontend alone (`pnpm --dir web/app dev`) shows the startup error screen, because there is no core to answer; use it only for layout work.

The Tauri webview leaves `app.security.freezePrototype` disabled because the xterm.js renderer used by `@scoplen/terminal` installs a compatibility `toString` implementation during module initialization. Freezing JavaScript prototypes makes that import fail before React can render the startup screen.

The app's `dev`, `build`, `typecheck`, and `test` scripts build the workspace terminal package first. A fresh checkout therefore does not need a separate `web/terminal` build before starting the client.

The crates in `proto` are Git dependencies. Cargo fetches them through the git CLI when `CARGO_NET_GIT_FETCH_WITH_CLI=true` is set. If `scoplen/proto` is private, CI uses the `SCOPLEN_PROTO_TOKEN` repository secret with read access.

Set `SPL_DATA_DIR` to run the application against a separate data directory, for example a temporary one; the default is the platform's application data directory. On macOS the key of each data directory is a separate Keychain item, service `com.scoplen.client`, account `local-database-key:<directory>`.

Local work against the `proto` checkout uses a Cargo `[patch]` section in an untracked `.cargo/config.toml` (`scoplen-docs/02-workspace-and-repositories.md` §6). Never commit it.

### After moving or renaming the checkout

Cargo build scripts cache absolute paths. Reusing `target/` after moving the checkout can make Tauri report `failed to read plugin permissions` with the old directory in the missing file path. Other native dependencies can retain old paths too; reinstalling pnpm packages does not clear this Cargo cache.

Stop the running development process, then run this once from the new repository directory:

```bash
cargo clean
pnpm dev
```

The first launch rebuilds the Rust dependencies. A fresh checkout does not need this cleanup.

## Disposable Personal server integration

### Password registration and independent-device sign-in

Use a fresh empty disposable HTTPS deployment with Account registration enabled. The client
creates its own Account and independent Device identities through public APIs; no preconfirmed
profiles, invitation, existing device, SMTP or identity database seed is used.

The private descriptor has exactly `disposable: true`, `origin` (`https://localhost:<port>`) and
`ca_certificate` (an absolute PEM path). Set `SCOPLEN_LIVE_ACCOUNT_DEPLOYMENT` to its absolute
file path. The descriptor is bounded to 8 KiB and the CA to 64 KiB. Test CA trust is confined
to this client; use a separate fresh descriptor/deployment for each database backend.

```powershell
$env:SCOPLEN_LIVE_ACCOUNT_DEPLOYMENT = '<absolute descriptor path>'
cargo test -p scoplen-client-core --lib --features live-server-integration personal_server::live_server::password_entry::live_password_registration_and_independent_device_sync -- --exact --test-threads=1
```

The scenario exports and confirms a generated recovery key before registration, authenticates
and installs the first Device, then rejects a wrong password on an independent Local directory.
After the documented first-denial cooldown, correct password sign-in admits a fresh Device to
the same Account/vault. Both devices rotate native refresh credentials, verify signed membership,
exchange reviewed encrypted Host data and a second-device edit, and durably acknowledge progress.
Local-only Hosts stay outside both Account stores; retained keys and synchronized data verify
after Account reopen. Local store protection uses test passphrases, not native keystore acceptance.
Passwords and account names are generated per run and are not printed. Successful owned client
fixtures are removed; failures retain the original encrypted stores and pending state.
This core integration check does not establish native desktop interaction, native picker or
macOS feature acceptance.

### Preconfirmed-profile integration

The opt-in `live-server-integration` feature checks retained admitted-device authentication,
refresh, sync keys, reviewed inventory, native notifications, history, SSH trust propagation and
three-device convergence against an independently running disposable server. It does not read
server source or seed the server database. It no longer invokes retired invitation or pairing
endpoints. This older fixture setup still requires preconfirmed profiles; it does not provision
them through the newer D-128 registration/password sign-in and independent installation APIs.

Provide a loopback `https://localhost:<port>` deployment and three independently admitted,
already confirmed disposable SQLCipher profiles for the same Account, with distinct device ids
and empty inventory. Close every source profile before running the checks. The profiles must
already contain valid neutral admission anchors; archived entry data, session markers and
cached bootstrap responses cannot substitute for them.
Provisioning these fixtures is external to this client, and a missing fixture is not passing live
verification. Use a fresh deployment/profile set for each scenario and database backend.

The private JSON descriptor has exactly `disposable: true`, `origin`, `ca_certificate` (absolute
PEM path), and `profiles` (three objects, each with absolute `store` and `key_file` paths). Each
key file contains exactly the corresponding disposable database's raw 32-byte key. These are
sensitive test fixtures; never use real user profiles, commit them, or print the descriptor or
keys. The integration test mutates these disposable stores in place. Source stores, SQLite WAL
sidecars and key files must remain under the fixture owner's control.

```powershell
$env:SCOPLEN_LIVE_PERSONAL_DEPLOYMENT = 'C:/private/disposable-personal.json'
cargo test -p scoplen-client-core --lib --features live-server-integration personal_server::live_server::live_confirmed_personal_inventory_roundtrip -- --exact --test-threads=1
```

The check bounds descriptor/certificate reads and trusts the test CA only in its own TLS clients.
It authenticates the first retained device, verifies complete K-4 keys, performs reviewed signed
ciphertext upload/download/ACK and restores the original local copy offline. Before transfer and
after encrypted-store reopen, it expires only the local access cache and exercises real refresh
through explicit account queries, checking generation, credential rotation and the non-extending
refresh-family deadline. It never changes signed JWTs, server clocks or quotas.

The production background owners require real D-75 extended CONNECT context/auth/ready. Adopted
edits must upload and reach the connected peer within 15 seconds, before the polling fallback;
unadopted hosts stay local. Both other preconfirmed devices authenticate and bootstrap using their
own saved identities. The scenario verifies signed membership, retained three-version history,
explicit offline history restoration, actual SSH host-key trust propagation, and a bounded
three-device offline edit/deletion/convergence round. Stores reopen offline with the same keys,
objects, provenance and cursors. No retired admission is performed during this coverage.

### Personal consumer process restart

Use a separate fresh disposable deployment/profile set and run this Windows/macOS test alone:

```text
cargo test -p scoplen-client-core --lib --features live-server-integration personal_server::live_server::process_restart::live_personal_process_restart -- --exact --test-threads=1
```

The controller starts two actual consumer processes under its inherited native user context.
The first imports only the closed disposable SQLCipher fixture into a uniquely owned temporary
data directory and protects that fixture's key with the real platform provider. This setup
preserves an already confirmed device identity; it does not enroll a new one. Both consumers then
use `LocalData::start` and the same canonical native slot. The first authenticates, verifies keys,
adopts and synchronizes one Host, queues an offline edit, and exits normally. Another Host stays
local. The controller waits for the genuine access lifetime to reach the production 60-second
refresh threshold, bounded by 15 minutes and an absolute run deadline.

The second process's first network action is a production account query with persisted refresh;
no new challenge precedes it. Identity, keys, session generation, access rotation and the family
deadline must match across exit. The durable offline edit then uploads, decrypts and acknowledges;
real remote history verifies both versions. No keys or tokens enter process arguments,
environment or output. Failed or uncertain operations are not retried. Cleanup addresses only
the exited consumers' uniquely owned native slot; success removes owned temporary artifacts and
failure retains them. Source fixtures remain the owner's responsibility.

These opt-in checks require runnable confirmed fixtures. Compilation does not establish live
server, native desktop interaction, macOS, hardware signing or D-128 admission acceptance.

## Membership-only Personal key revisions

Confirmed devices accept later K-4 account-key revisions without replacing
their trusted account roots or private keys. Account signing/KEM ciphertexts and the recovery
blob must match their compact admission digests. Saved neutral anchors retain the opened
epoch/key set and, when present, the exact Personal wrapping digest. These persisted anchors
remain readable independently of archived entry formats.
The device ARK wrap can be randomized again only at a higher revision and must open to the
same retained ARK. Pending rotation, a different epoch or different keys still stops sync.

The encrypted `personal_sync` snapshot also holds the highest verified revision. Lower
revisions fail; an equal revision must retain the exact key projection (`wrapped_ark`,
account signing/KEM ciphertexts and recovery blob). Certificates and revocations can change
independently, so they are fully verified on every read rather than frozen into that
projection. This device must keep its exact original, unrevoked certificate. The existing
snapshot-generation, provenance, identity and credential transaction fences prevent a competing
process from saving an older result after another process advances the floor. Neutral admission
also retains the initial floor/projection before the first `personal_sync` snapshot exists.
Offline reopening revalidates the saved roots and artifacts.

The GET response has no enclosing account signature. This local floor rejects rollback
after this device has observed a revision; it does not prove that the server has disclosed
every update or revocation. It does not implement key rotation.

The focused public-API fixture uses genuine TLS 1.3/HTTP2, signed distinct-device certificates,
DPoP proofs and SQLCipher stores, including competing bootstrap operations:

```text
cargo test -p scoplen-client-core --lib personal_server::sync::tests::membership
```

## Retained admission and retired entry regressions

Invitation, replacement and pairing network code, desktop commands and archived codecs are
removed. Run the neutral-anchor, explicit revalidation and archived-data boundary checks:

```text
cargo test -p scoplen-client-core --lib personal_server::tests::admission
cargo test -p scoplen-client-core --lib personal_server::sync::tests::a_saved_bootstrap_without_neutral_anchors
cargo test -p scoplen-client-core --lib personal_server::sync::tests::revalidation
cargo test -p scoplen-client-core --lib store::personal::tests
pnpm --filter @scoplen/app test -- personal-settings
```

Coverage includes offline reopening with saved anchors, metadata-only status without writes,
opaque and oversized archived payload preservation, rejection of session or cached-bootstrap
admission, immutable origin/Account/vault/device/key ownership, and fenced atomic revalidation.
Revalidation failures retain original bytes, including stale profile/auth generations, substituted
roots, revoked certificates, revision rollback, unsupported rotation and failed publication.
Fixtures construct public K-2 artifacts and signed K-4 updates without retired DTOs or proofs.
Retained fresh-challenge, JWKS, invalid-response, refresh, account, sync, history and notification
regressions remain applicable alongside the separate password sign-in entry flow.

## Password registration preparation and HTTPS

The public Rust preparation API uses the production D-127 profile, not a cheaper test KDF:

```text
cargo test -p scoplen-client-core --lib personal_server::registration:: -- --test-threads=1
```

The suite independently opens all generated wrappers, checks the real verifier/password
binding, create-new recovery export and explicit confirmation, failed SQL commits, exact
original bytes and fresh submit/confirm proofs across reopen, every terminal-confirmation field,
immutable/oversized pending records, existing-profile preservation and captured-store fences.
The suite serializes its genuine derivations, while production uses a process-wide fail-fast
slot. Recovery output on Windows inherits the chosen directory ACL; Unix asserts mode 0600.
No tokens, admission anchors or usable sync state may result from preparation or historical
confirmation. A request handed to a sender is conservatively unknown even if the caller drops
it without transmitting. A trusted unchanged Submit result instead requires the explicit Retry
action with fresh challenge/proof; its durable generation and rate deadline survive restart.

The independent loopback TLS 1.3/H2 peer verifies real shared request codecs and both signatures,
fresh challenge/proof binding, exact business bytes and native credential-free headers. Tests
cover historical success, dropped replies, restart/exact confirmation, trusted unchanged failures,
explicit retries, missing receipts, malformed/oversized/duplicate/inexact responses, cache/media
metadata, redirects, untrusted TLS, timeout, cancellation, future drop, profile replacement and
failed result transactions. These checks do not run production-server or native-picker acceptance.
The same suite drives the public `install_registration_profile` API over this real TLS/H2 peer.
The peer independently verifies ordinary Device signatures, JWT/JKT binding and every fresh DPoP
request before serving K-4 derived from the original encrypted public registration artifacts.
Installation tests cover original Device/private keys, separate encrypted files and keystore slots,
Local/Account namespace isolation, equal object UUIDs, two Accounts, selection/reopen generations,
valid higher membership revisions, revoked/corrupt/missing keys and certificates, authentication
denial, bad JWTs, target rollback, root publication failure, process reopen and exact retry.
Cancellation/future drop/timeout and root replacement retain unusable candidates; SQL identity,
generation and replacement guards and independent no-keystore local passphrases are exercised.
The suite also asserts that the installation future can run on a native Send executor.

The desktop uses generated commands for registration preparation, native recovery export and
confirmation, real password sign-in and Device admission, explicit exchanges, installation and
Local/Account selection. `AccountProfilesBoundary` binds all
context-sensitive commands to the captured generation, and a successful profile change remounts
the Shell. Native request admission drains before replacement; native file dialogs have a bounded
15-second drain failure that preserves the selected profile. Stop targets one operation ticket
and preserves its durable pending state. Existing retained-account roots remain accessible.
`web/app/test/account-registration.test.tsx` checks the actual frontend command surface, recovery
gates, unknown-result recovery, explicit Retry, cancellation, independent local passphrase input,
and obsolete invoker/event rejection using Tauri IPC mocks. Sign-in coverage checks transient
password clearing, no recovery-export step, explicit admission, unknown-only confirmation, safe
SignInRequired restart and existing-profile refusal. These are interface tests, not native
picker or real-server acceptance. Regenerate bindings with `pnpm bindings` and Chinese font assets
with `pnpm fonts` after command or message changes. On Windows installations where the `python3`
app alias is unavailable, run the same supported script with `python scripts/build-cjk-font.py`.

Same-catalog replacement/re-entry after Device revocation, Team contexts and macOS/native acceptance
remain incomplete.
These Rust tests substitute isolated in-memory keystore
slots for native key providers; they do not establish native keystore, picker or platform UI
acceptance.

## Native Personal notification fault tests

The independent TLS 1.3/H2 peer verifies context/auth/ready, CONNECT/token-bound fresh DPoP,
fragment reassembly, complete message limits, text and invalid ordering, close replies,
bounded handshake timeout, fresh reconnect, durable refresh, typed revocation and stale-session
invalidation. Runtime tests cover no network before bootstrap, initial catch-up, coalesced hints,
foreign-vault hints, remote apply without a feedback loop, adopted local edits, 60-second fallback,
FIFO confirmed adoption, rotation during an active pull, and replacement/shutdown during a sent
write. A separate cancellation test checks serialization with the synchronous commit boundary.

```text
cargo test -p scoplen-client-core --lib personal_server::sync::tests::notification
cargo test -p scoplen-client-core --lib personal_server::background::tests
```

## Upload source admission regressions

Run the native source-admission and related file-access tests with:

```bash
cargo test -p scoplen-client-core --lib session_files::tests::
```

On Windows, these tests create real file symlinks and verify their reparse attributes.
The replacement regression deterministically substitutes a symlink between the path
preflight and the production handle-admission step; it does not rely on a timed race.
Enable Windows Developer Mode or use an account with the Create symbolic links privilege.
A permission error fails the tests; an unavailable symlink fixture is not passing evidence.
An ordinary-file test also checks that replacing the path after admission does not
redirect reads from the retained handle. Unix additionally checks FIFO rejection.

## Remote text preview checks

```text
cargo test -p scoplen-client-core --lib preview
pnpm --filter @scoplen/app test -- session-files
```

The independent SSH/SFTP peer checks complete UTF-8, empty and exact-cap text, bounded short
reads, progressing reads beyond one step deadline, stalled-request timeout, EOF growth and
shrinkage, type/size/modification changes, control/encoding refusal,
malformed EOF-probe packets, cleanup refusal and cancellation followed by a fresh channel.
Manager checks cover serialized admission, live terminal input/resize, cancellation, the
60-second absolute deadline and late replies after transport replacement. The public OpenSSH
Files fixture also checks real UTF-8, empty and exact-cap previews, binary/control/link/folder
and permission refusals, continued terminal input/resize and absence of local preview files.
The frontend suite covers literal rendering, localized refusal/retry, tab/transport fencing,
late cancellation, queue admission and keyboard focus after delayed directory loading.
Rendered English and Chinese checks cover literal text, empty/error/retry states, long file
and connection names, narrow-window content scrolling and visible keyboard closing controls.

## Native drop checks

```bash
cargo test -p scoplen-client-core --lib file_drop
cargo test -p scoplen-client-core --lib session_transfers
cargo test -p scoplen-client-app --lib file_drop
```

Core regressions exercise whole-batch capacity, FIFO order, invalid later sources, duplicate
names, file-type refusal, expiry/replay and context/transport races while local opening is
blocked. The absolute-deadline regression returns a refusal and re-reserves every queue slot
before releasing the blocked opener. The disposable OpenSSH Files fixture exercises admitted
batches through the public session manager and ordinary per-item transfer behavior. Frontend
component tests cover path-free event hit testing, stale views, modal refusal and localized
feedback. Synthetic coordinates and direct manager calls do not establish native drag
acceptance. Before marking the native-drop roadmap outcome complete, perform real file drops
on scaled Windows and Retina macOS, including empty directories, resizing, zoom and refusal
outside the Files list.

## Upload continuation checks

```text
cargo test -p scoplen-client-core --lib session_files::uploads
cargo test -p scoplen-client-core --lib session_manager::transfers
cargo test -p scoplen-client-core --lib session_transfers
pnpm --filter @scoplen/app test -- session-transfer-queue
```

The independent SSH/SFTP peer records actual WRITE offsets and retained handles across
repeated pauses, separately from validation READ requests. Regressions cover first-Pause
staging verification, metadata-preserving source/staging prefix changes, pathname replacement,
changed targets, staging-read refusal and uncertain admission, cleanup, cancellation and lost
publication replies. Queue tests exercise fresh FIFO executions, retained capacity and stale
messages. The disposable OpenSSH Files example also exercises upload Pause/Resume through
the public queue with later queued work, terminal input/resize and exact saved bytes.
These checks do not establish cross-transport or process recovery, immutable source/staging
files, inode identity, or physical-platform UI acceptance.

## Standalone tunnel checks

```text
cargo test -p scoplen-client-core --lib forward_manager::tests
cargo test -p scoplen-client-core --lib forward
pnpm --filter @scoplen/app test -- tunnels
pwsh -NoProfile -File scripts/test-ssh-local-forward.ps1
pwsh -NoProfile -File scripts/test-ssh-dynamic-forward.ps1
pwsh -NoProfile -File scripts/test-ssh-remote-forward.ps1
```

Core regressions cover frozen configuration and Login identity, concurrent peers and
half-close, pending channel opens, capacity and deadlines, occupied listeners, target
refusal, idle and active SSH loss, preparation cancellation, stale replies, traffic
coalescing, retained snapshots, store release and shutdown admission. The disposable
OpenSSH check disables session channels on its forwarding listeners and verifies binary
payloads, EOF trailers, exact counters, Direct and Jump authentication, owned resource
release and a separate usable terminal. It requires Docker and `ssh-keygen`.

Frontend checks exercise generated commands and events, view changes, fixed identity,
secret-input cleanup, stale revisions and replies, deletion during a run, keyboard
operation and English/Chinese states. Synthetic IPC and browser rendering do not establish
native desktop or complete C7 acceptance. Failed OpenSSH runs retain private diagnostics
in their owned temporary directory and stop the owned container; successful runs clean up.

Remote additionally checks exact delivered-channel metadata, Streamlocal/Agent refusal,
bounded local resolution/connect, late resolver fencing, fixed-port acknowledgements and
unknown registration/cancellation. Its disposable OpenSSH fixture uses `MaxSessions 0`
and actual incoming connections to client-owned TCP services. Direct and Jump runs require
two peers to deliver a prefix before either can continue, then verify binary payloads,
half-close in both directions and exact counter direction. The fixture covers encrypted-key
and Interactive preparation, occupied ports, forwarding denial, local refusal/recovery,
requested versus actual `GatewayPorts` scope, Stop, SSH loss, complete parent release and
an independent terminal. Only the fixture's container/listeners and private scratch files
are inspected or changed; it needs Docker and `ssh-keygen` in addition to the Rust toolchain.

## Generated files

| File | Regenerate with | When |
| --- | --- | --- |
| `web/app/src/ipc/bindings.ts` | `pnpm bindings` | A command or a type it uses changes |
| `web/ui/src/fonts/scoplen-serif-sc.woff2` and `.json` | `pnpm fonts` | `web/app/src/messages/zh-Hans.ts` changes |
| `src-tauri/icons/*` | `pnpm icon` | The mark geometry changes |

Tests fail while the bindings or the font are out of date.

## Writing interface copy

Add the English message to `web/app/src/messages/en.ts` first, then write the Chinese in `zh-Hans.ts` as natural Chinese, not a sentence-by-sentence translation, using the vocabulary of `scoplen-docs/11-client-architecture.md` §4.1. Use ICU plural and select forms rather than concatenating strings.
