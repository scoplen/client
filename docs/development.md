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

The opt-in `live-server-integration` feature checks the production Personal enrollment,
device authentication, second-device pairing, sync-key verification, native notifications and reviewed inventory APIs against an
independently running server. It does not read server source or seed its database.

Prepare a fresh disposable server on `https://localhost:<port>` with a trusted test CA.
Complete public Operator setup and login, then issue an unused Personal invitation. Put a
JSON descriptor in a private file with exactly `disposable: true`, `origin`,
`invitation_url` and `ca_certificate` (the PEM certificate's absolute path). Keep the
descriptor and server output private; the invitation is a one-use credential.

In PowerShell, point to that existing private descriptor and run:

```powershell
$env:SCOPLEN_LIVE_PERSONAL_DEPLOYMENT = 'C:/private/disposable-personal.json'
$env:SCOPLEN_LIVE_PAIRING_MODE = 'png' # omit for the manual link/password path
cargo test -p scoplen-client-core --lib --features live-server-integration live_server:: -- --test-threads=1
```

The test rejects a non-loopback origin, bounds descriptor and certificate reads, and adds
the test CA only to its own HTTPS and TLS 1.3/H2 notification clients. It consumes the invitation, creates and reopens
an isolated SQLCipher store, uploads and downloads a signed encrypted host and its edit,
checks durable acknowledgements, and restores the original local copy offline. Before the
first transfer and again after reopening the store, it expires only the client's cached
access lifetime and exercises the production refresh path using the genuine server-issued
refresh credential through explicit account queries. The real profile and complete signed
device list must bind to the retained account and current device, then revalidate offline
after reopening SQLCipher. It checks durable session generation, a changed access credential and
the retained refresh-family deadline ceiling; server clocks and signed JWTs are unchanged.
The remaining whole seconds and JWT issuance time can be sampled independently. Rotation
uses their lifetime estimate conservatively and never extends the retained ceiling.

After the first reviewed upload, the test starts the production Rust background owner without
Settings. It requires a real D-75 extended CONNECT context/auth/ready exchange, then uploads and
acknowledges an adopted local edit automatically. Expiring only the local cache exercises actual
refresh and notification reconnect before orderly owner shutdown. No alternate WebSocket path
or server-private test control is used.

The same test then creates a second independent SQLCipher store and HTTPS client. It pairs
through a public link and separate password by default, or through real QR rendering and local
PNG recognition when `SCOPLEN_LIVE_PAIRING_MODE=png`. It verifies the old device's authenticated review,
explicitly approves admission, and requires the new device's real native authentication and
complete K-4 bootstrap. Both devices query the signed two-device list. A pre-existing local
host stays local throughout setup and the first explicit download; only a later preview and
confirmation uploads it. Both production background owners then run concurrently. Local store
edits on each device must upload automatically and reach the connected peer through real
notifications, with matching durable applied/acknowledged cursors. Each direction has a
15-second deadline, shorter than the 60-second polling fallback; no manual sync intent follows
either edit. New unadopted hosts remain local on both devices throughout these transfers.
Both owners shut down normally, and retained keys, account statements, synchronized objects
and local-only hosts revalidate after offline store reopen. No server database or private
test control is accessed.

After both devices have edited the same host, the scenario queries its complete retained
history through real HTTPS. All three versions must verify, including the paired device's
signature, without exposing host addresses or advancing local cursors. An explicit offline
restore creates exactly one unadopted copy of the oldest version, preserves the current
object and server history, consumes its review ticket, and survives SQLCipher reopen.

A third independent device then completes the same public pairing ceremony, and all devices
verify the signed three-device list. The original device explicitly confirms a disposable
SSH peer's actual key, then adopts its Host, Login, Credential and generated trust record.
Both paired devices verify that record through Personal synchronization and authenticate
to the SSH peer without another trust prompt. Source provenance and key bindings revalidate
after offline SQLCipher reopen. This Rust SSH peer does not establish OpenSSH or native
desktop interoperability.

Two separate hosts are explicitly adopted for an offline
round with every background owner stopped. Each store changes the same name and a different
field; the second device also edits and then tombstones the other host. Before reconnecting,
each durable outbox and cursor must reflect only its own changes. One parallel synchronization
round and one fixed catch-up round must succeed within 30 seconds, without retrying any failed
or uncertain operation. All three devices must retain the merged fields, hide the deletion,
acknowledge the same cursor, preserve unadopted local contents and reopen offline with the same
objects and signed membership. The original three-version history object is unchanged. This
does not exercise server retention or cursor expiry.

The deployment must expose the production pairing endpoints. Repeating the test requires a
fresh disposable deployment and invitation. Run it separately for SQLite and PostgreSQL.
Remove the private descriptor, test server and its temporary data after verification. This
does not establish native desktop picker interaction, camera capture, physical passkey or macOS acceptance.

## Membership-only Personal key revisions

Retained first and paired devices accept later K-4 account-key revisions without replacing
their trusted account roots or private keys. Account signing/KEM ciphertexts and the recovery
blob remain byte-identical to the retained enrollment or authenticated handoff. The first
device retains its exact epoch-1 wrapping; a paired device opens every handoff epoch and
requires the unchanged epoch/key set.
The device ARK wrap can be randomized again only at a higher revision and must open to the
same retained ARK. Pending rotation, a different epoch or different keys still stops sync.

The encrypted `personal_sync` snapshot also holds the highest verified revision. Lower
revisions fail; an equal revision must retain the exact key projection (`wrapped_ark`,
account signing/KEM ciphertexts and recovery blob). Certificates and revocations can change
independently, so they are fully verified on every read rather than frozen into that
projection. This device must keep its exact original, unrevoked certificate. The existing
snapshot-generation, provenance, identity and credential transaction fences prevent a competing
process from saving an older result after another process advances the floor. A paired identity
also retains its initial floor/projection before the first `personal_sync` snapshot exists.
Offline reopening revalidates the saved roots and artifacts.

The GET response has no enclosing account signature. This local floor rejects rollback
after this device has observed a revision; it does not prove that the server has disclosed
every update or revocation. It does not implement key rotation.

The focused public-API fixture uses genuine TLS 1.3/HTTP2, signed distinct-device certificates,
DPoP proofs and SQLCipher stores, including competing bootstrap operations:

```text
cargo test -p scoplen-client-core --lib personal_server::sync::tests::membership
```

## Second-device pairing

The native core implements D-114 QR screenshot and public-link plus separate-password pairing. Create on the
new device and join on an authenticated existing device are explicit actions against the exact
selected HTTPS origin. Rust owns the CPace state, one-attempt ledger, monotonic five-minute
ceiling, at least two seconds between polls, device confirmation, immutable slot replay and
strict shared crypto/API codecs. A canonical public link contains only origin and UUID; the
password and rendered QR matrix cross only the dedicated transient display/input boundary.

The PNG entrance accepts a regular file up to 8 MiB, at most 4096 pixels on either side and
4,194,304 total pixels. PNG decoder allocations and decoded output are each limited to 32 MiB;
this is not a whole-process memory budget for the QR recognizer. Decoding validates the complete
static PNG, including IEND and CRCs, rejects APNG and requires exactly one detected QR.
Grayscale, grayscale-alpha, RGB and RGBA expand locally, with transparency composited on white.
Recognition uses `rqrr`; shared `PairingQrPayload::decode` then rejects legacy or noncanonical
text. Origin mismatch, malformed input and detached foreground intents fail before a claim.
The QR digest is verified against authenticated CPace peer keys before device confirmation.
Source bytes, decoded pixels and recognized output use zeroizing buffers; dependencies may
retain temporary decoder/detector allocations until drop. Nothing is logged, uploaded, opened
as a URL or saved to the application database. No camera permission is requested.

Migration 10 stores pending device keys, exact transcripts/plans and an authenticated handoff
as distinct Personal provenance. New identity and exact acceptance commit atomically before
slot 7; the old device verifies possession and saves complete approval JSON before `complete`.
Lost replies keep these checkpoints. Explicit recovery reads the receipt or authenticates the
retained device before replaying the saved bytes. No CPace state or password is serialized.
A restart before handoff requires a fresh session while retaining device keys. A paired
installation has no enrollment request, no invented recovery key and no enrollment-attempt
flag; it becomes complete only after native authentication and full K-4 verification.

Device keys and their creation time are durable before the first session request. If no valid
session checkpoint or account identity exists, an explicit retry can correct the origin/name
with an atomic conditional metadata update. The first saved session checks that exact retained
device record in the same transaction, so a competing process cannot bind stale metadata.
Once a session exists, retries retain its original origin and device name.

The independent TLS 1.3/H2 peer drives both public Client managers and verifies checkpoints
before receiving messages. Focused coverage includes wrong passwords, changed duplicates,
strict cache headers, restart before/after handoff and acceptance, uncertain complete with
and without admission, exact replay, first-response rollback/projection rejection, higher
membership revisions, account queries, explicit encrypted inventory sync and offline reopen:

```text
cargo test -p scoplen-client-core --lib pairing
```

This fixture does not establish a released Server deployment or two physical desktop
installations. Native QR display and PNG recognition are connected to desktop IPC/UI; key rotation remains
unsupported. The public-link/password path retains every Personal epoch supplied by the
verified handoff and never uploads pre-existing local inventory during account setup.

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

## Generated files

| File | Regenerate with | When |
| --- | --- | --- |
| `web/app/src/ipc/bindings.ts` | `pnpm bindings` | A command or a type it uses changes |
| `web/ui/src/fonts/scoplen-serif-sc.woff2` and `.json` | `pnpm fonts` | `web/app/src/messages/zh-Hans.ts` changes |
| `src-tauri/icons/*` | `pnpm icon` | The mark geometry changes |

Tests fail while the bindings or the font are out of date.

## Writing interface copy

Add the English message to `web/app/src/messages/en.ts` first, then write the Chinese in `zh-Hans.ts` as natural Chinese, not a sentence-by-sentence translation, using the vocabulary of `scoplen-docs/11-client-architecture.md` §4.1. Use ICU plural and select forms rather than concatenating strings.
