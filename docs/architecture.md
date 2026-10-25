# Architecture

The canonical architecture is `scoplen-docs/11-client-architecture.md`. This page records how this repository realizes it.

## Layers

```text
web/app (React)  ── typed commands, binary channels ──  src-tauri  ──  scoplen-client-core
      │                                                                      │
   web/ui (design system)                              web/terminal (@scoplen/terminal)
                                                            │
                                               caller-owned Uint8Array streams
```

- `web/app` renders state and sends intents. It never performs cryptography or talks to the
  network. Private keys, decrypted account packages and tokens remain in Rust. Dedicated
  transient SSH/passphrase and D-114 pairing inputs are the narrow secret-input exception;
  only the new-device pairing view may display its one-time password and QR matrix. Ordinary state never
  carries these values.
- `src-tauri` adapts commands to `scoplen-client-core` and owns windows. Its capability file (`src-tauri/capabilities/main.json`) grants the main window only Tauri's core defaults and the application's own commands. The content security policy in `tauri.conf.json` allows only the application's own resources and IPC.
- `scoplen-client-core` holds every behavior, so it is the same on both platforms and testable without a window.
- `scoplen-client-platform` is the only crate that may contain `unsafe` code or FFI; it is denied by default there too and allowed per module with each block documented.

The shared libraries and Pageant patch are pinned to `proto@b1748dd`. That revision
supplies kind-8 descriptor validation and the D-121 asynchronous challenge API with
zeroizing response custody. D-116 adds the object-safe
`Signer::sign_async` hook, awaited by concrete SSH authentication. The built-in agent signer
runs each serialized signing exchange on Tokio's blocking pool. Existing synchronous signers
retain the default hook; other blocking providers need their own override. SSH and agent wire
bytes remain unchanged.

The client lockfile retains HPKE and P-256 0.14, `crypto-bigint` 0.7.6 and `ctutils` 0.4.5 for
RUSTSEC-2026-0387, without the former 0.5.5 bigint/P-256 0.13 dependency path. Updating the shared
pin requires checking the client's own transitive lockfile; the shared repository's lockfile
does not constrain consumer resolution.

## IPC

Commands are declared in `src-tauri/src/commands.rs` with `#[specta::specta]`. `pnpm bindings` writes `web/app/src/ipc/bindings.ts` from them; a test fails when the committed file differs from what the commands generate, so the frontend and the core cannot drift.

Streams use Tauri channels carrying raw binary frames: `FrameSender` on the Rust side (`src-tauri/src/frames.rs`) and `frameChannel` on the frontend (`web/app/src/ipc/frames.ts`). Frames arrive intact and in order; nothing is encoded as JSON.

The interactive `session_connect` command has a separate typed readiness channel.
It sends once authentication, optional PTY allocation, and the shell request
succeed. The view becomes connected on that notification, independently of
terminal output. Ended and unsubscribed views ignore late notifications.

Keyboard-interactive preparation resolves an explicit kind-8 Credential on each
saved target or Jump Login. Missing Credential references retain the existing
local-material selection policy. Ordinary authentication continues only from valid
partial success advertising keyboard-interactive. Rust retains the same reviewed
connection, preserves RSA rejection metadata, and opens channels only after full
success. Unsupported further factors fail explicitly.

Each hop's authentication has a 300-second absolute deadline after trust, including
key passphrase entry. Every server challenge has a 120-second reply deadline capped
by that budget. Pending metadata checks its deadline, expected answer count, response
kind and one-use prompt id under the response lock. `session_respond` also names the
active transport. Cancellation and errors discard pending state and release the chain.
Uncontrolled, echo-aware DOM fields are the dedicated transient input boundary;
literal server text remains separate from trusted hop identity. Both echo policies
are sensitive. Answers become zeroizing Rust values at IPC, never enter snapshots
or stored records, and are not reused by reconnect. Zero-prompt requests require
an explicit empty response.

Pairing uses dedicated create/join commands for its transient password boundary. The general
`personal_pairing_status` command reads only public local metadata. An explicit foreground
`watch_personal_pairing` invocation drives bounded core progress and sends safe typed status;
its Rust-registered observer id fences stale notifications. Registration precedes scheduling;
a detached observer cannot restart when its async command arrives late. Detaching stops
further cycles after the current bounded core operation without cancelling or deleting its
durable checkpoint. A subsequent intent waits for the bounded tick to release its operation
lock. No settings-mount effect resumes network activity. Confirmation and
admission recovery require distinct intents; all protocol state remains in `PersonalServer`.

## Terminal package

`web/terminal` publishes `@scoplen/terminal`, a framework-agnostic custom
element and a React binding. The source and sink boundaries accept
`Uint8Array` frames (including Web Streams); subscriptions receive an
`AbortSignal` and must provide cancellation. The element serializes sink writes,
enforces bounded output/input/pending-write limits, and cleans up source
subscriptions when disconnected. The package has no Tauri or client-core
dependency, so the server web console can consume the same API. xterm.js core
renders ANSI terminal state and bounded scrollback; the search addon, profile,
clipboard, and explicitly confirmed broadcast APIs remain inside this boundary.
`TerminalWorkspace` stores session-agnostic tab and nested split layout state;
the caller binds terminal elements and transports to each pane. Renderer
initialization has an accessible bounded text fallback and reports a typed
error when host capabilities are missing. WebGL, Unicode width addons,
serialization, image protocols, platform-wide IME verification, and the
`vttest`/`esctest` compatibility suite remain later C4 outcomes.
The package copies xterm's stylesheet into its distribution and loads it inside
the terminal custom element's shadow root, so the renderer styles are scoped to
the component in both desktop and browser consumers.

## Local data

`scoplen-client-core::store` is the SQLCipher store. It is opened with a raw 32-byte key, so SQLCipher runs no key derivation of its own; a wrong key fails on the first page. Migrations in `store/migrations.rs` run at startup in one transaction, and a store with a newer schema than the build knows is refused rather than modified. Replicated objects are kept as their deterministic CBOR envelopes with per-field clocks. A local write is stamped with the next device clock, applied to the stored object, merged with the stored version through `scoplen_model::merge`, validated, and committed; subscribers hear about it only after the commit. The store also enforces the 100,000-objects-per-vault limit (D-36). Objects created before sync enrollment have no vault.

`local_key` decides how the database key is protected: by the platform keystore (`scoplen-client-platform::keystore`), by the keystore plus a passphrase envelope (`scoplen_crypto::LocalDatabaseKeyEnvelope`), or by the passphrase alone on a system without a keystore. Setting or changing the passphrase rewraps the same key, so the store is never re-encrypted. `local_data` is the state machine the interface drives: open, needs passphrase, needs a new passphrase, or unreadable. An unreadable store is renamed and kept, never deleted.

Windows keystore deletion opens only the slot's exact current-user name in the Platform Crypto
Provider. Key opening uses `NCRYPT_SILENT_FLAG`; deletion uses the provider's default flags.
Only `NTE_BAD_KEYSET` from that key-open call confirms absence. Provider-open, other key-open
and deletion failures are returned without removing the protected blob. The native slot is
checked even for DPAPI or missing blobs: an earlier TPM wrapping attempt can leave a native key.
Once native deletion succeeds or absence is confirmed, the adapter removes the blob. A file
removal failure is returned; deletion can be retried against the now-absent native slot.
The native deletion and file removal are separate operations. TPM-backed deletion still
requires acceptance on a real TPM-equipped device.

`repository` gives typed access to every object type of `04-object-model.md` §4. A record is a read view of a stored object; a change names only the fields it sets, with `Edit::Clear` writing `null` to clear an optional field (D-57) and map changes naming the entries to set or remove. Because a change touches only its own fields, fields this build does not know survive every write. Credential secrets are never part of a record: `credential_secret` reads one when a connection needs it, and a change containing a secret is redacted when formatted. Gateway networks are authored by the organization's server and are read-only on a device.

The C3 independent-object facade builds on those typed records rather than
letting the interface edit raw fields. AccessProfiles, Credentials, and local
Routes have separate redacted DTOs and input validation. Profile creation or
replacement and the Host default reference are committed together, while
deletion checks Forward, Workspace session, jump-route, profile, and route
references first. Shared credential input material is wrapped in `SecretVec`;
device-bound password input is written to the device-local credential table.
Creating a device-bound key asks the platform crate to generate a P-256 key,
protect the scalar in a per-credential macOS Keychain or Windows keystore slot,
and return an opaque `device-keystore-v1:<credential-id>` handle. The
credential object stores this device's OpenSSH public key in its `devices` map;
the local table stores only the handle. Connection planning validates the
handle, resolves it just before signing, and wraps the returned scalar in
`SecretVec`. Hardware-bound credentials never accept pasted material, and
`SecurityKey` returns a typed unsupported-capability error until the
libfido2/WebAuthn interaction boundary is implemented. Neither private form
is ever present in a result, debug representation, or IPC error.
Managed Routes remain readable but reject local create, update, and delete
operations until the organization client owns them. Profiles and Routes whose
references were tombstoned by another device remain visible as orphaned items;
the restore command writes the missing object through the normal model path,
while deletion removes the dependent object after the usual reference checks.

After every committed change the shell sends the frontend a `storeChanged` event with the type and identifiers of the changed objects; `useStoreChanges` (`web/app/src/ipc/store-events.ts`) subscribes to it. `LocalData` keeps the listener attached to whichever store is open, so events continue after unlocking or starting with empty data.

`SQLCipher` is built with a vendored, statically linked OpenSSL on both platforms, so a build never links a system OpenSSL by accident.

## Personal account identity

Migration 4 retains the chosen canonical HTTPS origin, generated account/device/vault identity,
software private keys, recovery key, and exact signed enrollment artifacts inside SQLCipher before
network access. Recovery export writes directly from Rust through a native picker; joining requires
a separate explicit confirmation that the recovery file is safe. The frontend receives only public
status and typed errors. Account setup does not move or upload existing local inventory.

An enrollment request is durably claimed before sending. A connector failure known to precede
HTTP transmission restores readiness; a timeout, denial, or uncertain response retains the claim
and requires fresh challenge/device authentication. Authentication verifies the exact selected
issuer's JWKS, account/device identity, device-key binding, and access-token expiry. The original
certificate, K-4 update, and wraps remain stored after authentication; none is regenerated as a
recovery shortcut.

`update_personal_invitation` implements D-109. It first rejects malformed or different-origin
links, then obtains a fresh challenge and signs a device request with the retained key. Verified
authentication ends recovery without changing or redeeming the replacement invitation. Only a
noncached, no-store `401 application/problem+json` response to that device request, parsed as
the complete shared RFC 9457 problem with `status: 401`, exact `auth.authentication_required`,
and `retryable: false`, allows replacement. A challenge denial, catch-all authentication error,
explicit revocation, unknown code, malformed or oversized body, redirect, transport failure,
or invalid token leaves the old request pending. Neither value of `changed` proves enrollment
success or failure.

Replacement changes only the token and its D-101 device possession signature, retains all ids,
keys, recovery confirmation, certificate, bundle, and wraps, and atomically restores Join readiness
only if the saved request still matches and no verified credentials have appeared. Import sends
no invitation token; a separate explicit Join submits the new request. Missing or inconsistent
saved artifacts fail closed rather than recreating identity. The transport bounds responses and
timeouts, verifies TLS, and has no redirect, proxy, cookie, or automatic POST retry behavior.
Hardware device signing remains a separate outcome.

`PersonalServer` also owns D-114 second-device pairing. The new device durably retains its
signing/KEM keys before creating the anonymous relay session. The existing device claims the
public link using its current D-100 session and fresh, request-bound DPoP with `keys:write`.
CPace, both confirmations and authenticated frames run only in Rust. SQLCipher records a
per-session attempt ledger, so switching sessions or restarting cannot reuse a CPace attempt;
the password, scalar and ISK are never persisted. A monotonic five-minute deadline and Rust's
two-second polling interval bound each foreground ceremony.

The existing device requires explicit approval of authenticated name/platform claims. Before
disclosing slot 6 it saves the exact certificate, complete membership-only K-4 update and
handoff. The new device verifies the existing-account roots, revision floor, account ciphertexts,
Personal key projection and all retained epochs, then atomically saves its pending identity
and exact possession signature before slot 7. The old device retains the exact acceptance and
approval JSON before completion. Checkpoint recovery uses the stored bytes without CPace;
an earlier interrupted ceremony requires a fresh session/password while keeping the new keys.
Unknown completion is checked through the retained receipt or fresh device authentication.
New-device completion additionally requires verified D-100 authentication and full K-4 bootstrap.
Old-device completion confirms admission only. Pairing creates no invitation or recovery key,
and the paired identity cannot export a fabricated recovery file.

The dedicated create command returns the secret QR as a monochrome module matrix beside
the one-time password. The UI draws that matrix without interpreting the payload. The native
PNG picker keeps file paths, image bytes and recognized text in Rust. A foreground registration
fences abandoned picker/decoder results before a claim. Bounded PNG decoding precedes strict
QRv2 decoding; the account origin is checked before network work, and the QR digest is checked
against authenticated peer keys before `confirm_device`. The expected QR binding is volatile,
so restart behavior and saved checkpoints remain the same. Rendering failure retains the
valid manual session, public link and password.

Migration 8 adds a monotonically increasing authentication generation, the verified scope ceiling,
single-use refresh claim and an optional Retry-After deadline, alongside the saved absolute family
expiry. Initial authentication accepts exactly D-107's initial scope set. An explicit
key-verification or sync action refreshes when the access lifetime received from the server, capped by the verified JWT
expiry, has at most 60 seconds remaining. Status, offline key reads, inventory reads and recovery
never initiate refresh. The active background owner refreshes before reconnecting near expiry.

A FULL-synchronous IMMEDIATE transaction captures the current credentials and consumes them
locally before refresh I/O. Other processes cannot claim the same credential. Success verifies
same-origin JWKS, signature, issuer/audience, account/device/JKT, Personal membership shape,
scope subset and non-extending absolute refresh expiry before a generation/identity/device-key
CAS atomically publishes both new tokens. A fresh signed-device exchange also has a durable
generation fence; a late refresh or authentication response cannot overwrite a newer session.
Protected requests recheck the local generation before sending, and a 401/403 invalidates the
matching session without clearing offline keys or inventory.

Cancellation, crash, malformed or unverifiable success, lost response and unknown commit leave
the refresh claim spent. Recovery is an explicit fresh challenge, never an old-token replay.
Only an exact noncached no-store/no-cache unchanged nonce problem allows one immediate retry
with a fresh proof; an exact unchanged storage or rate-limit problem restores the claim for a
later operation. A rate limit requires a canonical decimal Retry-After between 1 and
300 seconds and persists its deadline. A connector failure proven to precede transmission also
restores the claim. Rejected or unverifiable responses never
restore it. Legacy sessions lacking a verified scope ceiling require fresh authentication;
their identity, original artifacts and saved bootstrap are retained.

`PersonalServer::query_account` is an explicit read-only operation for D-99/D-113. It reuses
the same native refresh owner, validates the issuer/account/device/JKT and exact `account:read`
scope, and binds a new token-specific DPoP proof to each GET. The TLS 1.3 transport bounds the
profile to 4,096 bytes and device statements to 6,291,456 bytes; shared codecs require exact
cache-prevention metadata and the profile's matching ETag. Redirects, compressed responses,
duplicate metadata and wrong media types fail locally. This action does not bootstrap sync
keys, move inventory or mutate device membership.

The entire statement set is decoded and verified against the locally retained account signing
key. Every certificate must bind that account; duplicate certificate and revocation device ids
are rejected, all revocations are applied, and the active set must contain the exact retained
current-device certificate. No response-provided key becomes trusted. Names and platforms are
signed claims; the set cannot establish a malicious server's completeness or freshness and is
not used to bypass K-4 anti-rollback or rotation validation.

Migration 9 stores the raw bounded profile/device responses and local manual-query completion
time as one SQLCipher snapshot. Cryptographic verification and durable publication run off the
async executor. A single FULL-synchronous statement replaces both only while the original
authentication generation, unexpired token, origin, account and retained identity still match.
Failure or a stale session preserves the prior snapshot. `personal_account_snapshot` reverifies
the saved statements locally even after authentication expiry; it never initiates refresh or
network I/O. Safe IPC carries only account id/email, active signed names/platforms/ids and the
current-device flag plus the local query time, without certificates, keys or credentials.

`PersonalServer::bootstrap_sync` is the Rust-only K-4 retained-identity boundary. It revalidates the
retained access token against same-origin JWKS, its account/device ids and device thumbprint,
expiry, and both `keys:read` and `sync:read` scopes. Its separate HTTP/2-only client requires
TLS 1.3, verifies platform trust, and sends canonical CBOR with a fresh DPoP proof bound to
each method, URI, token, and signing key. No redirects, cookies, proxies, or retries are used.
Each complete response is independently capped at 4 MiB; server-announced quotas never
change this budget. Session descriptors, including unknown kinds, are retained verbatim.

The bootstrap reads `POST /sync/v1/session`, `GET /sync/v1/keys`, and the retained Personal
vault's keys. It verifies the retained enrollment or paired handoff, account signature, signed device list and
revocations, exact local certificate, device ARK wrap, encrypted account signing/KEM keys,
recovery ARK, and Personal epoch key using shared `scoplen-crypto` constructions. Decrypted
material must equal the retained private material. Membership-only revisions may advance while
the anchored account ciphertexts, recovery artifact and complete Personal epoch-key projection
stay unchanged. This device's unchanged ARK may have a fresh valid wrap. The persisted revision
floor prevents rollback after restart; paired provenance anchors its first bootstrap. All
retained Personal epochs remain available for older envelopes. New or pending key rotation
returns the distinct `RotationRequired` result and preserves the old snapshot. Other vaults
are metadata only.

Migration 5 adds a single encrypted `personal_sync` snapshot with the raw session/account/vault
responses. A FULL-synchronous transaction publishes all three only while the original
identity, enrollment request or paired handoff, device keys, unexpired access token, and prior snapshot generation
still match. A competing authentication, invitation update, or bootstrap cannot publish a
stale result. `load_sync_bootstrap` decodes and cryptographically revalidates all artifacts on
restart without requiring network or an unexpired token. Its secret key handle stays in Rust;
there is no IPC export or automatic inventory migration.

`sync_personal_inventory` is a separate Rust-owned one-shot action (D-112). The caller names the
retained vault and exact object ids whose upload was confirmed. Existing local object references
must already belong to that vault or be explicitly selected; references never expand selection.
Migration 6 adds immutable K-1 adoption copies, per-object base sequences and dirty markers,
and separate applied/confirmed-ack cursors. Adoption, copies, ownership and queuing commit together
with FULL synchronous durability. Every subsequent local write, tombstone and restoration marks
an adopted object dirty inside its normal transaction. New objects stay local until selected.
The immutable copies restore as new local ids; references within the restored selection are
remapped at known K-1 reference fields only. Opaque secrets, unknown fields, device ids, and
account ids are preserved. Device-local credential secrets and handles are not duplicated.

Each cycle requires `keys:read`, `sync:read` and `sync:write` and refreshes the verified bootstrap.
It pulls before writing, separates canonical query parameters from the DPoP target, checks the
Personal envelope's epoch and certified signer against its response metadata, verifies signatures
and AEAD, and checks the decoded object's id/type/schema and tombstone. All objects on a page
must validate before one immediate transaction merges fields, advances the local HLC, queues
unpublished local differences, updates bases, and advances the applied cursor. Notifications
follow commit. Cursor compare-and-swap prevents another store from publishing stale progress.
Unknown object types and fields retain their K-1 representation.

Only after the page is durable does the client acknowledge its applied cursor. A larger server
ack maximum cannot move either local cursor. An uncertain acknowledgement retains the applied
cursor and earlier confirmed ack; the next cycle rechecks the feed before acknowledging.
The complete response budget is 9 MiB, individual envelopes at most 1 MiB, change pages at most
eight objects, and writes at most eight objects / 4 MiB further limited by session announcements.
Each cycle bounds pages, batches and conflict retries. `more` reports a safe continuation point.
The HTTP Date header must be present and the device wall clock within the specified forward-skew
limit before writes. The native background owner schedules bounded continuations and recovery
cycles only for already adopted Personal objects.

`PersonalSyncRuntime` starts at native startup and follows local-store unlock, creation, reset
and shutdown independently of Settings. It remains inactive until a saved bootstrap passes
offline identity/key-anchor verification. Store replacement cancels the old future and its
HTTP requests, reconnect delays and HTTP/2 driver. A cancellation guard serializes each synchronous
local commit with store replacement and shutdown; late old responses cannot commit or publish status.
Store authentication/bootstrap watches wake
the owner; object subscriptions schedule only a dirty adopted outbox. Remote-only apply and the
cycle's own bootstrap signals do not create a self-triggered loop. Manual inventory requests
wait at the same FIFO operation mutex, preserving their exact reviewed object/version selection.
Background requests always carry an empty adoption list and never consume a review ticket.

Notifications use platform certificate verification, TLS 1.3, negotiated HTTP/2 extended CONNECT
and the shared D-75 context/auth/ready codecs. A fresh DPoP proof binds the actual CONNECT method,
canonical HTTPS target, current access token and retained device key. Complete reassembled
messages are bounded to 16 KiB before CBOR parsing; text, invalid ordering and oversized data
close safely. Credentials are sent only in the first binary auth message. Control frames and
bounded close handshakes remain active. Thirty-second Ping/Pong checks detect a silent socket.
Each reconnect uses fresh credentials/proof and schedules catch-up, with exponential delays
capped at 60 seconds. An unavailable socket enables polling every 60 seconds.

Hints coalesce; they never advance the durable change cursor. Typed revocation invalidates only
the captured token/generation and fences further requests; a 1008 close alone does not revoke.
Rotation hints increment a store key-retrieval fence checked before every next sync request.
Each new cycle retrieves fresh keys; an unsupported rotation pauses with a safe actionable state.
Responses are rechecked against current authentication before local apply. Sent writes retain
the existing unknown-outcome/pull-before-retry rules. Local editing, offline keys and SSH remain
independent of network or authentication failures.

Writes contain only encrypted signed K-1 objects. Confirmed assignments update bases and clear
only the exact sent version; a concurrent local edit stays dirty. Write assignments never advance
the applied cursor. Complete request-bound 409 conflicts decrypt and merge before a bounded
retry. A transport failure, malformed success, or uncertain commit preserves the queue; every
subsequent attempt pulls and merges instead of replaying the old batch. This path still supports
membership-only account changes and the retained Personal epoch set; key rotation remains incomplete.

An exact unchanged `410 sync.cursor_expired` triggers full snapshot reconciliation. Snapshot
pages contain at most 32 objects, each HTTP response at most 9 MiB, and the entire pass at most
32 MiB of response bodies, 100,000 objects, and 60 seconds. Body accounting includes ignored
extensions. Query-bound cursors, unique ids across pages, signer/epoch bindings, signatures,
AEAD, tombstones and K-1 validation must all succeed before any inventory mutation. The session's
announced vault sequence is the fixed baseline: the final snapshot cursor must equal it. A
newer sequence safely aborts as concurrent activity; the next bounded cycle obtains a fresh
session. There is no unbounded automatic retry and no cross-page snapshot token in this contract.

Migration 7 adds append-only encrypted recovery copies, each with its own id. A single FULL
synchronous immediate transaction compares the old applied cursor, re-reads current local
objects, merges every present remote object with concurrent local edits, removes missing clean
objects, preserves missing dirty objects as recovery copies, and adopts the final snapshot
cursor. A missing object with no confirmed base or a base beyond the last confirmed ACK is
also preserved conservatively. This includes newly adopted objects that have never uploaded;
they are not silently re-created on the server. The complete transaction rolls back on any
validation, ownership, capacity, or cursor failure, with no notifications before commit.
After server restore, a snapshot can lower the expired cursor; confirmed ACK evidence is clamped
to that snapshot position in the same transaction. Only then is the snapshot acknowledged.
An unknown ACK result retains the committed inventory, recovery copies and earlier confirmation.

Recovery copies are distinct from original adoption copies and remain immutable across restarts
and restores. Restoring exact copy ids creates fresh local ids, remaps known references between
the selection, and clears tombstones without creating sync entries. Multiple historical copies
of one original cannot be restored in one selection. Device secrets and keystore handles remain
at their original device-local ids and are never copied to restored ids. The new objects require
a fresh D-112 review and confirmation before upload.
Recovery-history reads are independently bounded to 100,000 copies and 32 MiB of stored K-1
envelopes. A bounded SQL length/count check runs before decoding; exceeding either limit returns
the explicit resource-limit state without silently truncating the history or deleting copies.
The reconciliation transaction checks that same budget before committing new copies. If the
new history would exceed it, the complete pass rolls back, preserving the old inventory,
cursor and previously readable copies for local restoration. History pagination and management
are separate future work.

`PersonalInventorySettings` is the secret-free desktop facade. A single local read transaction
returns object names/categories, shared-secret presence, immutable-copy metadata, dirty counts,
and separate applied/acknowledged decimal-string positions. Preview names exact local ids and
missing existing references; it never expands the selection or opens a connection. A valid
preview retains only object digests, the store path/device/vault, and a random one-use ticket
in Rust for at most five minutes. The ticket, not any object bytes or secrets, crosses IPC.
The adoption transaction compares every selected object's current bytes and ownership to that
review before committing any copy, ownership change, or queue entry. Competing edits therefore
require another review. Manual sync without a ticket can only synchronize existing Personal
objects. Native restore runs the same core local transaction on the blocking pool, retains
original snapshots, creates new local ids, and emits normal store notifications after commit.
The UI makes no network request and never retries an uncertain network intent automatically;
it reloads only local metadata after any result, including an unknown write outcome.

Personal TrustRecords currently require manual/imported provenance naming this account and a
verified active device. Missing/cross-account/revoked-device provenance and CA/policy records
stop with `TrustReviewRequired` before adoption or page application; the complete trust-replication
and reconfirmation UI is a separate outcome. Organization-only inventory is not adopted here.

## Tier-0 inventory and OpenSSH onboarding

Migration 3 adds `implicit_objects`, an encrypted, device-local visibility marker for tier-0 AccessProfiles and Credentials. Creating a host marks its login and credential implicit in the same transaction. Inspecting a host promotes its login; inspecting a private-key login promotes that credential, while password and agent credentials remain implicit. Using the same private key for a second host reuses and promotes the credential in the host creation transaction. The marker does not replicate and does not change the object format. `areas()` reports Keys only after a private-key credential becomes explicit.

The empty Hosts list can open a native file picker and preview a limited OpenSSH config before writing. The Rust core reads a bounded UTF-8 file, separates representable literal `Host` blocks from skipped hosts, and reports unsupported directives with line numbers. `Include`, `Match`, wildcard hosts, or global rules can change the meaning of every block, so a file containing them yields a report without importable hosts. The frontend displays that report and sends the preview back for confirmation. The core re-reads and compares the source before import; if it changed, the user must preview again. Identity files and every host are validated before one atomic store transaction. The source config is never written. Complete OpenSSH import and idempotent re-import remain roadmap C10.

## SSH session routes

`scoplen-client-core::connection` resolves an AccessProfile into an endpoint,
Route, and device-local credential material, then owns the concrete
`scoplen-ssh` connection and session channels. The Tauri `session_connect`
command retains the negotiated connection and resolves host-specific trust before authentication.
New, changed, or unverifiable keys require explicit confirmation; wildcard-only and CA records
do not authorize raw host keys. Personal manual/imported records require the retained account's
signed source certificate. Account-query and sync-key snapshots contribute a union of verified
revocations, and each entrance rejects removal of its previously observed revocations. A revoked
origin remains replicable when relayed by an authenticated active signer but cannot authorize
SSH without a separate active-device confirmation of the same key. Local-only confirmations
remain usable offline. Every accepted key records this device and, when verified, its account;
the per-hop Verified event carries safe source metadata to Connection details. Password
and OpenSSH Ed25519, ECDSA P-256/P-384/P-521, and RSA private-key
authentication, one command, and an optional PTY shell are available now.
Direct connections and saved SOCKS5 or HTTP CONNECT routes use the same
target-host trust check. A proxy route may pair a separate username with a
password Credential; probe and session setup resolve the same pair. The
username and resolved password are validated before dialing. The proxy
receives them over plain TCP, without transport encryption; the target SSH
connection still verifies its host key and encrypts its traffic. Proxy
endpoints must be `host:port` or `[IPv6]:port` with a non-zero port. The shared SSH engine
bounds proxy setup and SSH handshakes separately at ten seconds. Proxy
rejection and timeouts remain typed failures, and an accepted proxy cannot
override target-host trust.
Encrypted keys use a one-time passphrase entered after host-key review. The
Tauri command moves it immediately into a zeroizing secret container, and the
core decrypts on a blocking worker before selecting the existing signer. The
key file, passphrase, bcrypt salt, and round count are bounded before the KDF
runs; closing the session drops the waiting connection future before remote
authentication or shell setup continues, though a running blocking derivation
may finish before its secret is released.
No passphrase is stored or returned over IPC. The imported ECDSA key's actual
curve determines the shared signer.
RSA queries the shared connection's bounded, cached `server-sig-algs` selection
before authentication: it uses SHA-512 when advertised, SHA-256 when that is
the strongest advertised choice, and SHA-512 once when the result is unknown.
A SHA-1-only advertisement fails before authentication; a rejected SHA-2
attempt does not retry another hash or password. Host-key trust remains a
prerequisite to all credential use.

Agent Credentials retain their saved `public_key` in the resolved plan. Before
any network access the core validates a supported raw OpenSSH public key; only
after host-key trust succeeds does it connect to the system agent. The platform
crate selects the Unix `SSH_AUTH_SOCK` or a local Windows named pipe and exposes
a bounded synchronous byte interface backed by an async local I/O task. The
shared `AgentClient`, framed channel, and `AgentSshSigner` own protocol messages
and signatures. The core requires the exact public-key blob to appear among
the agent identities; it never substitutes a first identity or another credential.

The core retains at most four native authentication workers for synchronous agent setup and
identity listing. Concrete authentication awaits the shared D-116 signer hook, whose complete
serialized signing exchange runs on the blocking pool. One absolute ten-second client deadline
covers agent connection, all partial local reads/writes, identity listing, and SSH authentication. Dropping
the authentication future aborts agent I/O and notifies the worker, which discards
its result; only a live caller restores its connection and advances to Open.
The shared hook releases an awaiting caller on cancellation while a running blocking exchange
retains channel ownership until completion or its underlying I/O deadline. It adds no agent
transport deadline or asynchronous setup guarantee; the native guard and deadline remain in place.
This path adds no unsafe code, protocol format, IPC field, private-key export,
Pageant discovery, or forwarding permission. RSA agents use the existing bounded
SHA-2 discovery and never retry with SHA-1 or a password.

The client pins the same proto revision for its shared crates and its Cargo
`pageant` patch because a Git dependency does not inherit the proto workspace's
local patch.

Output is delivered as bounded binary frames (8 MiB aggregate per session),
and command/input fields are bounded at 64 KiB. The desktop session view uses
`@scoplen/terminal` to interpret ANSI/VT output. A process-local session
registry routes bounded input frames and close requests to the owning SSH
channel; disconnecting the tab closes that channel. Remaining credential providers
and complete workspace restoration remain
later connection slices.

After local profile and trust-record preflight, each `session_connect` attempt
owns a `session_lifecycle::SessionHistoryLease` with a store-generated UUIDv7,
independent of the frontend transport ID. Normal completion and an explicit
close during preparation record `Closed`; error returns and externally dropped
futures record `Failed` through the lease's drop
fallback. Opened and closed `SessionChanged` events refresh the existing Recent
view. A separate registration guard releases the process-local transport ID on
every exit, including future cancellation. Invalid profiles and locked stores
are rejected before creating a history row.

Recent reconnect resolves an ended Terminal record to its still-live
AccessProfile and Host in the core, without opening a socket or writing history.
The Hosts view passes that profile to the ordinary Connect entry point. The
connection owner then performs current preflight and host-key verification and
records a fresh attempt. Active records, Files/Forward kinds, and deleted
profiles or hosts fail lookup without creating a new session.
The Hosts source navigation remains available as a horizontally scrolling row
when the window is narrower than the desktop sidebar breakpoint, including at
the desktop window's minimum width.

## Independent local TCP tunnels

`forward_manager::ForwardManager` owns standalone Local Forward runs separately from
`SessionManager`. Start validates a saved definition and fixes its endpoints and complete
saved connection plan synchronously, including a display-safe target Login context. The
common preparation executor retains per-hop trust and authentication. It opens no session,
shell or PTY. Editing inventory after Start cannot change that run's connection or identity.

Each run owns one numeric-IP listener, at most 32 accepted or opening peers, and the target
SSH connection with its Jump parents. Peers open independent `direct-tcpip` channels with a
15-second deadline, then copy both directions concurrently with half-close and 32 KiB buffers.
Traffic snapshots are coalesced at 250 milliseconds and expose decimal-text counters and
revisions. Sixteen runs may be live, with at most 32 completed snapshots retained. A retained
snapshot holds only a weak store identity; completion releases its observer and strong store
ownership. A failed connection never triggers reconnect.

The generated `forward_start`, `forward_list`, `forward_snapshot`, `forward_respond` and
`forward_stop` commands bind actions to the exact open store and run. Prompt replies also
require the current one-use preparation token. Stop fences new peers and replies, then
settles the listener, peers and complete SSH chain. Store replacement drains all owners;
application exit first permanently fences Starts and waits under one 35-second cleanup
budget. Remote, dynamic, Unix-socket and automatic profile forwards remain separate work.

## Session upload sources

The native picker supplies an upload path; Rust performs an ordinary-file preflight,
opens it once and validates the resulting handle before reading. Unix retains
`O_NOFOLLOW | O_NONBLOCK`. Windows uses `FILE_FLAG_OPEN_REPARSE_POINT` and rejects
`FILE_ATTRIBUTE_REPARSE_POINT` on the opened handle as well as non-regular files.
Replacing the final component with a link or reparse point after the path preflight
therefore cannot admit its target as the upload source.

This protects the final component only. Ancestor directories resolve normally,
including ancestor links or reparse points; the preflight does not pin their identity
or distinguish an ordinary-file replacement before opening. Once admitted, the
retained handle prevents later path replacements from redirecting reads. It does not
exclude writers or provide an immutable snapshot. Existing size and modification-time
checks can detect some changes while queued or transferring, but edits preserving
the compared metadata can escape them, and writes can race later checks.

## Native file-drop uploads

The native window event is the only drop source-path entry. The application emits its own
typed `SessionFileDrag` event with a view identity, bounded count, normalized position and
optional opaque ticket. The frontend never subscribes to Tauri's path-bearing drag events.
This describes normal product IPC, not framework-wide isolation of a compromised renderer.
Native paths and selected handles stay transiently in Rust and never enter status or storage.

One armed context per window freezes the logical session, ready transport, queue, remote
directory bytes and Files view identity. A Drop replaces any earlier ticket and expires after
30 seconds. Consuming it takes the native paths once and atomically reserves every required
queue slot before opening sources through `open_upload_source`. All files and target names
must validate, and duplicate target bytes reject the batch. The final append rechecks ticket,
deadline and connection under the same context/queue locks, appends every item contiguously,
then starts the existing worker. Rejection drops every selected handle and reservation without
dispatching that batch. Admission is atomic; later remote execution remains per item.
Source preparation shares the ticket's absolute deadline: even if a local filesystem call
remains blocked, expiry returns a refusal and releases every reserved slot and completed
source handle. A later result from that call is discarded without queue admission.

The current single full-window webview must match native bounds at origin zero. Wry's macOS
points and Windows physical coordinates are normalized against bounds in that same platform
space; the frontend multiplies by its current viewport and hit-tests only the visible list.
Resize, scale, viewport, layout, modal and view changes revoke pending intent. Cleanup and
expiry identify their own context/ticket, and cannot erase a replacement. Leave after Drop
does not cancel consumption. Admitted items preserve their destination after Files is hidden.
Real scaled desktop drops on both supported platforms remain required acceptance evidence.

## Session download checkpoints

The Rust session transfer queue owns selected resources and paused download checkpoints.
Each checkpoint retains its original SFTP session and remote file handle, source attributes,
same-directory private local partial and read/write handle, native destination baseline,
absolute confirmed offset and streaming SHA-256 state. Paths, handles and digests never enter
IPC. A download completes 1 MiB segments with the published `download_to` range-end API and
four pipelined 32 KiB reads; Pause waits for normal segment completion, flush and local sync.
It does not cancel and reuse a poisoned SFTP session. Paused items retain an outstanding slot
but release the execution permit. Each retained channel also consumes the peer's channel
budget; refusing another channel does not evict existing checkpoints.

Resume allocates a fresh execution, keeps the item identity and moves it to the FIFO tail.
At dispatch, it checks source size and available non-access-time attributes, local native
partial identity and exact length, and the selected destination. It hashes both confirmed
prefixes again before seeking the retained local file and continuing the original remote
handle from the absolute offset. Prefix verification uses bounded buffers but rereads the
entire confirmed prefix on each resume. These reads never increment payload progress.
An open handle and metadata are not an immutable snapshot, and prefix hashes cannot prove
an unread suffix is unchanged or exclude writes after validation. Sources must remain stable.

An owned download task settles cancellation and cleanup even when the transport actor ends.
Native file identity and ordinary-file checks gate both partial deletion and publication;
a path replaced by another file is preserved and cleanup uncertainty is projected. These
checks followed by unlink or rename are not filesystem compare-and-swap. Disconnect and
session close discard checkpoints after cleanup settlement; no item is replayed over a new
transport. Unknown publication remains an explicit acknowledgement-only result.

## Session upload checkpoints

The queue enables upload Pause only after ordinary exclusive `WRITE | CREAT | EXCL` staging
creation succeeds and a separate read-only open of that owned pathname has matching private,
zero-length ordinary-file attributes and returns EOF on an empty-file read. An associated
remote STATUS refusal closes any known read handle and retains ordinary upload without Pause.
Malformed or uncertain admission ends the attempt and follows owned staging cleanup;
staging creation is never retried to obtain read capability.

Uploads finish 1 MiB bounded `upload_from` segments with four pipelined 32 KiB writes. Pause
and Cancel wait for the current segment to finish normally. Each completed segment captures
the write-handle baseline; Pause additionally waits for supported `fsync` and verifies both
local and remote confirmed-prefix digests. The Rust checkpoint retains the original SFTP
session, write/read handles, private staging path/baseline, admitted local source handle and
metadata, absolute offset, SHA-256 state, target baseline and original replacement consent.
Paused uploads retain capacity and release execution. Resume keeps the item identity,
allocates a fresh execution at the FIFO tail, rechecks source/staging/target and both prefixes,
then seeks the retained source and continues the original write handle at the actual offset.
Validation reads never advance payload progress. Access-time changes caused by reads are
ignored; changed source, staging or target refuses continuation or publication.

Cancellation and transport/session expiry settle retained staging cleanup. Failure cleanup
rechecks the current pathname against the last confirmed write-handle baseline before removal;
a detected replacement or unverified baseline preserves the path and reports possible staging.
These checks and removal are separate filesystem operations. A new transport cannot inherit a checkpoint. Publication
refuses Pause/Cancel, and a lost rename reply stays Unknown without automatic replay.
SFTP v3 has no stable file identifier or compare-and-swap: matching attributes and prefix
hashes do not prove inode identity or an immutable snapshot, an unchanged unread suffix,
or absence of later concurrent writes. Cross-transport and durable continuation remain open.

## Localization

Messages are ICU MessageFormat catalogs in `web/app/src/messages`. English (`en.ts`) is the source; every other catalog has its type, so a missing key fails type checking, and the catalog tests format every message. The interface language is chosen in the core (`Locale::negotiate`) from the system's preferred languages: Simplified Chinese for `zh-Hans` and Simplified-script regions, otherwise English. A language setting arrives with Preference objects (roadmap C2).

## Design system

`web/ui/src/styles.css` defines the tokens of `scoplen-docs/18-visual-identity.md` as semantic names (`background`, `foreground`, `primary`, `muted-foreground`, `border`, `ring`, `attention`) for Tailwind. Light and dark follow the system; increased contrast raises secondary text and borders to the full foreground; reduced motion removes transitions and animation. Fonts are bundled; none is loaded from a third-party service. Chinese headings use a subset of Noto Serif SC at weight 600 containing exactly the characters of the Chinese catalog.

## Device-local records

Records that never replicate (`04-object-model.md` §4.9) live in the same encrypted store, in their own tables (migration 2): this device's half of device-bound credentials, as a stored secret or a keystore handle; the device key pair, created at sync enrollment; the session history, limited to the 1,000 most recent sessions; saved scrollback; and window geometry. None of them is an object, so sync never sends them. Device-key handles are opaque references to platform slots and are invalidated when the credential is deleted or changed away from a device-bound key. Secrets resolved from either the encrypted table or a platform slot come back as `SecretVec`, which is zeroized when dropped and redacted when formatted. The main window's size and position are saved when it closes and restored at the next launch if they are still on a display.

## Saved terminal output

Saved terminal output is a bounded, versioned snapshot of rendered xterm state and dimensions,
kept in the device-local `scrollback` table. `SessionManager::save_output` binds a checkpoint
to its logical owner, current attempt, generated history UUID and exact store Arc, with a
monotonic sequence. `LocalData::with_store` holds the replacement boundary during the bounded
write. The store validates Terminal history, the 1 MiB encoded limit and grid dimensions before
one transaction writes and evicts oldest snapshots to a 64 MiB aggregate limit. History prune
and forgetting remove snapshots atomically; late calls cannot resurrect them. Neither output
nor input enters sync or error diagnostics; snapshot Debug output is redacted.

The terminal package owns serialization after queued rendering drains. The desktop checkpoints
every five seconds. Closing stops the transport and waits for its final ordered output before
saving and unmounting; a failed save preserves the view and offers an explicit discard action.
Recent loads snapshots only through View output into an offline read-only terminal. Restoring
suppresses parser-generated replies and input, and rejects attaching a live source or sink
until complete. Explicit Reconnect creates a new normal attempt while retaining the display.
Window close is requested again only after saves succeed, so native geometry and shutdown hooks
remain active. The window capability includes close and destroy because Tauri's
`onCloseRequested` completes an allowed native close through its internal destroy command.

## No network while sync is disabled

`scripts/check-offline.sh` runs the built application on macOS under a sandbox profile that kills the process on any IP network operation. The application must open its local data, render, and stay idle for 15 seconds; a control run of `curl` under the same profile must be killed. CI runs it on every change. On Windows the same core runs, but no equivalent check exists on hosted runners.

## Launch verification

With `SPL_SMOKE_TEST=1`, the application exits with status 0 once the frontend reports that its first screen rendered (the `shell_ready` command), or `SPL_SMOKE_LINGER_SECS` seconds after that, and with status 1 after 90 seconds otherwise. CI runs a release build this way on macOS and Windows.
