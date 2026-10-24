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

The shared libraries and Pageant patch are pinned to `proto@22a83ad`. This revision retains
the K-2 public API and wire bytes while upgrading HPKE and P-256 to 0.14. The client lockfile
resolves `crypto-bigint` 0.7.6 and `ctutils` 0.4.5 for RUSTSEC-2026-0387, removing the former
0.5.5 bigint/P-256 0.13 dependency path. Updating the shared pin requires checking the client's
own transitive lockfile; the shared repository's lockfile does not constrain consumer resolution.

## IPC

Commands are declared in `src-tauri/src/commands.rs` with `#[specta::specta]`. `pnpm bindings` writes `web/app/src/ipc/bindings.ts` from them; a test fails when the committed file differs from what the commands generate, so the frontend and the core cannot drift.

Streams use Tauri channels carrying raw binary frames: `FrameSender` on the Rust side (`src-tauri/src/frames.rs`) and `frameChannel` on the frontend (`web/app/src/ipc/frames.ts`). Frames arrive intact and in order; nothing is encoded as JSON.

The interactive `session_connect` command has a separate typed readiness channel.
It sends once authentication, optional PTY allocation, and the shell request
succeed. The view becomes connected on that notification, independently of
terminal output. Ended and unsubscribed views ignore late notifications.

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

Synchronous signer calls run on at most four blocking workers, leaving the app
executor responsive. One absolute ten-second deadline covers agent connection,
all partial local reads/writes, identity listing, and SSH authentication. Dropping
the authentication future aborts agent I/O and notifies the worker, which discards
its result; only a live caller restores its connection and advances to Open.
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
channel; disconnecting the tab closes that channel. Jump and ProxyCommand routes,
remaining credential providers, automatic reconnect, and saved scrollback remain
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

## Localization

Messages are ICU MessageFormat catalogs in `web/app/src/messages`. English (`en.ts`) is the source; every other catalog has its type, so a missing key fails type checking, and the catalog tests format every message. The interface language is chosen in the core (`Locale::negotiate`) from the system's preferred languages: Simplified Chinese for `zh-Hans` and Simplified-script regions, otherwise English. A language setting arrives with Preference objects (roadmap C2).

## Design system

`web/ui/src/styles.css` defines the tokens of `scoplen-docs/18-visual-identity.md` as semantic names (`background`, `foreground`, `primary`, `muted-foreground`, `border`, `ring`, `attention`) for Tailwind. Light and dark follow the system; increased contrast raises secondary text and borders to the full foreground; reduced motion removes transitions and animation. Fonts are bundled; none is loaded from a third-party service. Chinese headings use a subset of Noto Serif SC at weight 600 containing exactly the characters of the Chinese catalog.

## Device-local records

Records that never replicate (`04-object-model.md` §4.9) live in the same encrypted store, in their own tables (migration 2): this device's half of device-bound credentials, as a stored secret or a keystore handle; the device key pair, created at sync enrollment; the session history, limited to the 1,000 most recent sessions; saved scrollback; and window geometry. None of them is an object, so sync never sends them. Device-key handles are opaque references to platform slots and are invalidated when the credential is deleted or changed away from a device-bound key. Secrets resolved from either the encrypted table or a platform slot come back as `SecretVec`, which is zeroized when dropped and redacted when formatted. The main window's size and position are saved when it closes and restored at the next launch if they are still on a display.

## No network while sync is disabled

`scripts/check-offline.sh` runs the built application on macOS under a sandbox profile that kills the process on any IP network operation. The application must open its local data, render, and stay idle for 15 seconds; a control run of `curl` under the same profile must be killed. CI runs it on every change. On Windows the same core runs, but no equivalent check exists on hosted runners.

## Launch verification

With `SPL_SMOKE_TEST=1`, the application exits with status 0 once the frontend reports that its first screen rendered (the `shell_ready` command), or `SPL_SMOKE_LINGER_SECS` seconds after that, and with status 1 after 90 seconds otherwise. CI runs a release build this way on macOS and Windows.
