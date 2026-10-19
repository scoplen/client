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

- `web/app` renders state and sends intents. It never holds secrets, never performs cryptography, and never talks to the network.
- `src-tauri` adapts commands to `scoplen-client-core` and owns windows. Its capability file (`src-tauri/capabilities/main.json`) grants the main window only Tauri's core defaults and the application's own commands. The content security policy in `tauri.conf.json` allows only the application's own resources and IPC.
- `scoplen-client-core` holds every behavior, so it is the same on both platforms and testable without a window.
- `scoplen-client-platform` is the only crate that may contain `unsafe` code or FFI; it is denied by default there too and allowed per module with each block documented.

## IPC

Commands are declared in `src-tauri/src/commands.rs` with `#[specta::specta]`. `pnpm bindings` writes `web/app/src/ipc/bindings.ts` from them; a test fails when the committed file differs from what the commands generate, so the frontend and the core cannot drift.

Streams use Tauri channels carrying raw binary frames: `FrameSender` on the Rust side (`src-tauri/src/frames.rs`) and `frameChannel` on the frontend (`web/app/src/ipc/frames.ts`). Frames arrive intact and in order; nothing is encoded as JSON.

The interactive `session_connect` command has a separate typed readiness channel.
It sends once authentication, optional PTY allocation, and the shell request
succeed. The view becomes connected on that notification, independently of
terminal output. Ended and unsubscribed views ignore late notifications.

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

## Tier-0 inventory and OpenSSH onboarding

Migration 3 adds `implicit_objects`, an encrypted, device-local visibility marker for tier-0 AccessProfiles and Credentials. Creating a host marks its login and credential implicit in the same transaction. Inspecting a host promotes its login; inspecting a private-key login promotes that credential, while password and agent credentials remain implicit. Using the same private key for a second host reuses and promotes the credential in the host creation transaction. The marker does not replicate and does not change the object format. `areas()` reports Keys only after a private-key credential becomes explicit.

The empty Hosts list can open a native file picker and preview a limited OpenSSH config before writing. The Rust core reads a bounded UTF-8 file, separates representable literal `Host` blocks from skipped hosts, and reports unsupported directives with line numbers. `Include`, `Match`, wildcard hosts, or global rules can change the meaning of every block, so a file containing them yields a report without importable hosts. The frontend displays that report and sends the preview back for confirmation. The core re-reads and compares the source before import; if it changed, the user must preview again. Identity files and every host are validated before one atomic store transaction. The source config is never written. Complete OpenSSH import and idempotent re-import remain roadmap C10.

## SSH session routes

`scoplen-client-core::connection` resolves an AccessProfile into an endpoint,
Route, and device-local credential material, then owns the concrete
`scoplen-ssh` connection and session channels. The Tauri `session_connect`
command reads active host-specific trust records before opening a socket;
new, changed, revoked, wildcard-only, and CA records are rejected. Password
and unencrypted OpenSSH Ed25519, ECDSA P-256/P-384/P-521, and RSA private-key
authentication, one command, and an optional PTY shell are available now.
Direct connections and saved SOCKS5 or HTTP CONNECT routes without proxy
credentials use the same target-host trust check. Proxy endpoints must be
`host:port` or `[IPv6]:port` with a non-zero port; malformed endpoints and
routes with proxy credentials fail before network I/O. The shared SSH engine
bounds proxy setup and SSH handshakes separately at ten seconds. Proxy
rejection and timeouts remain typed failures, and an accepted proxy cannot
override target-host trust.
Encrypted keys require a passphrase flow and return an explicit error in this
build. The imported ECDSA key's actual curve determines the shared signer.
RSA queries the shared connection's bounded, cached `server-sig-algs` selection
before authentication: it uses SHA-512 when advertised, SHA-256 when that is
the strongest advertised choice, and SHA-512 once when the result is unknown.
A SHA-1-only advertisement fails before authentication; a rejected SHA-2
attempt does not retry another hash or password. Host-key trust remains a
prerequisite to all credential use.

The client pins the same proto revision for its shared crates and its Cargo
`pageant` patch because a Git dependency does not inherit the proto workspace's
local patch.

Output is delivered as bounded binary frames (8 MiB aggregate per session),
and command/input fields are bounded at 64 KiB. The desktop session view uses
`@scoplen/terminal` to interpret ANSI/VT output. A process-local session
registry routes bounded input frames and close requests to the owning SSH
channel; disconnecting the tab closes that channel. Jump and ProxyCommand routes,
authenticated proxy routes,
other credentials, automatic reconnect, and saved scrollback remain
later connection slices.

After local profile and trust-record preflight, each `session_connect` attempt
owns a `session_lifecycle::SessionHistoryLease` with a store-generated UUIDv7,
independent of the frontend transport ID. Normal completion records `Closed`;
error returns and cancelled futures record `Failed` through the lease's drop
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
