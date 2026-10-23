# Interface and the core

The interface (`web/app`, `web/ui`) and the core (`crates/`, `src-tauri`) are built separately. Each screen states what it needs from the core as a TypeScript contract; the core implements that contract with typed commands. This page lists the contracts, what each operation must do, and how a contract is connected once its commands exist.

The screens never read the store, decide business rules, or hold secrets. Anything the screens must not decide — validation beyond "is this field empty", what a deletion removes, which areas the user has reached — is the core's.

## Seeing the screens

`pnpm --dir web/app dev`, then open `/gallery.html`. The gallery renders every screen and state with sample data, in any theme, (`web/app/src/gallery/sample-inventory.ts`), in English or Chinese, as on macOS or Windows. It is a development tool: it is not built into the application, and its sample data is not a reference implementation of the core.

## Look and feel

The interface has a character: the Scoplen mark, a small tilted egg whose eyes are a text cursor and a wink (`web/ui/src/components/mark.tsx`). It reacts only when something happens, never on its own: it watches the field being typed in the Add host dialog and shuts its eyes for a password or key, sleeps while the local data is locked, shakes its head when something is refused, and every host has its own egg in one of a few poses chosen from its identifier (`host-egg.tsx`). A session tab's egg shows the connection: eyes wide while connecting, asleep once closed, the attention color when it failed. The selected item is marked by the mark's open eye on its left edge (`pick.tsx`). With reduced motion the faces still change but nothing animates.

Colors and shapes come from a theme the person chooses in Settings (`web/ui/src/themes.css`, `theme.tsx`): Paper (the default), Brutal, Sakura, Midnight, and Phosphor, each in light and dark where it has both, or following the system. A theme sets every color token and its radii, border width, shadows, the way buttons press, and the heading face; components read only the tokens. Every theme's text pairs are checked for WCAG AA contrast by `web/ui/test/tokens.test.ts`. The choice is an interface preference of the device and is kept in the webview's local storage until the core offers a settings store.

Right-click menus are the application's own (`web/ui/src/components/context-menu.tsx`): hosts, session tabs, and the terminal offer theirs, text fields get Cut, Copy, Paste, and Select all, and elsewhere a right click does nothing, so the web view's Reload and Inspect never appear. Interface text is not selectable, as in a native application; fields, terminal output, addresses, and host keys are. Session tabs close with their button, a middle click, or their menu. The interface language can be fixed in Settings → Appearance; "Same as system" uses the language the core negotiated, and the choice is kept like the theme.

The terminal has its own colors, chosen in Settings → Terminal (`web/app/src/terminal-colors.tsx`, `terminal-settings.tsx`): "Match the theme" (the default) takes the interface theme's surface, text, and accent, and a set of fixed schemes uses their projects' published palettes. Each of the four surface colors and sixteen ANSI colors can be changed; an edit makes the colors the person's own scheme. They are applied to running sessions at once and kept like the theme. The session header has a shortcut to these settings, and sessions stay mounted and connected while another tab or Settings is shown.


`web/app/src/frame.tsx`. A strip of tabs above the content. The first tab is always Hosts, led by the mark; each session adds a tab after it, led by its host's egg (roadmap C5). On macOS the strip is the title bar: the window is created with `titleBarStyle: "Overlay"` and a hidden title, the strip leaves 92 px for the window controls, which sit centered in it, and its empty space carries `data-tauri-drag-region`. Windows keeps its native title bar. Settings opens from the gear at the right of the strip.

## Personal account setup

Settings → Personal account opens the optional first-device flow. It reads public status
without network access. The invitation is a hidden, uncontrolled input: submitting clears
its DOM value and passes it once to Rust. The frontend retains no invitation, recovery key,
private key, access token, or refresh token. The device name and trusted server origin are
shown before joining. Rust parses the invitation, generates the shared K-2 artifacts, and
persists the same pending identity in SQLCipher before any request.

Save recovery file opens a native picker and writes the plaintext backup directly from Rust
to a new file; existing files are not overwritten. Cancellation retains the current phase.
The user separately confirms that the file is kept safely before Join becomes available.
Clear connector failures before any HTTP request allow explicit Join again with the same
identity. Timeouts, lost responses, and unknown outcomes retain the pending identity and show
Authenticate this device, which uses a fresh challenge without replaying the invitation.
Errors use typed localized codes; arbitrary IPC or server diagnostics are not rendered.

Only the unconfirmed phase offers Use a new invitation. It reveals a hidden, uncontrolled
field for a link from the displayed server, focuses it, and clears it before calling the
generated `updatePersonalInvitation` command. Cancel also clears the field. Rust handles
the same-origin check, fresh authentication, and exact D-109 device-denial rules; the frontend
does not infer permission from a general authentication error. Authentication success ends
recovery without using the new link. A replacement accepted by Rust returns to Join readiness
with the original identity and recovery confirmation; another explicit Join is required.
A rejected replacement retains the pending phase and offers no Join. Busy state blocks duplicate replacement
and authentication intents, and no invitation appears in localized errors or public status.

Authenticated status means Rust verified the unexpired device access token against the exact
chosen HTTPS origin's JWKS and the saved account/device/key identity. It does not mean inventory
has synchronized. Existing hosts and credentials remain local. Pairing, refresh rotation,
profile display, and complete multi-device reconciliation remain separate outcomes. Settings navigation supports
arrow keys, Home/End, visible focus, and wrapping at narrow widths. An explicit action that
advances to another phase focuses its heading; initial status reads and same-phase actions
retain keyboard focus.

Verify sync keys reads locally on mount and connects only on explicit activation. A verified
snapshot reveals Inventory sync. Its initial status read and Refresh local status stay offline.
Local object checkboxes select exact ids, show category and shared-secret presence, and do not
follow references. Review selected opens a modal listing the selection, immutable-copy behavior,
and missing references. Upload remains disabled until references are resolved and the user
separately agrees to upload the selected content. The native preview ticket expires after five
minutes and is consumed once; an object edit between review and adoption requires review again.
Sync now sends no adoption ticket and never includes new local objects automatically.

The panel shows pending changes and separate applied/confirmed-ack positions. Every completed
or failed intent reloads durable local status without starting another network cycle. Typed
uncertainty, reconciliation, rotation, trust, clock, authentication, and selection failures are
localized; arbitrary native diagnostics are replaced with a safe local-data failure. A bounded
cycle with more work offers the same explicit Sync now action. Original local copies have a
separate exact selection and confirmation. Restore works with expired authentication and no
network, creates new local objects, and explicitly says it does not undo remote data or copy
device-only secrets/handles. Cancelling either confirmation performs no mutation.

## Inventory (roadmap C3)

Contract: `web/app/src/inventory/api.ts` (`InventoryApi`). Screens: `inventory/home.tsx` (sidebar, list, details; the logins, keys, and routes editors open beside the sidebar, which stays), `inventory/host-details.tsx`, `inventory/add-host.tsx`.

| Operation | What the core does |
| --- | --- |
| `areas()` | Which sidebar sources exist (`01-product-definition.md` §7.6): `favorites` when any host is a favorite, `recent` when the session history names a host, `groups` when any group exists, `keys` when a credential has been promoted by reuse or inspection, and `routes` when a route exists. Implicit tier-0 credentials do not make Keys visible. |
| `groups()` | Every group with its parent and host count. |
| `hosts(source, query)` | Hosts from the source (all, favorites, recent, or one group and its subgroups) whose name, address, username, or `key:value` tag contains the query, case-insensitive; favorites first, then by name. Orphaned hosts are not listed. `username`, `loginCount`, and `route` describe the default login, else the only one. |
| `recentSessions()` | The newest device-local session history entries, with the current Host label and login metadata. Entries whose Host or Login was deleted are omitted; no credential, scrollback, or live connection data is returned. Timestamps are decimal Unix-millisecond strings at the IPC boundary. |
| `openSession(profileId, kind)` | Records an open event after a real connection owner has accepted a transport; the login must still exist. It does not open a socket. The result is the same redacted session DTO shown by `recentSessions()`. |
| `closeSession(id, outcome)` | Records `closed` or `failed` from the connection owner. A missing or already-ended session is rejected, and a failed write leaves history unchanged. |
| `reconnectSession(id)` | Resolves an ended terminal history entry to its current Host and Login, which the screen passes to the normal Connect flow. Active sessions, unsupported session kinds, and deleted logins are rejected. Lookup creates no history row. |
| `forgetSession(id)` | Deletes one ended device-local history row and its saved scrollback. Active sessions cannot be forgotten; orphaned rows can still be cleaned up by identifier. |
| `host(id)` | The host with every login, `null` when it no longer exists. Inspecting a host promotes its implicit login; inspecting a private-key login also promotes that key credential. Password and agent credentials remain implicit. A key credential carries its public key. |
| `addHost(host)` | Creates the host, one implicit login, and an implicit credential, with a direct route, as one change (§7.6 tier 0). `name` defaults to the address and `port` to 22. Password and pasted or generated keys are stored as shared-binding credentials; a key file is read and stored the same way; `agent` creates an agent credential. Reusing an existing private key on a second host reuses and promotes that credential in the same transaction; the reuse search is bounded at 4,096 private-key credentials and returns a clear error beyond that limit. Each `AddHostError` names the field it belongs to; nothing is saved on error. |
| `setFavorite(id, favorite)` | Sets the favorite field. |
| `deleteHost(id)` | Deletes the host, its logins, and unnamed credentials no other login uses, and returns a token. |
| `undoDelete(token)` | Restores everything that deletion removed, for as long as the store keeps the tombstones. |
| `chooseKeyFile()` | Opens the system file picker starting in `~/.ssh`, returns the path or `null`. |
| `chooseOpenSshConfig()` | Opens a native picker for an OpenSSH config file, starting in `~/.ssh`; returns the path or `null` when canceled. The entry point is offered on the empty host list. |
| `previewOpenSshConfig(path)` | Reads at most 1 MiB of UTF-8 text and returns the selected path, importable literal hosts, skipped hosts with reasons, and every unsupported directive with its source line. It does not write to the store or source file. The review dialog lists the complete report and disables Import when no host is representable. |
| `importOpenSshConfig(preview)` | Available only while the host inventory is empty. Re-reads the source and rejects a changed preview, validates every host and identity file, then writes all importable hosts as one transaction. It returns imported hosts and the skip report; on an expected error, nothing is written. The source file is never modified. |
| `onChange(listener)` | Calls the listener after any inventory change; built on the `storeChanged` event (`ipc/store-events.ts`). |

The independent object editor uses the same `InventoryApi` boundary for the
objects that tier-0 creates implicitly:

| Operation | What the core does |
| --- | --- |
| `accessProfiles()` / `createAccessProfile()` / `updateAccessProfile()` / `deleteAccessProfile()` / `restoreOrphanedHost()` / `restoreOrphanedObject()` | Lists and edits AccessProfiles with host, Credential, Route, and saved Forward references validated before a write. `forwards` is a complete replacement list; duplicate identifiers are removed, and every referenced Forward must be live before the profile write begins. A profile whose Host, Credential, Route, or Forward was tombstoned on another device is shown as an orphan; the user can restore the missing object or delete the profile. Updating a default changes the Host default in the same store transaction; deleting the default or a profile referenced by a Forward, Workspace session, or jump Route is refused. |
| `forwards()` | Lists live saved Forward objects as redacted tunnel choices (`id`, `name`, direction, and optional default profile) for the AccessProfile editor. |
| `credentials()` / `createCredential()` / `updateCredential()` / `deleteCredential()` | Lists and edits Credentials with kind and binding validation. Shared password and private-key material is accepted only on writes and is stored through the encrypted secret path; device-bound password material is accepted through the write-only `deviceSecret` input and stays in this device's encrypted store. A device-bound key with `device` binding generates a P-256 identity in the platform keystore, stores only an opaque `device-keystore-v1:<credential-id>` handle in the device-local table, and records this device's OpenSSH public key in the credential's `devices` map. The handle is resolved only when a connection signer needs it and the private scalar is held in zeroizing process memory. Hardware-bound credentials carry no pasted secret and are resolved by their platform provider; `SecurityKey` currently fails closed with a capability error until FIDO2/WebAuthn support exists. Read DTOs expose only the redacted `hasSecret` flag and the device public key. A credential referenced by a profile or proxy route cannot be deleted. |
| `routes()` / `createRoute()` / `updateRoute()` / `deleteRoute()` | Lists and edits reusable local Routes, validating jump profile references, proxy endpoint shapes, and paired proxy usernames and password Credential references. The editor offers only password credentials and explains that the proxy receives authentication over plain TCP. Clearing authentication clears both Route fields. Routes with a missing jump profile or proxy credential are shown as orphaned and can be restored or deleted. Managed routes are display-only on the device, and routes referenced by a profile cannot be deleted. |

These operations return `ObjectEditError` on validation, reference, or
in-use failures. The error reference is diagnostic text and never contains
credential material. Independent object DTOs carry only redacted credential
labels and usage counts; secrets never cross the IPC boundary.

A saved Agent Credential connects only when its Public key field contains the
exact raw OpenSSH public key loaded in the system agent. The existing Login
credential selector assigns it to a host. Missing or malformed public keys are
reported before dialing; the Connect flow keeps its normal host-key
review and reports missing identities, agent signing failures, and timeouts in
the existing session error surface. It never prompts for a password fallback.
Agent forwarding and Pageant discovery remain unavailable.

Saved ProxyCommand Routes use the existing Route editor and Login selector. At Connect,
Rust parses quotes and expands only `%h`, `%p`, `%r`, and `%%` as literal arguments;
it rejects malformed or oversized commands before process creation, SSH-agent access, or private-key decryption.
The local program carries the target SSH stream without an implicit shell. The existing
host-key and one-time passphrase prompts remain bound to that retained connection.
Timeout, helper failure, and cancellation use the existing session failure surface;
closing or reconnecting releases the previous helper before preparing a new attempt.

Every operation that can fail returns `Outcome`; a `Failure` carries a reference for support, free of secrets.

The tier-0 OpenSSH importer accepts simple literal `Host` blocks with `HostName`, `User`, `Port`, and `IdentityFile` values. It skips a host block when a directive or value in that block cannot be represented. Global settings, wildcard `Host` patterns, `Include`, and `Match` can affect other blocks, so the preview excludes every host in those files and explains why. Full OpenSSH semantics, `known_hosts`, keys discovery, and idempotent re-import belong to roadmap C10; this flow is limited to an empty inventory.
Session lifecycle commands emit `sessionChanged` after a successful open, close, or
forget operation so the Recent view reloads without polling. The event carries only
the session identifier and transition. The connection owner records accepted SSH
attempts and their closed or failed outcomes; terminal output and credentials stay
outside history DTOs. Reconnect in Recent starts the normal Connect flow for the
current saved Login. Restoring scrollback after tab closure remains a later outcome.

The session header also offers Reconnect after the current connection closes or
fails. It stays disabled until that attempt finishes cleanup. The same terminal
element keeps its displayed scrollback while a new transport identifier runs the
normal host-key review, current saved-credential lookup, and one-time passphrase
prompt. Each accepted attempt records its own history lifecycle. Old ready,
output, input-error, and trust results cannot update the replacement connection;
closing the tab cancels the whole logical session. Displayed output is retained
in the open tab; this does not restore output from a closed tab.

Rust owns automatic retries after a previously ready terminal suffers a typed
network failure: 1/2/4/8/16-second delays, at most five attempts, and a budget reset
only after thirty continuous seconds ready or a manual Reconnect. First failures,
normal exits, authentication/configuration errors, and renderer failures do not
retry. The interface renders `retrying` events and sends intents; it has no retry
timer. Stop reconnecting cancels backoff or preparation, while closing a tab
destroys the session. Each reconnect starts a new remote shell, keeps displayed
output, and discards queued old input.

The renderer first calls `sessionReserveTransport(sessionId, pty)` and waits for
its acknowledgment before `sessionConnect`. If the tab closes before that
acknowledgment, it closes the reservation once acknowledged and never connects.
`sessionCloseTransport` removes unclaimed reservations and cancels the logical
session, including timers, prompts, and transports. `sessionRetryTransport` starts
a fresh manual budget after a `closed` or `failed` event. `sessionStopReconnecting`
and `sessionFailTransport` cancel an attempt; the interface waits for its terminal
state event before permitting a retry. If the manager invocation itself fails,
the interface reserves a fresh logical identifier while retaining the terminal.

`sessionConnect` receives one ordered `Channel<SessionEvent | ArrayBuffer>`.
State events and raw output share the channel so a new attempt's `starting` event
precedes its output. Each binary frame begins with that attempt's sixteen-byte
UUID, which is stripped before the terminal receives the bytes. Input and resize
intents carry the same attempt identifier; stale frames and queued input cannot
reach a replacement transport. The terminal source stays subscribed across
normal closed/failed states and reconnects. Rust resolves the whole
saved route before dialing, rejecting repeated Login/Host identifiers, target
loops, missing references, unsupported credentials, and any jump Login whose
own route is not Direct. It emits per-hop progress, trust, and one-time
passphrase prompts, each identifying the Host, Login, username, endpoint, and
position. Trust review retains the same unauthenticated SSH connection; its
first negotiated key is pinned for all rekeys. Before agent access, private-key
decryption, or remote authentication, Rust requires exact saved trust or
explicit acceptance of that connection's key.

`sessionRespond(sessionId, promptId, intent)` accepts only the current,
correctly typed, one-use prompt. Trust intents contain no renderer-supplied
host or key. Passphrase intents are write-only, clear the input before sending,
and never enter React state; wrong local decryption requests a fresh prompt on
the same reviewed connection. Every encrypted hop has its own prompt. Stale,
duplicate, canceled, and cross-attempt replies fail. Canceling a prompt or
closing the tab cancels preparation, with reverse cleanup of the entire chain.
Delayed IPC acknowledgments cannot replace a newer hop's prompt. Background
sessions retain their pending prompts without opening a portal over the active
tab. Selecting that tab shows its prompt; hiding it clears any unsubmitted
passphrase field. The tab's host mark indicates that attention is needed.

## Connecting a contract

1. Add the commands in `src-tauri` with `#[specta::specta]` and run `pnpm bindings`.
2. Write `web/app/src/inventory/core-api.ts`: an `InventoryApi` that calls the generated `commands`, mapping their results to the contract's types where they differ.
3. In `web/app/src/app.tsx`, once the local data is open, render `Frame` with `HostsHome` inside an `InventoryContext.Provider` holding that API. The about text moves into Settings.
4. The screen tests (`web/app/test/hosts.test.tsx`) run against the gallery's sample inventory and describe the expected behavior; add tests for the adapter itself.

A contract change is made in `api.ts`, its screens, and this page together.
