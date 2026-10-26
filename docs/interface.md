# Interface and the core

The interface (`web/app`, `web/ui`) and the core (`crates/`, `src-tauri`) are built separately. Each screen states what it needs from the core as a TypeScript contract; the core implements that contract with typed commands. This page lists the contracts, what each operation must do, and how a contract is connected once its commands exist.

The screens never read the store or decide business rules. Private keys, account material and
tokens remain in Rust. Dedicated transient inputs accept SSH passphrases, keyboard-interactive
answers, the account password, and independent profile local passphrases. Recovery export stays
in the native Save dialog and never returns a key or path to the renderer. Transient inputs never
enter ordinary state snapshots or clipboard automation. Anything the screens must not decide —
validation beyond "is this field empty", what a deletion removes, which areas the user has
reached — is the core's.

## Seeing the screens

`pnpm --dir web/app dev`, then open `/gallery.html`. The gallery renders every screen and state with sample data, in any theme, (`web/app/src/gallery/sample-inventory.ts`), in English or Chinese, as on macOS or Windows. It is a development tool: it is not built into the application, and its sample data is not a reference implementation of the core.

## Look and feel

The interface has a character: the Scoplen mark, a small tilted egg whose eyes are a text cursor and a wink (`web/ui/src/components/mark.tsx`). It reacts only when something happens, never on its own: it watches the field being typed in the Add host dialog and shuts its eyes for a password or key, sleeps while the local data is locked, shakes its head when something is refused, and every host has its own egg in one of a few poses chosen from its identifier (`host-egg.tsx`). A session tab's egg shows the connection: eyes wide while connecting, asleep once closed, the attention color when it failed. The selected item is marked by the mark's open eye on its left edge (`pick.tsx`). With reduced motion the faces still change but nothing animates.

Colors and shapes come from a theme the person chooses in Settings (`web/ui/src/themes.css`, `theme.tsx`): Paper (the default), Brutal, Sakura, Midnight, and Phosphor, each in light and dark where it has both, or following the system. A theme sets every color token and its radii, border width, shadows, the way buttons press, and the heading face; components read only the tokens. Every theme's text pairs are checked for WCAG AA contrast by `web/ui/test/tokens.test.ts`. The choice is an interface preference of the device and is kept in the webview's local storage until the core offers a settings store.

Right-click menus are the application's own (`web/ui/src/components/context-menu.tsx`): hosts, session tabs, and the terminal offer theirs, text fields get Cut, Copy, Paste, and Select all, and elsewhere a right click does nothing, so the web view's Reload and Inspect never appear. Interface text is not selectable, as in a native application; fields, terminal output, addresses, and host keys are. Session tabs close with their button, a middle click, or their menu. The interface language can be fixed in Settings → Appearance; "Same as system" uses the language the core negotiated, and the choice is kept like the theme.

The terminal has its own colors, chosen in Settings → Terminal (`web/app/src/terminal-colors.tsx`, `terminal-settings.tsx`): "Match the theme" (the default) takes the interface theme's surface, text, and accent, and a set of fixed schemes uses their projects' published palettes. Each of the four surface colors and sixteen ANSI colors can be changed; an edit makes the colors the person's own scheme. They are applied to running sessions at once and kept like the theme. The session header has a shortcut to these settings, and sessions stay mounted and connected while another tab or Settings is shown.

Files opens beside a connected terminal, or below it in a narrow window. Each
IPC request carries the logical session, exact transport, operation identifier,
and remote path bytes to Rust. The panel keeps display-safe names and raw path
arrays for navigation. It sends no SSH traffic itself. Rust lists the
server's initial SFTP directory, opens subdirectories, and permits download of
regular files through the native Save dialog. Upload file asks Rust to select
one regular local file through the native Open dialog and upload it into the
current directory; the frontend never receives its local path or contents.
Rust checks an existing target and obtains native overwrite confirmation. If
the server cannot safely replace it, the original remains unchanged. The upload
intent passes the current interface locale so Rust can localize the native
overwrite dialog. New folder sends only the entered name and current raw
directory path to Rust. Rename sends a new name with the listed item's raw
path; it never derives a new path from its display name. Rust rechecks target
absence before dispatch, but standard SFTP v3 rename can still replace a target
created concurrently on some servers. Delete is available only for listed regular
files and directories. Rust checks the current remote type and asks for native
confirmation before removing a regular file or empty directory. Other entry
types remain visible but cannot be changed here.

Upload and download intents enqueue Rust-owned work instead of waiting for the
transfer in a mounted panel. `use-session-transfers.ts` reads typed snapshots with
at most one request in flight. Session, queue identity and decimal revision fence
stale replies. Snapshots contain bounded names, exact item/execution/transport
identity, direction, fixed issue categories and decimal byte counts. Native paths
and selected handles remain in Rust. The queue allows 16 outstanding slots,
including native selection reservations and unacknowledged Unknown results, and
retains the latest 32 known terminal records.

Closing Files hides transfers; it never cancels or replays them. The existing
listing can add files while transfers run, but navigation, refresh and remote
changes are disabled during actual queue work. Unknown results and paused downloads
alone allow browsing so the destination can be inspected. Cancellation and acknowledgement
identify the exact queue, item and execution. Reaching the byte total shows
finalizing, and only confirmed publication shows Saved. Cancellation is refused
after publication starts. Native replacement review identifies the authenticated
Host and Login from Rust's bound connection. Source and destination metadata are
rechecked before execution and local publication. These metadata checks do not
provide atomic filesystem compare-and-swap or detect every content change that
preserves metadata.

Disconnect interrupts unstarted items. Reconnect keeps the logical queue and its
results while creating a new authenticated transport; old items never run there.
The terminal offers Review transfers even after disconnect. Unknown results
require explicit acknowledgement, which clears a reminder without retrying or
claiming success. Cleanup uncertainty remains explicit. A directory error offers
another list; an uncertain create, rename or delete keeps the existing terminal
attention notice. Closing the logical tab settles its current save and releases
pending work.

An active download offers Pause while payload transfer is active. Pausing shows that
the current bounded part is still settling; only Rust's Paused snapshot confirms
the checkpoint is retained. Paused downloads keep their confirmed byte count and
queue capacity, while later files may run. Resume sends the same item identity to
Rust, which allocates a new execution at the FIFO tail and verifies retained local
and remote prefix bytes before continuing from the confirmed offset. The queue
shows Checking downloaded bytes without counting validation reads as new payload.
No picker is reopened, and the renderer never receives the retained partial path,
handle or digest. Pause, Resume and Cancel are fenced by queue, item and execution;
a fresh snapshot can settle a pending action even if its IPC reply is lost. Late
replies cannot override a newer action.

Pause and Resume are available only for downloads on their original ready
connection. Publication, interrupted transfers and Unknown results have no Resume
action. Reconnecting or closing the session ends paused downloads and settles
their owned cleanup. A retained remote handle is not an immutable snapshot; the
source must remain stable for a consistent complete-file download. Upload resume,
cross-connection recovery, queue recovery after tab/process closure, drag and drop
and other remote edits remain separate work.


`web/app/src/frame.tsx`. A strip of tabs above the content. The first tab is always Hosts, led by the mark; each session adds a tab after it, led by its host's egg (roadmap C5). On macOS the strip is the title bar: the window is created with `titleBarStyle: "Overlay"` and a hidden title, the strip leaves 92 px for the window controls, which sit centered in it, and its empty space carries `data-tauri-drag-region`. Windows keeps its native title bar. Settings opens from the gear at the right of the strip.

## Independent tunnels

Hosts → Tunnels lists saved Local TCP, Remote TCP and Dynamic SOCKS definitions and their independent runs. Saving only
writes inventory. Start selects an existing Login and uses the terminal's shared trust,
passphrase and Interactive dialogs without opening a terminal tab. The editor defaults to
loopback and explains access from other devices when another bind address is entered.

`useForwards` subscribes before listing native owners. Decimal revisions reject stale
snapshots without losing integer precision; refresh and unmount fence pending action replies.
The Shell keeps observing across view changes. A background challenge shows Needs attention
and an explicit Continue setup action. Leaving the view clears transient inputs and keeps the
native owner running; cancelling its preparation dialog sends Stop for that exact run.

Runs display the fixed Host, Login and endpoints captured by Rust, with current connection
count, uploaded/downloaded bytes and refusal count. Editing or deleting inventory never
relabels a running connection or removes its Stop action. Stopped and failed runs remain
visible; another attempt requires Start. The renderer receives no socket, key or credential
handle and sends no network traffic.

Remote labels the requested server listener separately from the fixed local target in the
editor and running snapshot. A successful Start does not report the actual interfaces:
server policy can override even a loopback request. Non-loopback requests also explain
access to the local service from devices reaching the remote listener. Saving requires
both nonzero ports, an explicit bind literal and a local target. Switching to Dynamic
clears the irrelevant fixed target. Unknown listener/cancellation outcomes remain failures
with an explicit instruction to check the listener before another Start.

## Remote text preview

Each ordinary file has an explicit Preview action beside Download. A transient dialog names
the file and current connection and shows complete literal read-only UTF-8 text. Empty files
have their own state. Rust permits at most 262,144 bytes, probes EOF, rechecks the ordinary
opened handle and path size/type/available modification time, and rejects oversized, changed,
incomplete or invalid text. TAB, CR and LF are permitted; NUL, other C0 controls, DEL and C1
controls are refused. The dialog interprets no HTML, Markdown, terminal escapes or active links.

`sessionPreviewFile(sessionId, transportId, operationId, path)` returns only typed text/byte
length or a fixed localized issue. Reading has a 60-second absolute deadline and 15-second
bounded SFTP steps. The current file-operation admission prevents preview from overtaking
runnable queued work. Paused and Unknown items retain their resources and allow browsing.
Input and resize continue through the independent terminal path.

Closing the dialog or Files, changing tabs/directories or replacing the transport discards
the text and cancels pending reading. Unique display and request identifiers prevent late
results or cancellation acknowledgements from replacing or closing a newer preview. Keyboard
closing restores the corresponding action after directory loading settles. No text enters
the local store, Recent, terminal snapshots, synchronization or diagnostics; no editor,
local write or remote write is started. SFTP v3 path resolution is not confinement or atomic
no-follow opening. Matching metadata and EOF do not establish an immutable snapshot.

## Personal account

Settings → Personal account reads saved public status without network access or database
mutation. From Local, Create account accepts a server URL, username, device name and transient
password, then asks Rust to prepare the real registration. Recovery export uses a native Save
dialog and must be explicitly confirmed before Submit. Unknown results expose exact Confirm;
only trusted unchanged results expose explicit Retry. Committed registration exposes Install
account profile, with an independent local passphrase when the system needs one. Stop and view
closure retain durable pending work, and startup never submits it automatically. Sign in calls
real password options/login and verifies account keys in Rust, then exposes explicit Admit this
device. It has no recovery-export step. Unknown admission permits only exact Confirm; a known
unchanged expired capability exposes safe cancellation followed by fresh password entry. Confirmed
admission exposes the same independent installer. Existing catalog identities direct the person
to their saved profile, with no replacement or Device reuse. Invitation enrollment, invitation
replacement and device pairing remain unavailable. An orphaned archived entry explains that its protocol has retired. Existing
local SSH data remains available. The frontend receives no recovery key, private key,
access token or refresh token, and performs no cryptography or network requests.

The header selects Local or a ready Account after explicit confirmation that sessions, transfers
and tunnels will close. Native commands capture the view's immutable generation from a request
header before dispatch. The native owner closes running work, denies admission during replacement
and waits up to 15 seconds for outstanding requests after tunnel shutdown. An unfinished native
dialog leaves the original profile selected with a clear error. A successful change remounts the
Shell and filters store, session, forward and background events by source generation. An obsolete
invoker rejects both dispatch and late replies. Local inventory and credentials are never copied
by account creation or selection. Existing account-bearing root stores retain their original
access and identity, with an explicit retained-profile label.

A retained profile shows its saved server, Account id and device name. Saved neutral admission
anchors are verified locally against the original private roots. Historical session flags,
cached bootstrap responses and archived invitation or pairing payloads cannot establish
admission. Rust leaves archived payloads in SQLCipher without reading or decoding them.

When the original device keys, ARK and both private Account roots remain available but neutral
anchors are absent, Revalidate this device is the explicit network action. It uses ordinary
signed-device authentication and validates the complete K-4 bootstrap against those roots and
all retained certificate, revocation, revision and epoch evidence. Credentials remain transient
until one captured-profile-generation-fenced transaction installs anchors, session and bootstrap.
A failed or superseded attempt preserves the original profile bytes and cannot start sync or
upload inventory. Revalidation does not resume a retired entry protocol or confirm a pending
D-128 operation; exact receipt confirmation remains separate.

Authenticate this device obtains a fresh signed challenge for an admitted profile. Authenticated
status means Rust retains a verified usable device session, which can refresh on a server
operation or background reconnect when its access token approaches expiry. It does not mean
inventory has synchronized. Existing hosts and credentials remain local.

Account, sync and authentication actions share one busy state to block duplicate intents.
Finishing an action reloads status locally. Late results from an unmounted view or superseded
status request cannot replace current state. Errors use typed localized codes; arbitrary IPC
or server diagnostics are not rendered. Reload status retries a local read. Settings navigation
supports arrow keys, Home/End, visible focus, and wrapping at narrow widths.

Account and devices loads the last saved manual query locally, including after authentication
expires. Refresh account and devices is the only network action for this panel; it queries the
profile and complete signed device set together. All verification must succeed before either
result changes. The panel displays the real account id, an exact optional email (or its absence),
signed names and platform claims, the current device, and the device-local Last manual query time.
It labels these as saved results, not live presence, hardware guarantees or server admission.
Errors retain the previous snapshot and timestamp, and expose no raw response. Account and sync
intents share the parent's busy state; revocation publication remains separate work.

An expired refresh family or uncertain renewal shows Authenticate this device with an explanation
that local inventory, recovery copies and sync keys were retained. That action obtains a fresh
challenge using the saved identity. Finishing a sync action reloads account status locally, so renewal failure updates
the recovery action without another network request. Retry-After and narrowed-permission failures
have separate localized messages. Mounting settings and offline recovery never renew a session.

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
cycle with more work offers the same explicit Sync now action and the native owner schedules
continuation for already adopted objects. Background status explains live connection, 60-second
fallback, required authentication, permissions and unsupported rotation. Observing this state
does not start synchronization; the native owner runs independently of Settings. Original local copies have a
separate exact selection and confirmation. Restore works with expired authentication and no
network, creates new local objects, and explicitly says it does not undo remote data or copy
device-only secrets/handles. Cancelling either confirmation performs no mutation.

After complete reconciliation, missing objects with local edits appear in Local edits need
attention, separately from original adoption copies. The panel identifies the original object
and its immutable recovery copy, allows one historical copy per original in a selection, and
never selects them for upload. Recover selected edits has its own exact selection and offline
confirmation; it creates new local objects whose upload requires a fresh review and consent.
Failed or unconfirmed sync actions reload this durable attention state without another network
attempt. Concurrent server changes ask for an explicit retry with a fresh session.

## Teams

The generation-bound native API keeps access tokens, DPoP proofs, canonical create bytes and
the original idempotency key in Rust. `pending_team_creation` reads SQLCipher locally, while
`teams_page` queries one current membership page only on an explicit intent. Rust validates the
complete Account-bound response before returning team ids, names and role identifiers for
display. `prepare_team_creation` saves a valid exact name without dispatching; a subsequent
`submit_team_creation` sends only that retained operation.

Unknown creation keeps the original operation through restart. Explicit retry uses fresh DPoP
and the same key/body within the original 24-hour window. A verified first unchanged response
can return to prepared; a later denial does not erase earlier uncertainty. Confirmed state can
be explicitly dismissed. An expired operation requires refreshed discovery before the person
decides to clear it or create another team. `discard_team_creation` rejects a still-retryable
unknown operation. These intents do not change the selected Personal profile or its inventory,
and role labels never grant client-side asset permissions.

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
| `savedOutput(id)` | Explicitly reads a retained terminal snapshot and its current Login metadata, without network access, history creation, or a credential lookup. `hasSavedOutput` in Recent is availability metadata only; retention and local read errors are handled when viewing. |
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

Connection details in a terminal lists each verified hop, fingerprint, trust method, source
device, and recorded confirmation time. A Personal key confirmed manually or imported on
another active enrolled device needs no additional prompt. A known revoked source instead
opens Confirm this host key again before SSH authentication; an unknown source shows no
unverified name or timestamp. A same-key confirmation on another active device remains usable.
These decisions use locally verified signed device statements and work offline. Fresh attempts
clear the previous connection details, and stale transport events cannot restore them.

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
current saved Login. Recent's View output opens a saved snapshot offline and read-only, including
after restart. Reconnect is a separate explicit action through the current saved Login.

`sessionSaveOutput(sessionId, transportId, sequence, snapshot)` checkpoints only rendered state
owned by the exact open store, logical session and current attempt. Rust rejects stale or
out-of-order writes, forgotten/pruned rows, invalid grids and snapshots above 1 MiB, preserving
the previous valid snapshot. Aggregate retention is 64 MiB. The terminal serializes only after
renderer writes drain. Checkpoints run every five seconds; orderly close stops the transport,
drains its final output, and awaits a final checkpoint before unmounting. Save failure leaves
the view open with a local explanation and explicit Close without saving. Restoring suppresses
terminal replies, keyboard/paste and broadcast input. Window close and ordinary application
quit use this same flow before native geometry saving and background shutdown.
Explicit discard closes the logical session through unmount cancellation without repeating
a failed transport drain or checkpoint.
The window capability includes `allow-close` for requesting that flow and `allow-destroy`
for Tauri's `onCloseRequested` wrapper, which destroys the window after the checked
close request is allowed.

The session header also offers Reconnect after the current connection closes or
fails. It stays disabled until that attempt finishes cleanup. The same terminal
element keeps its displayed scrollback while a new transport identifier runs the
normal host-key review, current saved-credential lookup, and one-time passphrase
prompt. Each accepted attempt records its own history lifecycle. Old ready,
output, input-error, and trust results cannot update the replacement connection;
closing the tab cancels the whole logical session. Reconnect retains the open tab's
display; use Recent's View output to reopen a closed tab's saved snapshot.

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

Add Host and each Login in Edit Host offer Interactive (OTP/PAM). Saving creates a
kind-8, binding-None descriptor and explicitly references it from that Login; editing
Host metadata and these Login choices commits atomically. The Credential editor can
also create or convert this descriptor, clearing all previous authentication material.
Other saved credential choices retain their meaning. Any usable local credential
does not implicitly select Interactive. Reconnect and Direct Jump hops resolve each
saved Login independently.

`sessionRespond(sessionId, transportId, promptId, intent)` accepts only the current,
correctly typed, one-use prompt. Trust intents contain no renderer-supplied
host or key. Passphrase intents are write-only, clear the input before sending,
and never enter React state; wrong local decryption requests a fresh prompt on
the same reviewed connection. Every encrypted hop has its own prompt. Stale,
duplicate, canceled, and cross-attempt replies fail. Canceling a prompt or
closing the tab cancels preparation, with reverse cleanup of the entire chain.
Delayed IPC acknowledgments cannot replace a newer hop's prompt. Background
sessions retain their pending prompts without opening a portal over the active
tab. Selecting that tab shows its prompt; hiding it clears any unsubmitted
passphrase or challenge fields. The tab's host mark indicates that attention is needed.

Interactive dialogs have a fixed localized title and trusted hop identity, with literal
server name, instructions and ordered prompts shown separately. Echo-true controls show
text and echo-false controls hide it. Both use uncontrolled DOM values, clear immediately
on submit, hide, replacement, cancellation or unmount, and send only ordered answers.
Empty answers are permitted; zero-prompt rounds require Continue and send an empty vector.
Rust enforces shared answer bounds and prompt count, a 120-second challenge deadline and
a 300-second absolute authentication budget per trusted hop, including key-passphrase
waiting. Wrong, overdue, duplicate and old-transport replies are refused. Answers never
enter React state, history, terminal output, saved objects or reconnect state. An accepted
password/key/agent factor continues into Interactive only through a typed partial-success
rejection advertising that method; ordinary rejection never selects a fallback.

## Connecting a contract

1. Add the commands in `src-tauri` with `#[specta::specta]` and run `pnpm bindings`.
2. Write `web/app/src/inventory/core-api.ts`: an `InventoryApi` that calls the generated `commands`, mapping their results to the contract's types where they differ.
3. In `web/app/src/app.tsx`, once the local data is open, render `Frame` with `HostsHome` inside an `InventoryContext.Provider` holding that API. The about text moves into Settings.
4. The screen tests (`web/app/test/hosts.test.tsx`) run against the gallery's sample inventory and describe the expected behavior; add tests for the adapter itself.

A contract change is made in `api.ts`, its screens, and this page together.
