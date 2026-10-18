# Interface and the core

The interface (`web/app`, `web/ui`) and the core (`crates/`, `src-tauri`) are built separately. Each screen states what it needs from the core as a TypeScript contract; the core implements that contract with typed commands. This page lists the contracts, what each operation must do, and how a contract is connected once its commands exist.

The screens never read the store, decide business rules, or hold secrets. Anything the screens must not decide — validation beyond "is this field empty", what a deletion removes, which areas the user has reached — is the core's.

## Seeing the screens

`pnpm --dir web/app dev`, then open `/gallery.html`. The gallery renders every screen and state with sample data, in any theme, (`web/app/src/gallery/sample-inventory.ts`), in English or Chinese, as on macOS or Windows. It is a development tool: it is not built into the application, and its sample data is not a reference implementation of the core.

## Look and feel

The interface has a character: the Scoplen mark, a small tilted egg whose eyes are a text cursor and a wink (`web/ui/src/components/mark.tsx`). It reacts only when something happens, never on its own: it watches the field being typed in the Add host dialog and shuts its eyes for a password or key, sleeps while the local data is locked, shakes its head when something is refused, and every host has its own egg in one of a few poses chosen from its identifier (`host-egg.tsx`). A session tab's egg shows the connection: eyes wide while connecting, asleep once closed, the attention color when it failed. The selected item is marked by the mark's open eye on its left edge (`pick.tsx`). With reduced motion the faces still change but nothing animates.

Colors and shapes come from a theme the person chooses in Settings (`web/ui/src/themes.css`, `theme.tsx`): Paper (the default), Brutal, Sakura, Midnight, and Phosphor, each in light and dark where it has both, or following the system. A theme sets every color token and its radii, border width, shadows, the way buttons press, and the heading face; components read only the tokens. Every theme's text pairs are checked for WCAG AA contrast by `web/ui/test/tokens.test.ts`. The choice is an interface preference of the device and is kept in the webview's local storage until the core offers a settings store.


`web/app/src/frame.tsx`. A strip of tabs above the content. The first tab is always Hosts, led by the mark; each session adds a tab after it, led by its host's egg (roadmap C5). On macOS the strip is the title bar: the window is created with `titleBarStyle: "Overlay"` and a hidden title, the strip leaves 84 px for the window controls, and its empty space carries `data-tauri-drag-region`. Windows keeps its native title bar. Settings opens from the gear at the right of the strip.

## Inventory (roadmap C3)

Contract: `web/app/src/inventory/api.ts` (`InventoryApi`). Screens: `inventory/home.tsx` (sidebar, list, details), `inventory/host-details.tsx`, `inventory/add-host.tsx`.

| Operation | What the core does |
| --- | --- |
| `areas()` | Which sidebar sources exist (`01-product-definition.md` §7.6): `favorites` when any host is a favorite, `recent` when the session history names a host, `groups` when any group exists, `keys` when a credential has been promoted by reuse or inspection, and `routes` when a route exists. Implicit tier-0 credentials do not make Keys visible. |
| `groups()` | Every group with its parent and host count. |
| `hosts(source, query)` | Hosts from the source (all, favorites, recent, or one group and its subgroups) whose name, address, username, or `key:value` tag contains the query, case-insensitive; favorites first, then by name. Orphaned hosts are not listed. `username`, `loginCount`, and `route` describe the default login, else the only one. |
| `recentSessions()` | The newest device-local session history entries, with the current Host label and login metadata. Entries whose Host or Login was deleted are omitted; no credential, scrollback, or live connection data is returned. Timestamps are decimal Unix-millisecond strings at the IPC boundary. |
| `openSession(profileId, kind)` | Records an open event after a real connection owner has accepted a transport; the login must still exist. It does not open a socket. The result is the same redacted session DTO shown by `recentSessions()`. |
| `closeSession(id, outcome)` | Records `closed` or `failed` from the connection owner. A missing or already-ended session is rejected, and a failed write leaves history unchanged. |
| `reconnectSession(id)` | Validates the history entry and returns an explicit transport-unavailable error until reconnect ownership is connected. The direct password connect command owns its live connection separately and never creates a history row by itself. |
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
| `routes()` / `createRoute()` / `updateRoute()` / `deleteRoute()` | Lists and edits reusable local Routes, validating jump profile and proxy credential references and endpoint shapes. Routes with a missing jump profile or proxy credential are shown as orphaned and can be restored or deleted. Managed routes are display-only on the device, and routes referenced by a profile cannot be deleted. |

These operations return `ObjectEditError` on validation, reference, or
in-use failures. The error reference is diagnostic text and never contains
credential material. Independent object DTOs carry only redacted credential
labels and usage counts; secrets never cross the IPC boundary.

Every operation that can fail returns `Outcome`; a `Failure` carries a reference for support, free of secrets.

The tier-0 OpenSSH importer accepts simple literal `Host` blocks with `HostName`, `User`, `Port`, and `IdentityFile` values. It skips a host block when a directive or value in that block cannot be represented. Global settings, wildcard `Host` patterns, `Include`, and `Match` can affect other blocks, so the preview excludes every host in those files and explains why. Full OpenSSH semantics, `known_hosts`, keys discovery, and idempotent re-import belong to roadmap C10; this flow is limited to an empty inventory.
Session lifecycle commands emit `sessionChanged` after a successful open, close, or
forget operation so the Recent view reloads without polling. The event carries only
the session identifier and transition. Transport ownership, reconnect, terminal
output, and credentials remain outside this history boundary until the connection
orchestrator and protocol core are implemented.

## Connecting a contract

1. Add the commands in `src-tauri` with `#[specta::specta]` and run `pnpm bindings`.
2. Write `web/app/src/inventory/core-api.ts`: an `InventoryApi` that calls the generated `commands`, mapping their results to the contract's types where they differ.
3. In `web/app/src/app.tsx`, once the local data is open, render `Frame` with `HostsHome` inside an `InventoryContext.Provider` holding that API. The about text moves into Settings.
4. The screen tests (`web/app/test/hosts.test.tsx`) run against the gallery's sample inventory and describe the expected behavior; add tests for the adapter itself.

A contract change is made in `api.ts`, its screens, and this page together.
