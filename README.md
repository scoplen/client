# Scoplen client

> The Scoplen desktop client for macOS and Windows: an SSH client that connects to hosts directly or through a self-hosted Scoplen bastion.

Scoplen is a Plystra project. The full Plystra philosophy applies; this repository's review record is [PROJECT_PRINCIPLES.md](PROJECT_PRINCIPLES.md), which links to the project record in `scoplen-docs`.

Owner and operator: Plystra LLC. Responsible maintainer: Plystra LLC.

## Status

Maturity: Exploration. Maintenance: Active.

The application shell is in place: a Tauri 2 application for macOS and Windows, the Scoplen identity and design tokens, typed IPC generated from Rust with a binary channel transport, and a design system foundation with keyboard navigation, screen-reader labels, light and dark themes, increased-contrast and reduced-motion support, and ICU localization in English and Simplified Chinese. It keeps an encrypted local store: a SQLCipher database whose key is held in the macOS Keychain or, on Windows, by the TPM or DPAPI, optionally with a local passphrase. The desktop can manage local hosts, groups, tags, favorites, notes, and credentials. An empty inventory can preview and import simple literal OpenSSH `Host` blocks, reporting skipped hosts and unsupported directives without modifying the source file. SSH connects directly, through a saved SOCKS5 or HTTP CONNECT proxy with optional username/password authentication, through an explicit saved Jump chain, or through a saved local ProxyCommand. Each SSH host uses its saved password, OpenSSH Ed25519, ECDSA P-256/P-384/P-521, or RSA software key, or an explicitly selected key in the system SSH agent, after independent host-key review. The target opens an interactive terminal with ANSI rendering, keyboard input, and close handling. Encrypted private keys prompt for a one-time passphrase after that host's review. New or changed keys require explicit acceptance; wildcard-only and CA records do not authorize raw host keys. Other credential kinds and sync follow the client track of [`scoplen-docs/17-implementation-roadmap.md`](../scoplen-docs/17-implementation-roadmap.md).

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

Choose Interactive when adding a host, or for a Login in Edit Host, for OTP or PAM
login without a stored password or key. The Credential editor also offers Interactive (OTP/PAM), which
can be assigned to a saved Login, including a Direct jump Login. Server requests
show each prompt in order and respect its echo setting. Informational requests
with no inputs require Continue. Answers are cleared after submission or hiding
the prompt and are never saved or reused by reconnect. A selected password, key,
or agent continues into Interactive only after the server accepts that factor
and advertises keyboard-interactive; a rejected credential does not fall back.
Each hop has five minutes for authentication, including key passphrase entry,
and each server request has at most two minutes for a reply. Cancellation or
expiry closes that connection attempt; reconnect starts with blank inputs.

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

Tunnels manages saved Local TCP, Remote TCP and Dynamic SOCKS forwards independently of terminal
tabs. Local and Dynamic use a numeric local IPv4 or IPv6 address and a nonzero local
port. Local also needs a destination hostname or address and nonzero destination
port; Dynamic takes each destination from SOCKS4/4a or SOCKS5 CONNECT. New definitions
use `127.0.0.1`. Dynamic provides no SOCKS authentication: devices able to reach its
listener can request destinations through the selected SSH connection. Review that
access before choosing a non-loopback listening address. Choose Start and an existing
Login, then complete its ordinary host-key, key-passphrase or Interactive review.
The tunnel opens no terminal or shell. The SSH server resolves destination hostnames.

Running tunnels show their fixed configuration, connection count and traffic.
Leaving Tunnels keeps them running; editing or deleting a saved definition does
not change an existing run. Stop closes its listener, peers and SSH route. At most
16 tunnels and 32 peers per tunnel run at once, including SOCKS negotiation and
channel opening. Dynamic negotiation has an absolute 15-second deadline; channel
opening and the final SOCKS response each have their own 15-second deadline. Traffic
counts include only application bytes successfully written, excluding SOCKS messages.
A failed run requires an explicit new Start; tunnels do not reconnect or start
automatically. Application exit or local-store replacement stops every run. Unix-socket
and ad-hoc forwarding remain incomplete.

Remote requests a fixed nonzero listening port and numeric IPv4 or IPv6 address on the
SSH server, and reaches a fixed local target whose hostname is resolved by this device.
It opens no local listener or terminal. The editor and run view distinguish the requested
remote listener from the local service. Devices able to reach that listener can reach the
local service; review the server's forwarding and listening policies before starting.
Even a loopback request does not prove loopback-only access: OpenSSH `GatewayPorts` can
override the requested address, and SSH does not report the actual listening interfaces.
Incoming channels must match the acknowledged request exactly before a local connection
is attempted. Local resolution and dialing share a 15-second deadline. Stop attempts
remote cancellation, then closes the owned SSH route regardless of the reply. An unknown
registration or cancellation result reports unconfirmed cleanup; check the listener
before starting again.

A connected terminal's Files button opens an SFTP browser on that terminal's
authenticated SSH connection. It starts in the server's initial SFTP directory,
opens subdirectories, and downloads regular files to a location selected in the
native Save dialog. Upload file selects one regular local file through the native
Open dialog and sends it to the current remote directory. An existing regular
file requires explicit overwrite confirmation; if the server cannot safely
replace it, the original stays unchanged. Files can also create one folder in
the current directory, rename a regular file or directory after checking that
the new name is unused, and delete a regular file or empty directory after native
confirmation. Standard SFTP v3 rename may still replace a concurrently created
target on some servers. Other remote entry types are shown but cannot be changed here.

Upload source admission rejects final symbolic links on Unix and final reparse
points on Windows, including substitutions after the initial path check. Ancestor
directories resolve normally. Rust retains the admitted ordinary-file handle, so
later path replacement does not redirect reads; concurrent writes to that file
remain possible. Keep the source stable until the upload saves.

Uploads and downloads join a FIFO queue owned by the logical terminal session.
Up to 16 selections, queued files, running or paused transfers and unacknowledged unknown
results may be outstanding; the latest 32 known results remain visible. Hiding
Files leaves transfers running. You can add files from the current listing while
a transfer runs; directory navigation and remote changes wait until the queue is
settled; paused transfers release execution so later queued work and file navigation can run.
One native picker or replacement review is open per queue.

Files also accepts a native drop of 1 to 16 ordinary local files onto its visible remote
directory list, including an empty list. The entire selection must fit the queue and pass
local source/name checks before any item is added. A rejected batch starts no upload; an
accepted batch keeps native selection order and its original remote directory. Each item
then uses the ordinary replacement review, cancellation and publication rules. Leaving Files
does not cancel admitted items. Folders, links and special files are refused. The Upload file
button remains the keyboard alternative. Native scaled Windows and Retina macOS drag/drop
acceptance remains unverified.

Files shows confirmed contiguous bytes and a separate finalizing state. Only a
confirmed remote publication or local save shows Saved. Cancellation stops an
unstarted item or waits for cleanup of its running attempt; once final save has
started it cannot report a successful cancellation. Replacement review names
the bound Host and Login. A queued upload rechecks its retained source; a download
rechecks its local destination before replacing it. Metadata checks cannot detect
content changes that preserve all compared metadata or eliminate a change between
check and rename.

Disconnect interrupts unstarted items and never sends them over a new transport.
Unknown results stay visible across hiding Files and reconnecting. Check the
destination before adding the file again; Dismiss reminder releases its queue
slot without verifying or retrying the transfer. Cleanup warnings state when an
incomplete file may remain. Closing the logical tab cancels pending work and
settles a save already in progress. The queue has no recovery after tab or process
closure. A download can pause after its current bounded segment settles and resume explicitly
on the same connected SSH transport. Resume keeps the original open remote file and local
partial, verifies both confirmed prefixes, and queues a fresh execution at the FIFO tail.
Verification rereads the complete confirmed prefix locally and remotely on every resume; its
cost grows with that prefix and does not increase displayed payload progress. Metadata and an
open handle do not provide an immutable source snapshot: unread suffix changes or concurrent
writes after verification can still affect a download. Keep the source stable until it saves.
Cancellation and disconnect settle owned partial cleanup; a detected replacement is preserved.
Uploads can also pause on the original live transport when the server admits a separate
read handle for the exclusively created private staging file. A server refusing staging
reads still supports ordinary uploads without Pause. Pausing settles a bounded segment and
supported remote synchronization, then checks both confirmed prefixes. Resume retains the
original local source and remote write/read handles, verifies source, staging and destination,
and continues at the confirmed offset under a fresh FIFO execution. Validation reads do not
increase payload progress. SFTP v3 has no stable file identity: matching staging attributes
and prefix hashes cannot prove inode identity, an unchanged unread suffix or absence of
concurrent writes after validation. Keep the source and staging stable until publication.
Continuation after reconnect or tab/process closure remains separate C6 work.

Preview reads one complete ordinary UTF-8 file of at most 256 KiB through the current
terminal's SSH connection. It shows literal read-only text in a transient dialog, without
opening an editor, writing a local copy or starting synchronization. Empty files are supported.
Larger files, invalid UTF-8 and non-text controls require Download instead. Closing the preview,
changing tabs or ending the connection discards the text. Runnable transfers take priority;
paused or unknown-result items do not prevent preview. Remote handle and path metadata and EOF
are checked, but SFTP v3 provides neither an immutable snapshot nor atomic no-follow opening.

When a session closes or fails, choose Reconnect in its header to connect again
in the same tab. Its displayed terminal output stays available. Reconnect waits
for the previous connection task to finish, rechecks the host key, resolves the
current saved login, and prompts again when a one-time key passphrase is needed.
Each attempt uses a new transport identifier and records a separate Recent
entry. Closing the tab cancels its pending connection.

A terminal that has connected successfully retries confirmed network failures after
1, 2, 4, 8, and 16 seconds, with at most five automatic attempts. Thirty continuous
seconds connected reset the budget; choosing Reconnect starts a fresh budget.
The first failed connection, normal remote exit, authentication or configuration
errors, and terminal rendering errors do not trigger automatic retries. Each
attempt reads the current saved Login, Host, Route, and Credential, repeats host-key
review when required, and asks again for one-time passphrases. A background tab
shows that it needs attention and waits until selected before displaying a prompt.
Stop reconnecting cancels the delay or current preparation while retaining the tab.
Reconnecting starts a new remote shell and keeps the current displayed output;
queued input is discarded and remote processes are not restored.

Accepted SSH connection attempts appear in Recent using device-local history.
Normal completion and an explicit close during connection preparation record
`Closed`; connection errors and externally dropped connection tasks record
`Failed`. Closing a tab releases its transport registration.
An ended terminal in Recent can be started again through the normal Connect
entry point using its current saved login. The lookup opens no connection and
does not write history; the new attempt runs the usual host-key checks and
records its own lifecycle. Active sessions and Files/Forward entries do not
offer this action. Recent also offers View output when a saved terminal snapshot is retained.
It opens offline and read-only, without a connection or terminal input. Reconnect is explicit
and repeats the normal current Login, host-key and credential checks while retaining the display.

Rendered output is checkpointed every five seconds and before an orderly tab or application
close, in the encrypted local store only. A snapshot is limited to 1 MiB; retained snapshots
together are limited to 64 MiB, evicting the oldest output while retaining Recent entries.
Forgetting or pruning history removes its output atomically. An interrupted application can
recover its last durable checkpoint. A save failure keeps the tab/window open with an explicit
Close without saving option; it does not interrupt ordinary live SSH. Workspace restoration
and remote-process resumption remain separate capabilities.

Settings -> Personal account keeps access for an existing confirmed profile. It can authenticate
that device with its saved signing key, query account/device metadata, and explicitly verify
sync keys. Registration and password sign-in are not available in this build; local SSH remains
available. Invitation enrollment, invitation replacement, and device pairing have been retired.
An unfinished old setup is preserved and cannot resume its retired entry protocol.

Rust has a separate registration preparation API with the real fixed D-127 password derivation,
locally verified key wrappers, a mandatory saved recovery key and explicit confirmation.
Its independent SQLCipher pending record keeps the original Device keys and signed business
bytes through restart and uncertain request handoff. A separate Rust HTTPS driver runs fresh
D-128 challenge/register/exact-confirm exchanges over verified TLS 1.3/H2 without redirects.
Trusted unchanged Submit results permit only an explicit retry; unknown outcomes remain
receipt-only, including after a missing receipt. A separate Rust installation API creates an
independent encrypted candidate after exact confirmation and makes it usable only after fresh
ordinary Device authentication and complete verified K-4 bootstrap. Its encrypted Local catalog retains each
Account by canonical origin and Account id, with independent local key protection. Explicit Rust
selection/reopen gives each namespace a fresh generation and Store; Local inventory stays local.
Failed installation keeps the original keys and directory reservation for explicit retry.
Device keys are software keys protected by SQLCipher, not hardware-held non-exportable keys.
These APIs expose no desktop commands. The registration/profile-selection UI, password sign-in,
next-Device admission and Team context switching remain incomplete.

Profiles with saved neutral admission anchors continue to verify offline against their original
private roots. Profiles without those anchors require explicit current-device revalidation;
historical session flags, cached bootstrap responses and archived entry payloads cannot grant
admission. The client no longer reads or decodes archived invitation or pairing payloads, and
preserves the original database bytes. The admitted profile binds its canonical origin, Account,
Personal vault, device, and keys immutably to this encrypted store. Existing local SSH data stays local.
This is the retirement/storage prerequisite for D-128; password admission and full multi-profile
or Team context switching remain incomplete.

When a historical profile retains its original device keys, ARK and both private Account roots,
Revalidate this device explicitly proves its current server authority through ordinary device
authentication and verifies the complete K-4 bootstrap. Credentials stay transient until the
original keys, signed device statements, revocations, revision and epoch evidence all agree.
One open-profile-generation-fenced transaction installs neutral provenance, session and bootstrap;
failure preserves the original bytes and cannot activate background sync. This does not recover
a historical receipt, establish password credentials, resume an old entry request, or upload local
inventory. Pending D-128 operations must use their separate exact receipt confirmation.

Account and devices reads its saved results locally when Settings opens. Refresh account and
devices explicitly queries the authenticated account profile and complete signed device statement
set, renewing the native session when needed. Rust verifies the whole set against the retained
account signing key, applies revocations, and requires this device's exact saved certificate before
atomically saving a new offline snapshot. The panel shows the optional email, signed device names
and platform claims, this device, and the last manual query time. Failed queries retain the previous
results; opening the page never starts a query. These results do not prove recent activity,
hardware protection, current server admission, or statements a server has withheld. Revocation
publication and key rotation remain separate work.

The Rust core can bootstrap admitted devices through the real sync session,
account-key, and Personal vault-key endpoints. It requires a verified DPoP-bound access token,
TLS 1.3, and HTTP/2; verifies certificates and every key wrap against the neutral admission anchors;
and atomically saves the complete result in SQLCipher for offline restart. Membership-only
account revisions can advance while the account key ciphertexts and recovery blob match the
saved neutral anchors. Each profile retains its verified Personal epochs, checks responses against
its admission revision and key projection, and keeps the same verified epoch/key set at later
membership revisions. A newer revision may rewrap
this device's unchanged ARK. The saved revision prevents later rollback, including after
restart; at the same revision only independently verified device statements may change.
A pending or newer key rotation returns a distinct unsupported-rotation error while keeping
the existing keys. In Settings → Personal
account, Verify sync keys explicitly runs that bootstrap. Reopening the page revalidates saved
keys locally, including when device authentication has expired; server access requires fresh
device authentication. The interface receives only a verified/not-connected state and safe,
localized errors. This step does not pull or upload inventory.

Native session refresh is single-use and claimed durably in SQLCipher before sending. It
verifies the new token's issuer, signature, account, device, signing-key binding and non-expanding
scope, and cannot extend the original refresh family's absolute expiry. JWT issuance and remaining
whole seconds may cross a clock boundary; their lifetime estimate is capped by the retained
deadline. The active background owner refreshes before reconnecting near expiry. There is no
automatic replay after a missing response or uncertain commit. Authenticate this
device uses a fresh challenge with the retained identity when required; saved keys, inventory
and recovery copies remain available offline. A verified unchanged rate-limit response retains
the credential and its Retry-After deadline for a later operation. Older saved sessions
without a verified scope ceiling require fresh authentication after this update.

The Rust-owned `sync_personal_inventory` API implements a bounded Personal
roundtrip. Its typed intent names the retained vault and exact local object ids to adopt;
account setup never supplies this intent. Adoption atomically retains immutable encrypted
local copies, moves only the selected objects, and queues their initial writes. Existing
references must be selected explicitly; unselected and subsequently created objects stay
local. Later edits and deletions of adopted objects remain queued across offline restarts.
The core pulls authenticated encrypted pages, merges and saves their cursor before acknowledging,
and encrypts queued K-1 objects with the verified Personal key before compare-and-swap writes.
Device-bound private keys, secrets, and keystore handles never enter these envelopes.
Conflicts merge and retry within a fixed budget. Unknown write outcomes retain the queue and
require a fresh pull on the next cycle. Immutable adoption copies can be restored as
fresh local objects, preserving the original copies and leaving remote state unchanged.

After Verify sync keys succeeds, Inventory sync exposes local status, exact object selection,
a shared-secret preview, and a separate confirmation before enabling upload. Referenced objects
are listed when missing; they are never silently selected. A one-use five-minute review ticket
stays bound to the store and selected object versions in Rust. Adoption compares those versions
inside its SQL transaction, so an edit after preview requires another review. Sync now pulls and
uploads only the existing Personal objects; it does not adopt any newly created local object.
Applied and acknowledged positions are displayed separately without JavaScript integer loss.
Original local copies can be selected and restored while offline; this creates new local
objects and does not undo server changes or restore device-only secrets and handles.

Version history queries one explicitly selected Personal object and verifies the complete
retained list before showing names, categories, sequences, and content flags. Opening Settings
does not query history. After selecting a version, a separate confirmation creates a fresh
local copy with a new identifier and field clocks. The original object and concurrent edits
stay intact. This does not upload or overwrite anything; the new copy needs the usual explicit
adoption and shared-secret review before synchronization. The single-use review expires after
five minutes and cannot be reused after reopening the store. Device-local credentials and
hardware handles are never copied. Malformed or over-budget history leaves inventory and
sync cursors unchanged.
Every signer must currently remain active. If the verified account bundle revokes a historical
signer, the entire query stops with a specific explanation and creates no review or copy.
An unrecognized signer, unverifiable former root, or damaged signature still fails validation.
The signed revocation timestamp cannot be compared to a trusted envelope write time: server
sequences are not signed, and field clocks belong to the signer. Restoration of pre-revocation
history remains incomplete until verifiable historical authorization and rotation are supported.
After a copy is created, a failed inventory refresh preserves the confirmed copy result and
asks for Refresh local status; it does not retry restoration or report a failed copy.

An expired cursor downloads and verifies a complete, bounded snapshot before one atomic local
reconciliation. Missing clean objects are removed; missing local edits, including new selections
that never uploaded, become immutable encrypted recovery copies requiring attention. They never
upload automatically. Recover selected edits works offline and creates fresh local objects that
need a separate upload preview and confirmation. Original adoption copies remain separate.
Failed snapshot downloads leave inventory and cursors unchanged. Concurrent server writes stop
the pass safely; the next bounded cycle retries with a fresh session. Key rotation
and shared/organization host-key trust policies remain later outcomes. Personal manual and
known_hosts trust records replicate with verified same-account device provenance. SSH automatically
uses confirmations from an active enrolled device and shows their source and recorded time in
Connection details. A revoked source needs confirmation on this device unless another active
device confirmed the same key. Verified revocations remain effective offline and cannot be
removed by replaying an older signed active list. Missing or unverified provenance remains
local and requires review before sync; wildcard-only records and bare CA/policy claims do not
authorize raw host keys. A newly created trust record still needs explicit upload selection.

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

`scripts/test-ssh-keyboard-interactive.ps1` uses PowerShell 7 and Docker to start
disposable OpenSSH 9.9/PAM listeners with exact package versions. Through public
saved client preparation it checks explicit Interactive, accepted password/key/agent
continuation, wrong-answer/key refusal, fresh successful attempts, cancellation
and late replies, another terminal while one challenge waits, and Interactive
Jump plus target authentication. Every successful connection must execute the
exact expected command with exit status zero. The fixture cleans up its own
containers and temporary keys.

`scripts/test-ssh-local-forward.ps1` checks saved standalone TCP tunnels against
disposable OpenSSH listeners with session channels disabled. It exercises password,
encrypted-key, Interactive and Jump preparation, concurrent binary streams, half-close,
exact traffic counts, refusal, cancellation and SSH loss while another terminal stays
usable. It requires PowerShell 7, Docker and `ssh-keygen`. Successful runs remove their
owned resources; failed runs retain private diagnostics and stop their owned container.

`scripts/test-ssh-dynamic-forward.ps1` checks saved SOCKS4a/5 tunnels through Direct
and Jump routes against disposable OpenSSH listeners with session channels disabled.
It verifies literal destination names and server-side resolution, concurrent binary
streams with coalesced application bytes, half-close, application-only counters,
refusals, the absolute handshake deadline and cleanup during negotiation, channel
opening and copying. Saved edits/deletion leave the running configuration fixed;
an independent terminal remains usable. It uses the same prerequisites and fixture
retention rules as the Local check.

`scripts/test-ssh-remote-forward.ps1` checks saved Remote TCP tunnels with fixed local
targets and no SSH session channels. It verifies Direct, encrypted-key, Interactive and
Jump preparation, concurrent binary peers, both half-close directions, exact counters,
local refusal/recovery, occupied and denied listeners, requested versus actual
`GatewayPorts` scope, Stop, SSH loss and complete route cleanup while a separate terminal
stays usable. It uses the same prerequisites and fixture retention rules as the Local check.

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
`scripts/test-ssh-session-files.ps1` runs a connected terminal and Files operations
against a disposable OpenSSH server. It checks directory browsing, binary
transfer progress and finalization, including a failed local save after all bytes
arrive, on the same authenticated connection, plus folder creation, file rename
and collision handling, delete-confirmation outcomes, empty-directory deletion,
cancellation and failure recovery while terminal input and resizing remain available. It requires
PowerShell 7 and Docker, and removes its container and temporary files afterward.

On macOS, `scripts/check-offline.sh target/release/bundle/macos/Scoplen.app` verifies that a built application makes no network connection while sync is disabled.

To see every screen and state with sample data, run `pnpm --dir web/app dev` and open `/gallery.html`; see [docs/interface.md](docs/interface.md).

To build the application and confirm that it launches:

```bash
pnpm tauri build --bundles app
SPL_SMOKE_TEST=1 target/release/bundle/macos/Scoplen.app/Contents/MacOS/scoplen
```

## Data and privacy

Scoplen keeps its local data in the application data directory (`~/Library/Application Support/com.scoplen.client` on macOS, `%APPDATA%\com.scoplen.client` on Windows). The store is a SQLCipher database encrypted with a random 256-bit key. That key is held in the macOS Keychain (only on this device, after the first unlock) or, on Windows, wrapped by a TPM-held key or by DPAPI for the current user. With a local passphrase, the key is additionally wrapped with a key derived from the passphrase by Argon2id; forgetting the passphrase makes the data unrecoverable. If the key is lost, Scoplen keeps the unreadable store under a new name and can start with empty data.

Network access follows explicit SSH actions, admitted-device authentication, and Personal
sync after explicit key verification. Authentication sends signed device proof only to the
profile origin. Its HTTPS transport verifies certificates,
rejects redirects, and bounds exchanges and response bodies. Device signing/KEM keys currently
use software implementations protected by SQLCipher; hardware device signing is not implemented.
Historical recovery keys and ceremony artifacts remain encrypted in SQLCipher. This build has no
recovery export or invitation/pairing controls. Access/refresh tokens and secret keys never cross IPC into the frontend.
After a successful sync bootstrap, Rust maintains a TLS 1.3/HTTP/2 notification connection and
synchronizes already adopted Personal objects in the background. Reopening locally verified
saved keys resumes it. Notification failure enables a 60-second polling fallback. New local
objects still require the exact preview and upload consent; neither account setup nor background
work adopts them. Store replacement and shutdown cancel owned work. Authentication or unsupported
rotation pauses transfer while local editing and SSH remain available. Settings shows safe
background status without starting network work. This build has no telemetry.

## Security

Report vulnerabilities privately to `scoplen-security@plystra.com`; see [SECURITY.md](SECURITY.md). Do not open public issues for vulnerabilities.

## License

The source code is licensed under the Apache License 2.0; see [LICENSE](LICENSE). Bundled fonts (Inter, Lora, JetBrains Mono, and the Noto Serif SC subset) are under the SIL Open Font License 1.1.
