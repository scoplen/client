# Scoplen client

> The Scoplen desktop client for macOS and Windows: an SSH client that connects to hosts directly or through a self-hosted Scoplen bastion.

Scoplen is a Plystra project. The full Plystra philosophy applies; this repository's review record is [PROJECT_PRINCIPLES.md](PROJECT_PRINCIPLES.md), which links to the project record in `scoplen-docs`.

Owner and operator: Plystra LLC. Responsible maintainer: Plystra LLC.

## Status

Maturity: Exploration. Maintenance: Active.

The application shell is in place: a Tauri 2 application for macOS and Windows, the Scoplen identity and design tokens, typed IPC generated from Rust with a binary channel transport, and a design system foundation with keyboard navigation, screen-reader labels, light and dark themes, increased-contrast and reduced-motion support, and ICU localization in English and Simplified Chinese. It keeps an encrypted local store: a SQLCipher database whose key is held in the macOS Keychain or, on Windows, by the TPM or DPAPI, optionally with a local passphrase. The desktop can manage local hosts, groups, tags, favorites, notes, and credentials. OpenSSH migration previews new and previously imported aliases alongside existing inventory, including their usable identity, route and ordinary known host keys. SSH connects directly, through a saved SOCKS5 or HTTP CONNECT proxy with optional username/password authentication, through an explicit saved Jump chain, or through a saved local ProxyCommand. Each SSH host uses its saved password, OpenSSH Ed25519, ECDSA P-256/P-384/P-521, or RSA software key, a generated platform-keystore P-256 device key, or an explicitly selected key in the system SSH agent, after independent host-key review. The target opens an interactive terminal with ANSI rendering, keyboard input, and close handling. Encrypted private keys prompt for a one-time passphrase after that host's review. New or changed keys require explicit acceptance; wildcard-only and CA records do not authorize raw host keys. Other credential kinds and sync follow the client track of [`scoplen-docs/17-implementation-roadmap.md`](../scoplen-docs/17-implementation-roadmap.md).

In Settings > Data > Import and export, choose Import OpenSSH config to select a
configuration and review Create, Update and
Unchanged rows before confirming. Literal aliases receive applicable global and wildcard
`Host` rules in source order, including lexically ordered `Include` files. Relative Includes
use `~/.ssh`; relative identity and known-host paths use the client's working directory.
Source files remain read-only. Available private OpenSSH keys become encrypted-store
Credentials; public identity files select that exact key in the system agent. Missing,
unusable or multiple identities require an explicit source-key or saved-Credential choice.
Create a saved password Credential first for password-only aliases. Confirmation requires
one usable identity for every included alias and commits the entire reviewed batch together.

Direct routes, `ProxyJump` chains of imported Direct aliases and literal-argument
`ProxyCommand` values map to existing Routes. Shell operators and expansion in ProxyCommand,
inline Jump user/port overrides, nested routes, `Match`, Include character classes and
other unrepresentable directives are reported with source locations; affected aliases are
skipped. Ordinary exact `known_hosts` entries bind to the evaluated address and port.
Hashed, wildcard, CA and revoked entries are reported; conflicting ordinary keys of one
algorithm and keys marked revoked do not become ordinary trusted keys.

Reimporting the same source preserves object identities and writes only reviewed changes.
For listed aliases, confirmation replaces source-owned fields and removes imported trust
no longer supplied by that source; manually added trust remains. Removing an entire alias
from the configuration does not delete its migrated inventory. Edits to reviewed files or
imported objects require a fresh preview. The constrained `PreferredAuthentications password`
or `publickey`, `IdentitiesOnly yes`, `IdentityAgent none` and literal `HostKeyAlias` forms emitted by export are
also understood. Password blocks require an explicit saved password Credential; key and
public Agent sidecars retain their ordinary import behavior.

In Settings > Data > Import and export, choose Export OpenSSH to review all Logins in the current Local or Personal profile,
including rows outside the active search or group filter. Compatible Direct and explicit
Direct-hop Jump Logins produce standard `config` and `known_hosts` files in a fresh
`scoplen-openssh-<timestamp>` child of the selected folder. Use `ssh -F <export>/config <alias>`.
Stable aliases and Host/Login comments identify each block. Existing files are never overwritten.

Password blocks ask for the password in external OpenSSH; saved passwords are never included.
Agent blocks include only the exact public identity in `identities/*.pub`; its private key
must already be available in the system agent. Software keys reference a verified existing
private-key file with the same public half as the actual saved key. Imported source files
are discovered automatically when still available; otherwise choose a matching file in the
review. External OpenSSH uses that file with its own passphrase and disables Agent substitution
for the source-key block. No private key is copied, and
generated or pasted keys without an external source remain excluded.

Each exported Host gets its own `HostKeyAlias`, preserving independent trust even when Hosts
share an address and port. Only ordinary host-specific keys accepted by the current trust
policy are written. A Host with no saved trust still requires OpenSSH first-use review.
Unsupported credentials, routes, options or saved trust semantics are reported per Login;
an excluded Jump hop also excludes its dependent target. Key paths or destination paths with
unrepresentable expansion syntax are refused. Inventory or selected source changes require
a fresh review. If a write fails, the newly created child is removed; if cleanup fails, the
dialog identifies the retained partial directory.

Settings > Data also provides Generate OpenSSH config for the current Local profile or
selected Account's Personal vault. Review the same authentication and compatibility report,
then generate a stable native-owned Include file. Copy the displayed Include line into your
own OpenSSH config manually; Scoplen never reads or edits that config for generation.
Every compatible Login retains its `scoplen-<Login UUID without hyphens>` alias. A complete
ASCII Host name matching `[A-Za-z0-9][A-Za-z0-9._-]*` also gets a lowercase friendly alias
when it is unique among all live Hosts in that namespace and outside the UUID alias namespace.
The friendly alias uses the Host's valid saved default Login, otherwise its first live Login
by UUID. An incompatible selected Login does not silently select another username. The
review explains every omitted friendly alias; Jump references always retain UUID aliases.

Generate and Regenerate are explicit operations: inventory edits do not update these files
automatically. A complete generation contains its own `config`, `known_hosts` and public
identity sidecars; its stable Include wrapper changes only after all files are written and
synced. Old complete generations remain available until Clear. Local and each Personal vault
have independent stable paths, and a reopened profile uses its original path. An empty or
fully excluded inventory can publish a generation with no Login blocks. Clear first publishes
a valid empty Include wrapper, then removes only that namespace's marked generations. It does
not change inventory, external private-key files, or the user's OpenSSH config. A stale review,
changed key source or target, or failed publication preserves the previous active generation;
failed cleanup identifies the retained directory. Generated configuration is an output and is
never read back into inventory. The separate `spl config generate`/`ssh-proxy` helper workflow
and the complete C10 migration gate remain in the roadmap.

The same Settings page provides Scoplen JSON/age import and export for Local inventory or
the selected Account's Personal vault. JSON exports omit passwords, software private keys
and secret Snippet defaults. Explicitly including secrets requires an export passphrase and
confirmation; the whole document is then encrypted as a standard age file. Generated and
pasted software keys can move this way without an external key file. Device-bound credentials
retain their descriptions and require setup on the destination device.

Import reviews creates, replacements, unchanged entries, missing references, omitted secrets
and required device setup before any inventory is saved. Each new imported host key requires
explicit consent to its complete calculated fingerprint, CA status and revocation state.
A new shared Credential with an omitted secret blocks the batch. An existing compatible
imported Credential can retain its secret only with an explicit choice; retaining an omitted
Snippet default is optional. Repair any blocked entry, then choose the file and review again.

Reimporting the same source object ids updates their previous targets even when the archive
file was moved or renamed. Removing an entry from the archive does not delete its old target.
Source or destination changes require a fresh review. Confirmation commits the complete
inventory, receipts and Personal sync changes together after full archive authentication;
decrypted contents never enter frontend reports or plaintext temporary files. Exports create
a new file and do not replace an existing one. Legal dangling-reference imports and native
picker/rendered acceptance remain separate C10 outcomes.

Settings > Data > Import team inventory adds new Hosts and default Logins to an
explicitly selected current team. Choose CSV or Direct OpenSSH, then select one
UTF-8 file up to 1 MiB. CSV uses the exact header
`name,address,port,username,login_name` and 1–100 data rows; a blank port means 22
and a blank Login name is omitted. Any invalid CSV row rejects the complete file.
The Direct OpenSSH profile accepts `Host`, `HostName`, explicit `User` and `Port`;
`Include` and `Match` reject the file, and other applicable options block their
candidates. It never reads related files or runs commands. The complete preview
shows Ready and Blocked candidates in source order, initially with no selection.
Select the Ready rows, review the team and every selected field, then choose
Import reviewed rows. This creates new pairs without merging existing assets;
credentials, routes, trust files and commands are not imported.

Before dispatch, the Rust core saves the original typed batch, ids and operation
key in SQLCipher. An uncertain result offers Confirm original import for the same
24-hour window, including after restart; reopening Settings never resends it.
Later denial does not erase an earlier uncertain result. Saved imports for teams
missing from current Membership discovery remain available for recovery only.
Confirmation records the original outcome; current availability still requires
ordinary member inventory refresh and acknowledgement. A failed refresh retains
confirmation and offers another explicit refresh. After the confirmation window
ends, explicitly refresh/review current inventory before archiving the unresolved
operation; a refused read is sufficient for review, but missing or similar assets
never establish the original outcome. Existing team access rules, default-Login
connections, CA setup, SSH and Files remain the connection workflow. Native picker
interaction, rendered desktop/mobile review and real deployment acceptance are
separate verification outcomes.

When adding a host, choose Key and Create a new key to generate an Ed25519 key
in the Rust core. The private key stays in the encrypted store; the host, Login
and shared-binding Credential are saved together. The new host opens in the
details panel, where Copy public key copies only its OpenSSH public key. Install
that public key in the remote user's `~/.ssh/authorized_keys` before connecting.
Creating the key does not connect to or change the remote host. A failed clipboard
write shows an error and can be retried without creating another key.

In Credentials, create a Device-bound key with This device only binding to generate
a P-256 key protected at rest by the platform keystore. Assign it to a Local or
Personal Login, then use Copy public key in the Host details to install its public
identity on the SSH server. The same saved key supports Direct and Jump terminal
connections, Files and reconnect after reopening the encrypted store. Each hop
still requires ordinary Host-key trust. SSH signing takes place in the Rust core;
the private scalar and keystore handle never enter the frontend or synchronized
objects. A missing local key is refused without choosing another credential.

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

To fetch an SSH password or software private key from an existing desktop helper, create an External
Credential with binding None and these provider entries, then explicitly assign
it to a Local or Personal Login:

```text
type=command
path=secret-helper read ssh-password
field=password
```

For an OpenSSH-format software key, use `field=private_key` and a command that
returns that key. Ed25519, ECDSA P-256/P-384/P-521 and RSA use the existing SSH
signers. Encrypted keys ask for a one-time passphrase after format, algorithm and
KDF checks. An incorrect passphrase retries local decryption on the same reviewed
SSH connection with the same fetched key; it does not run or confirm the helper
again. Fetching, passphrase entry and any additional factors share the original
five-minute authentication deadline.

The helper must already have access to its secret service. The descriptor contains
only references and nonsecret arguments. Each connection verifies that hop's Host
key, then asks you to approve the exact program and arguments before running it.
Jump Logins fetch independently. Reconnect requires fresh approval and output.
Plan resolution and Host-key probes never start a credential helper.

The command uses the quoting and backslash rules below, but percent, environment,
home, wildcard, pipeline and redirection characters stay literal. It inherits the
environment, receives no standard input, and discards standard error. Windows
helpers create no console window. Output is held only in zeroizing authentication
memory. The helper must exit successfully within 30 seconds and return credential material
of 1 to 16,384 bytes, optionally followed by one LF or CRLF; other bytes, including
spaces, are preserved. Failure does not select another credential or rerun the
helper. Fetched keys, their public identities and passphrases are not saved to
inventory or history. Organization certificates, proxy passwords and other provider
types are separate features. Native confirmation and editor interaction remain
unverified by the command-line acceptance suite.

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
Pageant discovery remains a later outcome.

Local and Personal Logins can opt into Agent forwarding after selecting an Agent
Credential with its exact public key. It is off by default. The target can ask that
one loaded identity to sign while the terminal is connected; enable it only for a
target you trust. Other loaded identities, key management and extensions are not
forwarded. Jump Login flags do not enable forwarding on the target, and Team
Logins cannot enable it. A refused forwarding request stops setup with an explicit
error before starting a shell. Saved changes apply on the next connection.

Forwarding runs alongside the terminal, SFTP and attached Local or Dynamic tunnels
on the same authenticated connection. Closing, reconnecting or switching Accounts
stops its channels and pending local Agent I/O. Each forwarded signature has a
ten-second deadline, with at most four Agent channels and four local signers active
across the application. A missing key, locked Agent, refusal or timeout fails that
request without selecting another identity.

Host-key review completes before querying or signing with the agent. A single
ten-second deadline covers local agent connection, identities, signing, and SSH
authentication, including partial reads. At most four agent authentication
workers run concurrently. Closing a pending connection cancels local agent I/O
and discards the authentication result; no shell is opened by the cancelled task.
Missing keys, locked or unavailable agents, signing refusal, and timeouts are
explicit failures. Agent RSA keys use the same SHA-2 selection policy as software keys.

The pinned shared SSH engine uses russh 0.65.0. Waiting for authentication with configured
keepalives no longer busy-polls, and an agent's signing refusal returns through the ordinary
authentication error path.

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

Choose Find in a terminal's header to search that pane's retained output, including
read-only output opened from Recent. Find matches exact, case-sensitive text. Use
Next or Enter to move forward, and Previous or Shift+Enter to move backward. Escape
or Close find clears the selection and returns focus to the same terminal. Windows
Ctrl+Shift+F and macOS Command+F open Find in the active pane; ordinary Ctrl+F remains
available to the remote application. Each pane retains its query across selection
changes until it closes or the Account changes. Search keeps the connection and
terminal grid intact; queries are transient and never sent to the remote host.

Use Snippets to save single-line commands with Text, Integer and Choice variables,
tags and an optional folder. From a connected terminal, choose a saved snippet, fill
its values once and select up to 64 already-connected terminals in the current Account.
Only the current pane is selected initially; tab and pane locations distinguish repeated
connections to the same Login. Review the complete command and ordered targets before
Send command or Send to selected terminals. Changing values or targets requires a new review.
Every selected terminal must be at the intended empty shell prompt. Sending adds one
Enter to each target in order. Sent to terminal confirms local input acceptance; inspect
each terminal for the remote result. Unavailable captured connections show Not sent;
uncertain invocations show Result unknown and require manual inspection. Switching
accounts or tabs, closing the dialog, or losing its originating connection stops later
sends. A selected connection is never redirected to its replacement. Input is never
automatically replayed.

Personal is the default Snippet library. From an Organization terminal, explicitly
choose its read-only Team library to use Snippets from that terminal's current team.
The complete Team view must be Ready with its matching ACK confirmed. Refresh team
assets explicitly if the view is unavailable; opening the library does not fetch it.
Team execution uses the same Text, Integer and Choice review and sends only to up to
64 existing ready terminals with the exact same deployment, Account, Device and
Organization. Changes to the originating connection or Team view clear values and
review and stop later sends. A target-only change shows Not sent for that target.
Team definitions cannot be added, edited, deleted or copied from this dialog; Secret
and unsupported definitions remain inspection-only with secret defaults hidden.

Use exact `{{name}}` placeholders with ASCII letters, digits and underscores, starting
with a letter or underscore. A repeated placeholder uses one value. `{{{{` and `}}}}`
produce literal double braces; ordinary Docker actions such as `{{.State.Status}}`
and `{{json .Config}}` remain literal. Variables are inserted once without automatic
shell quoting: write the intended quoting in the template and inspect the expanded
command. Integer values are canonical signed 64-bit decimal, without spaces, `+`,
leading zeros or `-0`; Choice values must match a saved option exactly. Empty Text
and explicit empty Choice values are supported. Commands and values cannot contain
line breaks or terminal control characters; the command plus Enter fits 64 KiB.
Retained Secret definitions are read-only and their defaults are hidden. Secret,
multiline, automatic connections and saved-Workspace execution remain incomplete.

Split right or Split below opens a fresh ordinary SSH terminal for the focused
pane's Login. Panes keep independent input, output and connection prompts. Select
a pane or use Previous pane and Next pane to move terminal input focus. A tab supports
eight panes and three split levels. Equal halves keep a 320 by 240 CSS-pixel minimum;
smaller windows scroll inside the workspace. Closing a pane checkpoints its output
before removing it; failed checkpoints retain the pane for retry or explicit discard.

Use Workspaces in the tab bar to save all terminal trees, each tab's focused pane,
tab order and selection, plus explicitly selected saved tunnels. Choose a Login for
each included tunnel. Save tunnel-only Workspaces from Hosts. Each definition contains
at most 64 terminal panes and tunnels combined, including at most 16 saved tunnels.
Each terminal also retains whether Files is open and its selected remote directory,
including inactive panes or a directory whose listing failed. Temporary runs are not captured.

Explicit Open validates the complete definition before appending fresh SSH terminals
and starting each saved tunnel through its ordinary preparation. It preserves existing
connections and shows each tunnel's accepted run or exact start refusal. Acceptance
may still require trust or authentication in Tunnels; another tunnel's refusal does
not stop accepted runs. Open uses the captured Login even if a saved default changes.
Saving includes failed or closed ordinary panes, but refuses the entire definition
if any pane contains saved output or unsupported team intent. Save creates a new local
object without starting connections; Personal adoption stays separate.

Loading or listing never connects. After ordinary Host trust and authentication, a restored
Files panel lists its exact saved directory on that terminal's new SSH connection. A missing
or denied directory stays selected with Try again, Home and Close files available. No shell
directory command is sent. Closed panels stay closed, and reconnect keeps its ordinary
closed-panel behavior. Output, commands, remote processes and transfer queues are not restored.
Earlier tab-only, split-only and version-three layouts and other unsupported
definitions remain byte-identical in Unavailable workspaces with explicit Delete.
Missing inventory dependencies require repair before opening. Divider dragging,
detached windows and native restart acceptance remain separate work.

Tunnels starts saved or temporary Local TCP, Remote TCP and Dynamic SOCKS forwards independently
of terminal tabs. In New tunnel, choose a Login and Start without saving for a one-off run,
or use Save changes to retain a definition without starting it. Save keeps its optional default
Login. Temporary definitions are never added to inventory or synchronized; explicit host-key
acceptance retains the normal trust behavior. Local and Dynamic use a numeric local IPv4
or IPv6 address and a nonzero local port. Local also needs a destination hostname or address
and nonzero destination port; Dynamic takes each destination from SOCKS4/4a or SOCKS5 CONNECT. New definitions
use `127.0.0.1`. Dynamic provides no SOCKS authentication: devices able to reach its
listener can request destinations through the selected SSH connection. Review that
access before choosing a non-loopback listening address. Choose Start and an existing
Login, then complete its ordinary host-key, key-passphrase or Interactive review.
The tunnel opens no terminal or shell. The SSH server resolves destination hostnames.

Running tunnels show their fixed configuration, connection count and traffic.
Leaving Tunnels keeps them running; editing or deleting a saved definition does
not change an existing run. Saving an equivalent definition does not convert a temporary run.
For an independent run, Stop closes its listener, peers and SSH route. At most 16 tunnels and 32 peers per tunnel
run at once, including SOCKS negotiation and
channel opening. Dynamic negotiation has an absolute 15-second deadline; channel
opening and the final SOCKS response each have their own 15-second deadline. Traffic
counts include only application bytes successfully written, excluding SOCKS messages.
A failed independent run requires an explicit new Start; independent tunnels do not reconnect
automatically. Temporary runs end on Stop, SSH loss, profile replacement or application exit,
and are not restored after restart. Saved tunnels can be explicitly selected in a Workspace;
Unix-socket forwarding remains incomplete.

A Local or Personal Login's selected saved Local TCP and Dynamic SOCKS tunnels also start
with its terminal, sharing that target's authenticated SSH connection and Jump route with
the shell and SFTP. A Forward's default Login and a Jump-hop Login's own attachments do not
change this selection. Per-entry failures leave the terminal and other tunnels usable.
Attached runs identify their terminal; Stop releases only that tunnel's listener and peers.
It stays stopped across reconnects of the same tab; closing the tab discards that choice.
Reconnect releases old resources before starting eligible current definitions. Independently
running tunnels retain their own lifetime. Attached Remote and Unix-socket forwarding remain
unsupported. Direct and Jump routes use the existing bounded automatic reconnect after
confirmed network loss, including a lost Jump parent. A replacement transport recreates
eligible attached runs while preserving explicit Stop. Native Windows/macOS interaction
remains unverified.

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

Edit locally creates a working copy of one complete UTF-8 file up to 256 KiB at a location
you choose, then opens the platform text editor. This is an ordinary local file outside
Scoplen's encrypted storage. Files detects saved changes without uploading them. Choose
Upload changes to queue a write to the original remote path, then confirm replacement;
a different local filename does not change that target. Normal transfer progress,
cancellation, source checks and uncertain-result reminders still apply. An unknown upload
requires reviewing the remote file before another explicit attempt. One working copy is
active per terminal. Hiding Files keeps observation running; Stop editing, disconnecting
or closing the session never deletes your local copy or closes the external editor.
A replacement connection does not inherit upload authority. Native editor and picker
interaction on each platform remain separate acceptance.

Choose Compare folder files in the Files toolbar to compare the current remote directory
with an existing local folder. Choose upload or download, select the local folder, then
review Create, Changed and Same before Apply. This first profile processes at most sixteen
ordinary source files directly in that folder; the preview reports excluded subfolders.
Content-identical files are skipped, and target-only files stay unchanged.
Download names must be valid UTF-8; potentially equivalent native names refuse the entire
comparison without renaming files, including on a case-sensitive destination. Equal-size
contents use complete streaming comparison, with a 64 MiB per-file hash limit, 256 MiB total
read budget and a 120-second comparison deadline after folder selection. Comparison writes
nothing. Apply requires capacity for the entire changed batch, then each transfer uses the
normal confirmation, cancellation and result rules. Files finish separately. A changed
preview requires comparison again; an uncertain Apply requires reviewing the transfer queue.
Local files remain outside encrypted application storage. Native folder-picker and rendered
Windows/macOS interaction remain separate acceptance.

Upload folder copies a native-selected source folder into a new root in the current remote
directory. A remote folder's Download folder action selects a native destination parent.
Review the source, destination parent and editable new root name before adding one queue
item for the complete tree. The prepared selection reserves one slot and expires after five
minutes; an invalid root name can be corrected within that same review. An admitted selection
cannot be used again. The destination root must not already exist: copies never merge with
or replace an existing directory.

The complete source is scanned before creating the root, with limits of 10,000 entries
including the root, depth 32, 16 MiB retained metadata and 300 seconds of enumeration.
Links, reparse points, special entries, incomplete listings and invalid or colliding names
refuse the copy before creation. Download names use the same UTF-8 and conservative native
equivalence rules as folder comparison, across both files and directories. Complete directory
enumeration supports flat sources beyond the Files browser's 1,024-entry display limit.

Copies preserve ordinary file contents and directory structure, including empty files and
folders. They do not preserve metadata or provide a source snapshot. The queue shows scanning,
copying and finalizing, total bytes and entries, confirmed completed entries and whether the
new root was created. Cancel is unavailable during a dispatched mkdir or file publication
and becomes available again between confirmed steps. Failure or cancellation preserves
completed files and directories and cleans up only the current owned staging file. An unknown
mkdir or publication result requires manual review and is never retried automatically.
Folder copies have no Pause/Resume or process recovery. Native picker and rendered platform
interaction remain separate acceptance.

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
sync keys. From Local, Create account prepares a new independent Account, exports its recovery key
through a native Save dialog, requires explicit safe-storage confirmation, and offers Submit,
exact-result Confirm, and explicit Retry according to the durable operation state. Sign in verifies
an existing account password and prepares a new independent Device; Admit this device explicitly
submits that original admission before profile installation. It never creates a replacement Account,
reuses another Device, or overwrites an existing local Account profile. Invitation enrollment,
invitation replacement, and device pairing have been retired.
An unfinished old setup is preserved and cannot resume its retired entry protocol.

In an installed Account, Settings -> Personal account -> Change account password
verifies the current password, saves one encrypted replacement, then requires an
explicit Change password action. Equivalent normalized passwords are rejected
locally before network access or password derivation. Changing the password signs
out browser sessions; native Devices, the Account, Personal vault and recovery key
remain unchanged. Password inputs are cleared immediately after invoking Rust.
Closing Settings or restarting retains an unresolved operation. An unknown result
offers only Check this change, even when the device needs to sign in again.
An unsubmitted change can be cancelled. Only an attempt that the server confirms
did not change the password permits Retry this change; that attempt can also be cancelled.
Choose Done after success. If the password was changed again later, use the most
recent password.

The disposable SQLite and PostgreSQL password-change acceptance uses this public Rust
workflow with a Personal Host uploaded before the change, continued synchronization on
both original Devices, and the same Host decrypted by a third Device admitted with the
new password. See [the development guide](docs/development.md#existing-device-password-change).

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
The desktop exposes these APIs through generated native IPC. After confirmation, Install account
profile verifies current Device authority and K-4 before opening the Account. The header selects
Local or any ready Account. Switching closes SSH sessions, transfers and tunnels; a bounded drain
asks the person to finish a native file dialog when necessary. Each view and invocation retains
its original profile generation, and delayed events cannot refresh another Account. Closing the
account view or Stop retains pending/unknown work; restart resumes local status without submitting
automatically. Existing retained-account databases remain accessible under their original identity.
Sign-in also resumes unknown admission with exact Confirm only. Known unchanged or never-sent
expired admission can be safely cancelled before fresh password entry. An existing catalog Account
directs the person to its saved profile; re-entry after that Device is revoked remains incomplete.
Team context switching and native provider/picker acceptance on macOS remain incomplete.

Profiles with saved neutral admission anchors continue to verify offline against their original
private roots. Profiles without those anchors require explicit current-device revalidation;
historical session flags, cached bootstrap responses and archived entry payloads cannot grant
admission. The client no longer reads or decodes archived invitation or pairing payloads, and
preserves the original database bytes. The admitted profile binds its canonical origin, Account,
Personal vault, device, and keys immutably to this encrypted store. Existing local SSH data stays local.
Team context switching remains incomplete.

In Settings > Personal account, Teams offers explicit Refresh teams and Create team actions
through the selected deployment. Opening Settings only reads the retained creation locally;
Load more teams requests the next page. Rust validates complete shared Resources and pages, including
their Account binding, continuation and HTTP metadata. Role identifiers are display values;
the server checks current membership for each request. Creation retains one original request
and operation id in SQLCipher before dispatch. An uncertain result survives restart and permits
only an explicit retry of that request within its original 24-hour window. After expiry, refresh
discovery before explicitly clearing the reminder and deciding whether another creation is needed.
Creating a team preserves the Account's Personal vault, Device keys and existing Personal sync.
Edit reads that team's current name and exact version before offering Save team name. Saving
sends one conditional update and replaces only the verified team's displayed metadata. A stale
or uncertain result requires explicit Refresh team settings and review before another Save;
the client never automatically retries the edit. Closing the editor or changing Account ignores
late results. Name editing needs the session's organization write scope, while discovery and
Personal use remain available without it.
Join team accepts a public invitation link and its separate eight-character password. Rust
checks the signed-in Account's exact deployment and recipient-authorized preview before
acceptance. Administrators invite an existing username with built-in roles, inspect or revoke
invitations, and update, suspend or remove members through Invitations and members. Active members
can leave; Owners can explicitly dissolve a team after reviewing its current version.
Invitation, acceptance and dissolution retain their original protected request and operation
key before dispatch. Explicit confirmation uses that same request within its 24-hour window;
dissolution also keeps its original validator. A historical receipt does not establish current
team access. Expired uncertainty can be archived only after an explicit current-status review.
The separate invitation password stays in the encrypted Account-local operation. Reveal fills
only an explicit transient uncontrolled field; Copy password writes directly from Rust to the
native clipboard. No WebView clipboard permission is granted. Dismissing the confirmed operation
erases the local password; a lost password requires revoking and replacing the invitation.
Conditional member changes, invitation revocation and Leave team never replay automatically.
Conflict or unknown outcome requires an explicit refresh and review. Personal data and other
teams remain independent; installed host trust needs separate removal after dissolution.

Each team offers View assets. It fetches the complete currently permitted inventory before
showing any rows, labels the selected team and server, and distinguishes an empty inventory
from lost membership or a failed refresh. Rust stores that projection separately from Personal
objects, withdraws assets absent from the next complete view, and refreshes viewed teams in
the background at least every 60 seconds. Permission and membership notifications trigger a
fresh complete read. Reopening an Account requires online revalidation before showing saved
team rows. Refresh assets retries explicitly; an unconfirmed server acknowledgement keeps
the complete local projection and shows its unconfirmed state.
Viewing team assets does not switch the active Personal inventory or grant Connect permission.
Older saved sessions need fresh Device authentication to obtain the team scopes; refresh never
expands an existing family's permission ceiling.

Manage assets opens named forms for the team's Hosts, Logins, Host groups, Routes, host trust,
Snippets and gateway networks. These are server-readable Organization resources. Referenced
assets require their own read permission; an unavailable reference stays an opaque identifier.
Team Logins use their independent device-local certificate signer. They never select a Personal
credential. A create is saved in the encrypted store before its original request is sent.
An uncertain result offers Confirm original request, and no replacement creation can begin for
that team until the retained request is resolved. Editing and deleting first reads the actual
resource and uses its captured version. A conflict or uncertain change requires Refresh and review.

Access rules manages local member groups and policies. Group members are current team memberships;
identity-provider groups are read-only. Create access rule selects one member or local group and
May view assets, May connect or May request access. Connecting names an exact SSH username and
selected Hosts or Host groups. Request permission selects individual Hosts only; it does not
grant visibility, connection or approval permission. Preview uses the shared Cedar generator
and never grants dependent assets automatically. Advanced Cedar policy offers the supported
single-policy source editor.

After a verified team connection-policy refusal, Review access opens the original Host and
exact SSH username. Enter a duration of 1 to 86,400 seconds and a reason, then choose Check
request. Only a permitted check for those exact details offers Request access. Editing the
input or changing the session/team discards that check. Other connection failures do not
offer this form, and the server rechecks current eligibility when the application is sent.

Settings -> Personal account -> Teams -> Access requests provides My requests and the current
Approvals inbox. Both refresh when opened, every minute while open, after a confirmed action,
and through Refresh and review. Review shows the original requester, membership, Host ID,
username, duration, reason and pending deadline before separate Approve, Deny or Cancel
actions. An independent authorized teammate must approve; pending requests expire after
24 hours. This first profile requests one Host and one exact username, with one approval.

Approval records the original finite Grant interval; it is not proof of current access.
Reviewing an approved request offers a separate Connect using a currently visible Login
matching that exact Host and username. It opens an independent ordinary terminal with current
certificate acquisition and Host-key review, without automatically connecting or selecting a
different target. A missing matching Login explains how to refresh team assets.

Rust retains each original request/action and its recovery state in the encrypted local store.
An uncertain result offers only explicit Confirm original result with the original payload,
identity and precondition. No refresh automatically repeats a mutation. After the confirmation
window expires, explicitly refresh and review current requests before archiving uncertainty;
archiving does not undo a completed action. Stale reviews require a fresh read. Unknown future
request statuses remain visible without actions. Native desktop interaction and independent
request-to-SSH deployment acceptance are recorded separately in the roadmap.

SSH CA setup shows the team's authenticated public user CA and retained setup/certificate requests.
An administrator can explicitly create the CA. Select a visible Login to inspect its exact Host,
local SSH user, scoped principal, CA file and principals file. Install the shown public CA and
principal mapping manually, review the displayed sshd settings, and validate with `sshd -t` before
reloading sshd. The client never changes remote configuration. An unknown request can only be
confirmed with its original identity; confirming an old certificate does not renew it or connect.
An authenticated, validated revoked-certificate or issuance-limit refusal clears only that
original pending certificate request. The terminal and SSH setup show guidance in the selected
language: review current access after revocation, or wait for certificate expiry after a full
issuance limit, then explicitly start a new connection. Uncertain results retain their original
request and key; the client never silently replaces them.

Connect on a visible team Login carries its exact deployment, Account, Organization and Device
through Direct, Jump, credential-free proxy or explicitly reviewed local Command preparation.
Each Command shows its expanded program and every argument for approval before starting a local
helper. Host-key review precedes certificate issuance and SSH authentication. A successful team
session uses the ordinary terminal and Files/SFTP, including duplicate, split and reconnect.
Recent and saved output preserve the same team source. Team terminals cannot be saved in a
Personal Workspace, and the standalone Tunnels Login selector is not yet connected to teams.
An eligible unexpired certificate can survive a control-plane outage until that team's authority
is invalidated locally. Observed membership loss cancels that team's preparation and withdraws
its certificate cache; an established unmanaged SSH connection is not forcibly terminated.
Client-core team inventory and certificate-authenticated SSH/SFTP pass against fresh SQLite and
PostgreSQL HTTPS deployments. Native Windows/macOS desktop interaction for these workflows
remains unverified.

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

Settings > Terminal manages device-local named profiles for font, cursor and scrollback,
with an editable/resettable Default. Choose a profile in a Personal or Organization Login;
only the target Login affects its pane. Missing names use Default with a visible hint.
Saving applies to current live, hidden and saved-output panes without reconnecting.
These settings remain in the current Local or Account Store, do not synchronize and leave
the existing global colors unchanged. Per-profile colors, ligatures, bell and native
rendered acceptance remain separate roadmap outcomes.

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

The opt-in `live-server-integration` test
`personal_server::live_server::password_entry::team_inventory_import::live_native_team_inventory_import_ssh_and_sftp`
accepts the same private `SCOPLEN_LIVE_ACCOUNT_DEPLOYMENT` and
`SCOPLEN_LIVE_TEAM_SSH_FIXTURE` descriptor paths as the existing team SSH fixture.
It registers fresh Accounts, imports CSV and OpenSSH through the public native
facade, verifies the original default-Login pairs without repair, checks hidden,
authorized and withdrawn member views/ACK, and exercises real SSH and binary SFTP.
An opt-in test-only transport control discards one fully received and verified
production 201 per source, then closes and reopens the Account profile before
confirming its original key/body. This verifies recovery after a client-side
reply discard, not a real network outage. Ordinary production builds contain
neither the control nor its state.
Use only disposable HTTPS deployments and owned OpenSSH fixtures. This public-core
integration does not establish rendered or native interaction acceptance.

The opt-in `live-server-integration` test
`personal_server::live_server::password_entry::team_snippets::live_native_current_team_snippets`
keeps one native process and existing real Team SSH terminals across externally
authored publication, replacement, view withdrawal, restoration, membership removal
and deletion. Set `SCOPLEN_LIVE_TEAM_SNIPPET_DIRECTORY` to a private disposable
handoff directory and `SCOPLEN_LIVE_TEAM_SSH_FIXTURE` to the owned OpenSSH descriptor.
Each bounded `snippet-client-{phase}.json` and its closed `.ready` file provide
ordinary fields and a password-file path; no credential belongs in command output.
The consumer publishes `snippet-native-{phase}.json` with descriptor/command hashes,
source/view fences and per-target local outcomes plus exact executed output-line
counts. The controller checks it before publishing the phase's `.complete` file
containing `passed` and one newline. Old preparations remain in the same process
and must be refused after reconciliation; a replaced target receives no replay.
This public-core fixture does not establish rendered or native interaction acceptance.

`scripts/test-ssh-command-password.ps1` uses PowerShell 7 and Docker for real
Direct and Jump password authentication, exact literal helper arguments, optional
line endings and preserved password whitespace. It checks trust and command refusal,
malformed descriptors, failed/empty/excess output, timeout, cancellation and abandoned
preparation. Independent helper leases and SSH relays verify cleanup. SessionManager
journeys retain binary SFTP and require fresh approval and fetching after reconnect;
Stop and store replacement release pending helpers. Successful runs remove their
owned container and temporary files. Native confirmation and macOS process behavior
require separate platform acceptance.

`scripts/test-ssh-command-private-key.ps1` exercises the same command runner with
OpenSSH-generated Ed25519, ECDSA P-256/P-384/P-521 and RSA keys. It verifies encrypted
key retry on one retained connection, independent Jump keys, binary command/SFTP,
fresh approval and fetching after reconnect, and passphrase cancellation. Malformed,
unsupported and excessive-KDF output fails before a secret prompt or signing.
The shared helper leases, trust/command refusal and bounded-output failure controls
also run for private-key output. Native interaction and macOS process acceptance
remain separate.

`scripts/test-ssh-keyboard-interactive.ps1` uses PowerShell 7 and Docker to start
disposable OpenSSH 9.9/PAM listeners with exact package versions. Through public
saved client preparation it checks explicit Interactive, accepted password/key/agent
continuation, wrong-answer/key refusal, fresh successful attempts, cancellation
and late replies, another terminal while one challenge waits, and Interactive
Jump plus target authentication. Every successful connection must execute the
exact expected command with exit status zero. The fixture cleans up its own
containers and temporary keys.

`scripts/test-ssh-snippet.ps1` uses PowerShell 7 and Docker to save and prepare a
snippet in a real encrypted Store, fill all three supported variable kinds and send
the exact preview plus Enter through the public session manager to disposable
OpenSSH. It verifies the executed output marker once and rejects old transport input
after the shell exits. Independent same-Login sessions also receive one exact marker
each; a captured stale transport is refused without replaying input to its replacement,
while surviving peers remain usable. This verifies the public Rust session boundary;
cross-tab selection and per-target interface results have separate frontend tests and
rendered/native acceptance. Successful checks remove their owned fixture; failed
checks stop their owned container and retain temporary evidence.

`scripts/test-ssh-workspace.ps1` connects two independent ordinary terminals to an
owned OpenSSH fixture, checks separate marker output, resize and close while the
other pane stays usable, then reopens a mixed Workspace after SQLCipher reopen.
Fresh terminals replay no commands. Explicit saved Local, Remote and Dynamic starts
use ordinary Jump trust/authentication, binary traffic, counters and complete Stop.
Duplicate refusals preserve the other accepted tunnels and pre-existing ordinary
terminal and temporary run. Listing and core Open return intent without starting
connections. Native pane focus and rendering need separate platform acceptance.

`scripts/test-ssh-attached-forwards.ps1` uses public `run_target` with owned Direct and Jump
OpenSSH peers. It checks shared shell/SFTP/Local/SOCKS binary traffic, per-entry failures,
both Stop paths, Direct and Jump parent-loss reconnect and independent-run survival. Target
and Jump logs prove one authentication per owned transport, including fresh reconnects.

`scripts/test-ssh-local-forward.ps1` checks saved and temporary standalone TCP tunnels against
disposable OpenSSH listeners with session channels disabled. It exercises password,
encrypted-key, Interactive and Jump preparation, concurrent binary streams, half-close,
exact traffic counts, refusal, cancellation and SSH loss while another terminal stays
usable. It requires PowerShell 7, Docker and `ssh-keygen`. Successful runs remove their
owned resources; failed runs retain private diagnostics and stop their owned container.
Temporary Direct and Jump runs verify that traffic and Stop do not create a saved definition.

`scripts/test-ssh-dynamic-forward.ps1` checks saved and temporary SOCKS4a/5 tunnels through Direct
and Jump routes against disposable OpenSSH listeners with session channels disabled.
It verifies literal destination names and server-side resolution, concurrent binary
streams with coalesced application bytes, half-close, application-only counters,
refusals, the absolute handshake deadline and cleanup during negotiation, channel
opening and copying. Saved edits/deletion leave the running configuration fixed;
temporary Direct and Jump runs leave saved inventory unchanged, and an independent terminal
remains usable. It uses the same prerequisites and fixture
retention rules as the Local check.

`scripts/test-ssh-remote-forward.ps1` checks saved and temporary Remote TCP tunnels with fixed local
targets and no SSH session channels. It verifies Direct, encrypted-key, Interactive and
Jump preparation, concurrent binary peers, both half-close directions, exact counters,
local refusal/recovery, occupied and denied listeners, requested versus actual
`GatewayPorts` scope, Stop, SSH loss and complete route cleanup while a separate terminal
stays usable. Temporary Direct and Jump runs retain only their runtime identity and leave
saved inventory unchanged. It uses the same prerequisites and fixture retention rules as the Local check.

With PowerShell 7, Docker, and `ssh-keygen` available, `scripts/test-ssh-private-key.ps1`
starts disposable OpenSSH servers and verifies Ed25519, P-256/P-384/P-521, and RSA key
authentication, encrypted-key passphrases, constrained RSA-SHA2-256/512
selection, SHA-1-only refusal, wrong-key rejection, invalid-key errors, and
fail-closed host-key trust.
It also generates an Ed25519 key through Add Host, installs only its returned
public key, then reopens the encrypted store in another process and authenticates
through the saved Login's ordinary connection plan.
It removes its containers and temporary keys when finished.
CI runs this fixture on Linux in addition to the macOS and Windows Rust checks.

On Windows or macOS with PowerShell 7, Docker and `ssh-keygen`, run
`scripts/test-ssh-device-key.ps1` for platform-keystore device Credentials. It creates
keys through the public inventory API, installs only their public identities on
independent OpenSSH target and Jump listeners, and reopens the saved inventory in
separate processes. It checks interactive shell output, binary SFTP upload/download,
manual reconnect, refused Host trust, unauthorized-key rejection and a missing
platform slot. Successful runs remove their owned containers, files and keystore
slots; a failed run retains its local diagnostic fixture. Platform-protected
storage and public-core interoperability do not establish hardware signing or
rendered desktop acceptance.

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
`scripts/test-ssh-agent-forwarding.ps1` uses an isolated source with two loaded keys
and two real OpenSSH listeners. Through the public SessionManager it checks default
off, exact saved-key forwarding, second-hop SSH, simultaneous binary SFTP and Local
and Dynamic tunnels, forbidden requests, source refusal recovery, saved-edit and
reconnect behavior, and cancellation of a held source signature.
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

Network access follows explicit SSH actions, Account registration/sign-in, admitted-device
authentication, and Personal sync after explicit key verification. Rust derives the password
verifier locally and sends it only to the chosen server over verified HTTPS. Account-entry
passwords are transient; retained pending operation material stays encrypted in SQLCipher.
Device authentication sends signed proof only to the profile origin. HTTPS rejects redirects
and bounds exchanges and response bodies. Device signing/KEM keys currently use software
implementations protected by SQLCipher; hardware device signing is not implemented.
Registration exports its recovery key as a plaintext file through the native Save dialog and
requires a separate safe-storage confirmation. Keep that file private and offline. Retained
recovery keys and ceremony artifacts remain encrypted in SQLCipher. Personal invitation/pairing controls
are retired. Access/refresh tokens and secret keys never cross IPC into the frontend.
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
