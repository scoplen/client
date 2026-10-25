# Changelog

All notable changes to the Scoplen desktop client are recorded here.

## Unreleased

- Added explicit retained-device revalidation in Personal account settings. Original device,
  ARK and private Account keys anchor ordinary signed authentication and complete K-4 checks;
  temporary credentials, neutral provenance and bootstrap install atomically in the captured
  profile generation. Known certificates, revocations, revision and epoch evidence survive.
  Failed verification preserves the original data without enabling sync or uploads. Retired
  entry protocols and pending D-128 receipt confirmation remain separate.

- Retired Personal invitation enrollment, invitation replacement, and device pairing from
  the desktop UI, IPC and network paths. Confirmed historical profiles convert offline to
  verified, immutable account provenance; unfinished or invalid setups retain their data
  without gaining access. Existing admitted devices can still authenticate and synchronize.
  Live checks now require disposable, already confirmed profiles. Registration, password
  sign-in and full multi-profile switching remain incomplete.

- Added saved Dynamic SOCKS4/4a/5 CONNECT tunnels alongside Local TCP tunnels, with
  explicit Login and numeric bind selection, remote hostname resolution, fixed
  running configuration and application-only traffic counts. Negotiation, channel
  opening and copying share bounded peer capacity; an absolute handshake deadline
  prevents fragmented input from renewing negotiation. The editor and running view
  explain the unauthenticated proxy's access, and Dynamic saves clear fixed targets.
  Stop, SSH loss, store replacement and exit use the existing forwarding lifecycle.
  Local and Dynamic share run limits; Remote, Unix-socket and ad-hoc modes remain open.

- Added saved local TCP tunnels with explicit Login selection and independent
  Start/Stop, host-key and authentication preparation, fixed running configuration,
  bounded concurrent peers, half-close and traffic snapshots. Tunnels keep running
  across view changes and release their listener and SSH route on Stop, application
  exit or local-store replacement. Failed runs require a new Start. Automatic startup
  remains incomplete.

- Added an opt-in Personal process-restart integration check using two real consumer processes,
  the platform secret provider and one owned encrypted data directory. It waits for the genuine
  access lifetime, refreshes directly after restart, verifies retained identity and refresh-family
  bounds, and synchronizes a durable offline Host edit with signed history and acknowledged
  progress. Desktop-window and platform acceptance remain separate checks.

- Fixed Windows keystore deletion to check the exact current-user native slot before removing
  its protected file. An unavailable native probe permits software cleanup only when Windows
  independently confirms no compatible TPM and the file is valid DPAPI or absent. An opened
  native key's deletion failure, a present but unavailable TPM, other provider failures and
  unverified files remain errors with the file retained. Repeated deletion remains safe after
  confirmed absence.

- Fixed terminal menu paste to honor bracketed-paste mode and normalize line endings.
  Pending clipboard reads cannot enter a replacement connection or offline view. Paste
  now waits for its bounded primary input write and reports failures without duplicate errors.
  Broadcast target or mode changes invalidate pending paste reads and secondary copies,
  preventing old input and errors from reaching newly selected targets.

- Added saved Interactive (OTP/PAM) Logins for targets and Direct Jump hops without
  stored answers. Accepted password/key/agent factors may continue into Interactive;
  ordinary rejection never falls back. Per-hop authentication and per-request reply
  deadlines, ordered echo-aware inputs, and attempt-bound one-use replies fence stale
  answers across cancellation and reconnect. Credential kind 8 is a breaking pre-Stable
  registry extension and requires updated clients.

- Added upload pause and explicit continuation on the same live SSH transport. Private staging
  keeps exclusive write creation and admits a separate read handle before enabling Pause;
  an associated read refusal preserves ordinary upload. Pausing settles a bounded segment
  and verifies both confirmed prefixes. Resume keeps the original handles, checks source,
  staging and destination, and joins the FIFO tail with a new execution. Changed files refuse
  continuation; uncertain publication remains Unknown. SFTP attributes and hashes do not
  establish immutable files or inode identity. Cross-transport and durable recovery remain open.

- Added bounded native multi-file drop upload to the visible Files directory list. Rust
  retains one window/context-bound 30-second ticket, reserves capacity for the whole batch,
  rejects invalid sources or duplicate names together, and appends accepted files in order
  through the existing transfer queue. Product drag events contain no native paths. Stale
  views and changed geometry refuse pending drops. Native scaled-platform acceptance remains
  unverified.

- Added explicit read-only preview for complete ordinary UTF-8 files up to 256 KiB in Files.
  Rust checks metadata and EOF over the current SSH transport; typed refusals guide larger or
  non-text files to Download. The English/Chinese dialog keeps literal text transient, supports
  cancellation and retry, restores keyboard focus and discards content across connection or
  tab changes. It starts no editor, local write, remote write or synchronization.
  Long dialog titles and descriptions wrap within scrollable content, keeping closing
  controls visible in narrow windows.

- Added download pause and explicit continuation on the same live SSH transport. Pausing settles
  the current bounded segment before retaining the original remote handle and local partial;
  the paused item retains capacity while later queued work can run. Resume verifies both
  confirmed prefixes and the destination, then continues from that offset under a fresh FIFO
  execution. Partial cleanup and publication check native file identity. Cross-transport
  continuation and recovery after session/process closure remain incomplete.

- Added a bounded per-terminal upload/download queue that keeps running while Files is hidden.
  Typed snapshots show contiguous byte progress, finalizing, conflicts, cancellation and known
  results. Unknown saves retain a reminder until explicitly acknowledged, without retrying or
  claiming success. Reconnection retains results but never replays old transfers. Native
  replacement review identifies the bound host, login and selected filename. Closing the
  logical tab releases pending work and settles a local save already in progress. Recovery
  after closing the tab remains separate work.

- Added terminal-owned SFTP create-directory, rename, and delete actions in connected Files.
  Rust accepts only one direct child with its original remote filename bytes, checks ordinary
  file or directory type and destination absence before dispatch, and requires native deletion
  confirmation. Deletion uses file removal or empty-directory removal; rename never requests
  replacement. A lost reply is reported as unknown for manual inspection, without auto-retry.
  The disposable OpenSSH fixture covers successful changes, collisions, declined deletion,
  nonempty directory refusal, symbolic-link refusal, and a responsive terminal.

- Added terminal-owned, single-file SFTP upload through the authenticated SSH connection.
  Rust selects and holds a regular local source, reviews existing remote targets in a native
  confirmation, writes a private exclusive staging file, and publishes only after transfer and
  target recheck. Existing files require OpenSSH atomic replacement support; refusals and
  changed targets leave them untouched. Cancellation cleans confirmed staging when possible,
  while a lost publication acknowledgement reports an unknown result for manual inspection.
  The OpenSSH fixture exercises save, declined and confirmed replacement, in-flight cancellation,
  staging cleanup, and a still-responsive terminal.

- Added transient pairing QR display and an explicit native PNG screenshot picker. Rust
  bounds local decoding, accepts exactly one canonical QRv2, checks the selected account's
  origin before claiming, and verifies the authenticated device-key digest before approval.
  Images and QR text never enter IPC or network requests. QR modules and passwords clear
  with the foreground view; failed rendering preserves manual link/password pairing.

- Added Personal account settings for creating a public pairing link, entering its separate
  password on an existing device, explicitly approving authenticated device claims and
  recovering saved admission. Dedicated native commands keep cryptography and progress in Rust;
  only the one-time password display crosses the transient boundary. Local checkpoint reloads,
  retained setup metadata and registered observer lifetimes keep failure, cancellation and
  navigation paths recoverable. English/Chinese copy and generated bindings/fonts are included.

- Fixed first-session pairing failures trapping a mistyped server address or device name.
  Before any valid session checkpoint exists, an explicit correction preserves the durable
  device keys and creation time. Atomic metadata and checkpoint guards reject competing edits;
  a saved session retains its original binding.

- Extended the opt-in disposable HTTPS integration scenario to pair an independent second
  device with explicit approval and real native authentication/K-4 verification, query both
  signed device lists, synchronize encrypted hosts and edits in both directions, and reopen
  both encrypted stores offline. Account setup leaves pre-existing local inventory unshared.

- Added Rust-owned second-device pairing using a public locator and separate transient
  eight-character password. CPace, confirmation, authenticated device review, seven immutable
  relay slots, conservative deadlines and minimum poll spacing run in the core. Durable
  one-attempt records prevent restarting an old session after switching to another one.
  Exact handoff plans and acceptance/approval bytes are saved before transmission; restarted
  devices recover through receipts and retained-device authentication without changing keys.
  Paired identities have their own authenticated provenance, no fabricated enrollment or
  recovery key, and must finish D-100 authentication and K-4 verification before completion.
  Account queries and explicit inventory sync support that provenance and all retained Personal
  epochs. First-response floors, equal-revision projection checks, strict response bounds/cache
  headers and membership-only key invariants fail closed. Desktop QR workflows remain incomplete.

- Allowed the retained first device to synchronize after membership-only account-key
  revision advances, including skipped revisions and a randomized wrap of the same ARK.
  Account roots, private keys, account ciphertexts, recovery material, Personal epoch-1
  wrapping and this device's exact signed certificate stay pinned. The encrypted snapshot
  rejects revision rollback and changed key projections at the same revision across restarts;
  independently signed device statements remain refreshable. Competing operations retain
  the newer snapshot. Key rotation remains separate work.

- Fixed successful native refresh being rejected when independently sampled JWT issuance
  and remaining whole seconds cross a clock boundary. Positive returned lifetimes schedule
  conservatively without extending the retained family deadline, including overflowing sums.

- Added an explicit opt-in Personal integration check against a disposable HTTPS server,
  covering public enrollment, retained-device authentication, encrypted inventory round trips,
  durable acknowledgements, encrypted-store reopen and offline original-copy restoration.
  It also exercises real native session rotation before sync and after reopening the store,
  retaining the refresh-family deadline ceiling. Explicit real account/device queries verify
  the retained account and current signed device, with offline snapshot revalidation after restart.

- Raised the Tokio minimum and lock to 1.53.3 for RUSTSEC-2026-0386, addressing
  Unix `AsyncFd` I/O safety without suppressing dependency policy checks.

- Added Rust-owned single-use native device refresh during explicit sync and key-verification
  actions. SQLCipher claims and generation CAS prevent cross-process reuse and stale response
  overwrites. Verified tokens cannot change device/account/key identity, expand scopes or extend
  the original refresh family. Lost or uncertain replies require a fresh challenge while retaining
  offline keys and inventory; exact unchanged rate limits preserve their retry deadline. Settings
  exposes the retained-identity recovery action and safe localized renewal/permission errors.
  Older sessions without a verified scope ceiling require fresh authentication.

- Added explicit Account and devices queries in Personal settings. Rust verifies the authenticated
  profile and complete signed certificate/revocation snapshot before atomically caching both in
  SQLCipher. Settings shows the optional email, signed device names/platforms, this device and the
  last manual query; saved results remain available offline after failures or expired authentication.
  Querying reuses native session refresh. Opening settings makes no network request, and no pairing
  or revocation action is implied by the read-only list.

- Added bounded full reconciliation after cursor expiry: complete authenticated snapshots are
  validated before one atomic SQLCipher merge, removal and cursor update. Missing local edits
  become immutable encrypted recovery copies instead of being uploaded automatically. Settings
  exposes exact offline recovery separately from original adoption copies; restored objects
  need fresh upload consent. Concurrent snapshots, invalid later pages, resource limits and
  unconfirmed acknowledgements retain safe durable state across restarts.

- Updated `ctutils` to 0.4.4 for RUSTSEC-2026-0385, restoring constant-time mask
  generation and integer comparison in the shared cryptographic dependency graph.

- Added the Inventory sync settings workflow after key verification: exact object selection,
  content-category and shared-secret review, missing-reference guidance, explicit upload consent,
  manual bounded sync, dirty/applied/ack status, and offline restoration of immutable original
  copies as new local objects. Five-minute one-use Rust preview tickets and transactional object
  version checks reject stale consent. Secrets and object content stay outside IPC; failures are
  localized and never cause an automatic network retry.

- Added a Rust-only first-device Personal inventory roundtrip with explicit object selection,
  atomic immutable local adoption copies, a durable encrypted outbox, authenticated envelope
  decryption and field merge, cursor/ack persistence, bounded CAS conflict retries, and safe
  pull-before-write recovery after an uncertain commit. Restoring adoption copies creates new
  local objects and remaps selected references without uploading them or copying device secrets.
  The API remains separate from account setup and is exposed through the explicit settings flow.
  Unsupported rotations and unverified trust provenance preserve local data and stop explicitly.
- Upgraded all shared Rust pins to `proto@b52ee266`, including complete K-1 object-reference
  discovery for explicit adoption, and aligned UUID at 1.28.0.

- Added Verify sync keys to Personal account settings through typed native commands. Reopening
  settings checks saved keys offline; only the explicit action connects to the server. Busy,
  authentication, invalid-response and unsupported-rotation states are localized, and failed
  rechecks preserve existing verified keys. The frontend receives only redacted status and
  errors; inventory transfer remains a separate outcome.
- Added a Rust-only Personal sync bootstrap using real TLS 1.3 / HTTP/2 session and key
  requests with a fresh DPoP proof for each request. Verified account/device/token bindings,
  certificates, revocations, account key wraps, recovery material, and the retained Personal
  vault key must all agree before one SQLCipher transaction saves the snapshot. Restarts
  reverify the saved artifacts offline. Account or vault rotation is reported separately
  without replacing old keys; inventory frontend wiring remains a later outcome.

- Added first-device Personal account setup in Settings, with Rust-owned invitation parsing,
  encrypted pending identity, native recovery-file export and explicit confirmation, bounded
  verified HTTPS, and fresh device authentication after uncertain enrollment. The interface
  uses localized typed errors and never receives recovery keys, private keys, or access tokens.
  Inventory sync is available only through a separate explicit Rust intent.
- Updated `rustls-webpki` to 0.103.16 to reject distrusted certificate intermediates
  covered by RUSTSEC-2026-0382.
- Added the Rust/IPC path for explicit same-origin replacement of a pending Personal invitation.
  A fresh signed device exchange must first either authenticate the retained identity or return
  the exact parsed D-109 denial. Replacement preserves every id, key, certificate, wrap, and
  recovery confirmation, changes only the invitation and its possession proof, and waits for
  a separate Join. Malformed, cached, revoked, unknown, transport, and token failures cannot
  enable replacement. Settings now offers a hidden, write-only replacement field only while
  enrollment is unconfirmed; it delegates the recovery check to Rust and requires a separate
  Join after an accepted replacement. Successful authentication finishes recovery without
  redeeming the supplied link. Errors are localized, and cancelling clears the input.

- Added Rust-owned automatic terminal reconnect after confirmed network loss, with
  bounded backoff, fresh trust and credential preparation, a Stop reconnecting action,
  retained displayed output, and a new transport and Recent entry for every attempt.
  Background prompts wait for tab selection. Ordered state and binary output plus
  attempt identifiers prevent stale frames or queued input reaching a new shell.
- Connected saved ProxyCommand routes to real SSH through a directly invoked local program,
  with portable quoting, bounded literal target substitutions, no implicit shell expansion,
  retained host-key review, a ten-second handshake deadline, and helper cleanup on failure,
  cancellation, close, or drop. Command text and arguments are redacted from diagnostics.
- Reject invalid SSH usernames before connection preparation, even when a ProxyCommand
  does not substitute the username. Windows helpers do not open console windows, and
  `.bat`/`.cmd` programs that would invoke an implicit shell fail before spawning.
- Connected saved ordered Jump routes to real SSH with independent host-key review and password, encrypted software-key, or exact-key Agent authentication at every hop. The core retains each reviewed connection, fences one-use prompts, retries local passphrases, bounds forwarded setup, and closes chains in reverse on cancellation or failure. Invalid chains and non-Direct routes on jump Logins fail before dialing.
- Reserved transports before connection preparation so closing a tab before the IPC acknowledgment cannot start a late SSH connection or leave an unclaimed registry entry.

- Added manual Reconnect in ended session tabs, preserving displayed terminal output while rechecking host trust and current saved credentials, requesting a fresh one-time passphrase, and using a new transport and history entry for every attempt. Pending tasks and stale results cannot overlap or revive an old connection.
- Cancelled terminal input queued for a replaced sink so delayed keystrokes and old write errors cannot reach a replacement connection.

- Connected saved Agent Credentials to the system Unix socket or Windows OpenSSH pipe, matching the exact saved public key after host-key verification, with bounded cancellable local I/O, four authentication workers, explicit failure paths, and no credential fallback.

- Connected saved SOCKS5 and HTTP CONNECT proxy authentication through independent Route usernames and password Credentials, with preflight validation, the same credentials during host-key probing and SSH sessions, and an editor notice that proxy credentials travel over plain TCP.
- Opened saved passphrase-protected OpenSSH software keys during SSH connection, with one-time entry after host-key review, retry for wrong passphrases, bounded bcrypt work, and no stored passphrase.
- Wired ended terminal sessions in Recent to the normal Connect entry point, resolving the current saved login without creating history during lookup; active and unsupported kinds remain unavailable.
- Fixed terminal profile and theme changes restarting the same source subscription and opening a duplicate SSH connection.
- Connected real SSH attempts to device-local Recent history, recording normal completion, errors, and cancelled connection tasks, and releasing transport registrations when a task is cancelled.
- Connected saved SOCKS5 and HTTP CONNECT routes to live SSH host-key probing and sessions through the shared bounded proxy transports. Invalid proxy endpoints fail before dialing; proxy rejection, timeout, and target trust failures stay fail-closed.
- Upgraded the shared SSH contract and connected OpenSSH ECDSA P-384/P-521 keys and bounded RSA `server-sig-algs` selection. SHA-256-only and SHA-512 servers authenticate with their advertised SHA-2 algorithm; SHA-1-only servers fail closed without a fallback.
- Connected saved unencrypted OpenSSH Ed25519, ECDSA P-256, and RSA software keys to direct SSH public-key authentication, with explicit encrypted, invalid, unsupported-key, and RSA-SHA2-512 rejection errors and unchanged host-key trust checks.
- Fixed silent SSH shells remaining on the connecting screen: the desktop receives an explicit shell-ready notification independently of terminal output, and ignores late notifications after the connection ends.
- Added the first live direct SSH path: password authentication through the shared `scoplen-ssh` engine, host-specific trust-record verification, bounded command/terminal frames, and fail-closed lifecycle errors for unsupported routes and credentials.
- Added the application shell: a Tauri 2 application for macOS and Windows with the Scoplen icon, a typed IPC surface generated from Rust, a binary frame channel for streams, and a launch smoke test.
- Added `@scoplen/ui`: the Scoplen design tokens in light and dark with increased-contrast and reduced-motion support, bundled Inter, Lora, JetBrains Mono, and a Chinese heading subset of Noto Serif SC, the mark and lockup, buttons, a keyboard-navigable toolbar, a skip link, and ICU localization.
- Added the about screen in English and Simplified Chinese, with the interface language chosen from the system's preferences.
- Added the encrypted local store: SQLCipher with versioned migrations, a device identity and clock, field-by-field merging of local writes, change notifications, and the per-vault object limit.
- Added protection of the local database key in the macOS Keychain and, on Windows, the TPM or DPAPI, with an optional local passphrase, a passphrase-only mode for systems without a keystore, and recovery by starting with empty data when the key is lost.
- Added typed repositories for every object type, with field-level changes, clearing of optional fields, redacted credential secrets, and a `storeChanged` event to the interface after every committed change.
- Added device-local records: this device's credential secrets and keystore handles, the device key pair, a bounded session history, scrollback, and window geometry, which the main window now uses to reopen where it was.
- Added platform-keystore-backed `DeviceBoundKey` creation and resolution: each credential gets an opaque device-local handle and a per-device OpenSSH public key, while private material is resolved only at connection time and zeroized after use. `SecurityKey` remains an explicit unsupported capability until FIDO2/WebAuthn support is implemented; native non-exportable hardware signing remains a later platform outcome.
- Added a macOS check that the application makes no network connection while sync is disabled.
- Fixed Windows test executables failing to start because they lacked the Common Controls manifest.
