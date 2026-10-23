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
device authentication, sync-key verification and reviewed inventory APIs against an
independently running server. It does not read server source or seed its database.

Prepare a fresh disposable server on `https://localhost:<port>` with a trusted test CA.
Complete public Operator setup and login, then issue an unused Personal invitation. Put a
JSON descriptor in a private file with exactly `disposable: true`, `origin`,
`invitation_url` and `ca_certificate` (the PEM certificate's absolute path). Keep the
descriptor and server output private; the invitation is a one-use credential.

In PowerShell, point to that existing private descriptor and run:

```powershell
$env:SCOPLEN_LIVE_PERSONAL_DEPLOYMENT = 'C:/private/disposable-personal.json'
cargo test -p scoplen-client-core --lib --features live-server-integration live_server:: -- --test-threads=1
```

The test rejects a non-loopback origin, bounds descriptor and certificate reads, and adds
the test CA only to its own HTTPS client. It consumes the invitation, creates and reopens
an isolated SQLCipher store, uploads and downloads a signed encrypted host and its edit,
checks durable acknowledgements, and restores the original local copy offline. Before the
first transfer and again after reopening the store, it expires only the client's cached
access lifetime and exercises the production refresh path using the genuine server-issued
refresh credential. It checks durable session generation, a changed access credential and
the retained refresh-family deadline ceiling; server clocks and signed JWTs are unchanged.
The remaining whole seconds and JWT issuance time can be sampled independently. Rotation
uses their lifetime estimate conservatively and never extends the retained ceiling.
Repeating
it requires a fresh disposable deployment and invitation. Remove the private descriptor,
test server and its temporary data after verification. This does not establish native
desktop UI, physical passkey, macOS or multi-device acceptance.

## Generated files

| File | Regenerate with | When |
| --- | --- | --- |
| `web/app/src/ipc/bindings.ts` | `pnpm bindings` | A command or a type it uses changes |
| `web/ui/src/fonts/scoplen-serif-sc.woff2` and `.json` | `pnpm fonts` | `web/app/src/messages/zh-Hans.ts` changes |
| `src-tauri/icons/*` | `pnpm icon` | The mark geometry changes |

Tests fail while the bindings or the font are out of date.

## Writing interface copy

Add the English message to `web/app/src/messages/en.ts` first, then write the Chinese in `zh-Hans.ts` as natural Chinese, not a sentence-by-sentence translation, using the vocabulary of `scoplen-docs/11-client-architecture.md` §4.1. Use ICU plural and select forms rather than concatenating strings.
