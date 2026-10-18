# Repository guidance

The workspace guidance in [`../AGENTS.md`](../AGENTS.md) is authoritative. The canonical specification is in [`../scoplen-docs`](../scoplen-docs). This repository must not read or depend on `server` source; shared contract types come from `proto`.

All behavior lives in Rust (`crates/scoplen-client-core`); the frontend renders state and sends intents, never holds secrets, never performs cryptography, and never talks to the network. `unsafe` code is allowed only in `crates/scoplen-client-platform`, with each block documented.

## Commands

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cargo deny check
cargo machete
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm test
pnpm license-check
```

Regenerate `web/app/src/ipc/bindings.ts` with `pnpm bindings` after changing a command, and the Chinese heading font with `pnpm fonts` after changing `web/app/src/messages/zh-Hans.ts`. Every commit must include a `Signed-off-by:` trailer. Do not publish packages, bundles, or references from an agent checkout.
