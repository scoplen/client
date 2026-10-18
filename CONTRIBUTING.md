# Contributing

Scoplen is a Plystra project. Read the workspace guidance in `../AGENTS.md`, this repository's `AGENTS.md`, and the specification in `../scoplen-docs` before changing behavior. The client and server workstreams are separate: this repository never reads or depends on `server` code, and anything both sides need belongs in `proto`, specified in `scoplen-docs` first.

Run the checks listed in [README.md](README.md#development) before requesting review. After changing a command in `src-tauri`, run `pnpm bindings`; after changing the Chinese catalog, run `pnpm fonts`. Tests fail until the generated files are current.

Interface copy follows `scoplen-docs/11-client-architecture.md` §4.1: English is the source, Chinese is written as natural Chinese with the listed vocabulary, labels are sentence case, and every error says what failed, whether anything changed, and what to do next. Every visible change goes through the Craft UI review checklist (`.agents/skills/plystra-craft-design/assets/templates/ui-review-checklist.md`).

Every source file carries an SPDX header. Commit subjects use `type(scope): description`. Contributions require the Developer Certificate of Origin sign-off (`git commit -s`).

The DCO workflow treats the signed repository-import snapshot in
`DCO_IMPORT_BASELINE` as the boundary of the imported history. Initial pushes and new branches
check that snapshot and every descendant commit, including merges. Later pushes and pull requests
check their full event range. A signed branch tip cannot hide an unsigned intermediate commit.
Run `bash scripts/test-dco.sh` to verify these cases locally.
