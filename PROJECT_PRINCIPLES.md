# Scoplen client principles

This repository is a component of Scoplen, a Plystra project, and the full Plystra philosophy applies. The project-level adoption record is [`scoplen-docs/PROJECT_PRINCIPLES.md`](../scoplen-docs/PROJECT_PRINCIPLES.md); this record applies it to the desktop client.

## Review record

- Philosophy version reviewed: Plystra Craft 1.0.1
- Source commit reviewed: `plystra/craft@dd617b370203d5dce1d30b8b81284d16d96a432c`
- Review date and maintainer: 2026-10-07, Plystra LLC
- Maturity: Exploration
- Maintenance: Active
- Components: the desktop application for macOS and Windows, its Rust core and platform layer, the `@scoplen/ui` design system, and later the `@scoplen/terminal` package
- Public data surface: none yet. The client sends nothing to the vendor in Phase 1 (`scoplen-docs/16-decision-record.md`, D-32, D-52); user data stays on the device and, when sync is enabled, on the server the user chooses.
- Review status: Reviewed with open gaps

## Applicable standards

The repository applies `plystra-craft`, `plystra-craft-code`, and `plystra-craft-design` from `.agents/skills/`. Source code is Apache-2.0. Shipped JavaScript and Rust dependencies are checked for licenses compatible with that (`pnpm license-check`, `cargo deny`). Interface copy follows `scoplen-docs/11-client-architecture.md` §4.1, and visible changes go through the Craft UI review checklist.

## Open gaps

- The application shell, encrypted local store, inventory, and real SSH terminal path exist,
  including password/software-key authentication, exact saved-key system-agent
  authentication, saved proxy routes with optional password authentication, and
  explicit Jump routes with independent trust and credentials at each hop, and saved
  ProxyCommand routes with bounded literal arguments and owned helper cleanup.
  Connected terminals have bounded automatic network reconnect with explicit stop,
  fresh trust and credentials, and attempt-fenced input/output; a reconnect starts
  a new remote shell and does not restore remote processes. Bounded rendered output is saved
  locally and can be opened read-only from Recent after closing a tab or restarting the app.
  A connected terminal can browse bounded SFTP directories, download regular files through
  a native destination picker, and upload one regular local file through a native source picker
  on the same authenticated SSH connection. Upload to an existing regular target requires
  explicit native overwrite confirmation and safe replacement support. The same Files panel
  creates folders, checks for an unused target before renaming regular files or directories, and
  deletes regular files or empty directories after native confirmation. A concurrent remote rename
  target may still be replaced on some servers; uncertain results require manual review.
  Rust owns a bounded per-session transfer queue across Files visibility and transport
  replacement, with explicit cancellation, conflict handling and unknown-result acknowledgement.
  Drag and drop, pause, resume, and the remaining C6 workflows are incomplete.
  The inventory, terminal, and connection gates still have open outcomes; sync and organization
  workflows remain incomplete. The canonical roadmap records their implementation evidence.
- The Windows TPM path of key storage cannot run on hosted CI runners, which have no TPM; only its DPAPI fallback is exercised there.
- Windows and macOS build/launch checks pass in completed CI run
  [39270829781](https://github.com/scoplen/client/actions/runs/39270829781) at `client@76ad83f`,
  alongside frontend, Rust, dependency, and OpenSSH key/proxy checks. This does not establish
  release signing, packaging, or the complete C15 platform gate.
- An accessibility audit against WCAG 2.2 AA on both platforms is scheduled for roadmap C15; the current evidence is automated axe checks, contrast checks of the tokens, and keyboard tests of the components.
