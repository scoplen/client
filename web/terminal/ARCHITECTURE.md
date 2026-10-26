# Terminal package architecture

## Purpose

`@scoplen/terminal` is a reusable view and interaction boundary. It is
session-agnostic: the package accepts bytes from a caller-owned source and
returns input bytes to caller-owned sinks. It never opens sockets, reads client
state, stores credentials, or performs cryptography.

## Data flow

```text
caller source (Uint8Array)
        │
        ▼
ScoplenTerminalElement ── xterm.js core + SearchAddon ── DOM renderer
        │                         │
        │                         └─ bounded xterm scrollback/profile
        │
        ├─ terminal-output event (copied bytes)
        ├─ primary sink (serialized writes)
        └─ optional broadcast sink (secondary, failure-isolated writes)
```

The element also keeps a byte-level output cap for observability and fallback
rendering. xterm.js owns terminal parsing, ANSI state, cursor, selection, and
scrollback rows. The byte cap is independent of the xterm row cap so a caller
can bound transport memory even when a profile keeps a larger scrollback.

## Lifecycle

1. `connectedCallback` creates xterm.js, registers and selects the Unicode 15
   codepoint provider before opening the renderer, loads the search addon, installs input
   and IME listeners, and subscribes to the source.
2. Source chunks are copied, emitted as `terminal-output`, retained under the
   byte cap, and written to xterm.js.
3. xterm `onData` and `onBinary` input is converted to `Uint8Array` and enters
   the same bounded, serialized sink path as `send()`.
4. `disconnectedCallback` aborts and unsubscribes the source, disposes xterm.js,
   and advances a generation counter. Queued writes observe that generation and
   fail with `TerminalDisconnectedError` before touching a sink.
5. Reconnecting creates a fresh renderer and replays the bounded byte history;
   the package does not claim durable session serialization.

The React binding assigns `source` only when the source identity changes. Profile,
theme, sink, and limit updates preserve an existing subscription, so rendering a
new profile object cannot restart a caller-owned transport.

If xterm.js cannot initialize, the element switches to a `pre` text fallback,
emits a `renderer` error, and keeps the same binary source/sink and accessibility
surface. This fallback is for host capability failures; it is not a terminal
emulator and does not claim full-screen program compatibility.

## Interaction boundaries

- **Profiles:** `TerminalProfile` is the small stable subset of xterm options
  that affects user-visible terminal appearance and scrollback.
- **Search:** `SearchAddon` searches xterm's retained rows. The byte preview is
  used only as a capability fallback.
- **Clipboard:** read/write operations are injected or use `navigator.clipboard`.
  Permission errors return `false` and emit a typed `clipboard` error.
  Pending paste reads retain their renderer lifecycle, input-sink assignment and
  broadcast generation; stale results and errors are discarded. xterm's public
  paste operation supplies line-ending normalization and bracketed-paste framing
  through the existing bounded input queue. The paste promise retains that
  write's result instead of claiming success before the primary sink accepts it.
- **IME:** composition events outside xterm.js' helper textarea pass through a
  DOM-free `TerminalImeCompositionBridge`. Candidate updates are discarded;
  only non-empty `compositionend` data reaches the sink. Cancellation, blur,
  and disconnection clear the pending composition.
- **Broadcast:** enabling requires an explicit confirmation callback. A
  secondary caller-owned sink receives copies of primary input and cannot make
  the primary write fail. The visible status indicator and events make the mode
  legible to keyboard and screen-reader users. Each input frame captures its
  broadcast sink and mode generation; a changed assignment discards the pending
  secondary copy without redirecting it or cancelling the primary write.
- **Tabs and splits:** `TerminalWorkspace` stores only layout metadata. It does
  not create, close, or reconnect sessions; callers bind terminal elements and
  transports to pane IDs.

## Capability boundaries

This slice intentionally leaves WebGL,
inline image protocols, cross-platform IME verification, and the
`vttest`/`esctest` compatibility suite for later C4 outcomes. The package does
not describe those capabilities as available through a hidden fallback.

Unicode widths come from checked-in Unicode 15.0.0 UCD intervals with no additional
runtime dependency. The provider preserves
xterm's ordinary combining-cell policy and narrow ambiguous characters; it does
not enable grapheme-cluster width changes. The generator pins both official source
checksums, and offline full-codepoint and public-package rendering-state regressions
cover the tables and integration. Source provenance, licensing and regeneration
instructions are in the package README.

Serialization uses xterm's serialize addon after a write-barrier callback, preserving rendered
state rather than replaying the bounded raw transport suffix. Snapshots include version, grid
dimensions and ANSI state, with a 1 MiB encoded UTF-8 bound. Restore validates before mutation,
requires an offline source/sink, suppresses input and parser replies across its asynchronous
write barrier, and fits only after restoring the saved grid. Disconnect cancels pending barriers.
The optional `readOnly` property keeps all input disabled after restore. Persistence and
authorization are outside this framework-independent package.
