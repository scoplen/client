# @scoplen/terminal

`@scoplen/terminal` is the session-agnostic terminal boundary shared by the
Scoplen desktop client and the server web console. It has no Tauri, IPC, client
store, network, or cryptography dependency. Callers own the binary source and
sink and decide which session or transport they represent.

The package now provides the first terminal experience slice: xterm.js core
emulation with bounded output retention and scrollback, search, copy and paste,
profiles, Unicode 15 character widths, rendered-state serialization, accessible
fallback rendering, explicitly confirmed broadcast input, and a DOM-free IME
composition bridge. `TerminalWorkspace` provides tabs and split-pane layout state
without pretending to create a connection. WebGL, image protocols, platform-wide
IME verification, and the compatibility suite remain planned work.

The package build copies xterm's CSS into `dist`; each custom element loads it
inside its shadow root so renderer styles apply without leaking into the host
page. Consumers should run the package build before bundling a workspace app.

## Direct custom element

```ts
import {
  defineTerminalElement,
  type ScoplenTerminalElement,
} from "@scoplen/terminal";

defineTerminalElement();
const terminal = document.querySelector("scoplen-terminal") as ScoplenTerminalElement;

terminal.profile = {
  fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace",
  fontSize: 14,
  scrollback: 2_000,
  cursorStyle: "bar",
};
terminal.source = {
  subscribe(onChunk, { signal }) {
    const stop = transport.onBytes(onChunk);
    signal.addEventListener("abort", stop, { once: true });
    return stop;
  },
};
terminal.sink = {
  async write(bytes) {
    await transport.send(bytes);
  },
};
```

`source` accepts a subscription object, `ReadableStream<Uint8Array>`, or
`AsyncIterable<Uint8Array>`. A subscription returns `unsubscribe()` or a
cleanup function and receives an `AbortSignal`. `sink` accepts a `write`
object, `WritableStream<Uint8Array>`, or a function. `send()` serializes sink
writes and returns a promise; `maxPendingWrites` rejects new input with a
`TerminalBackpressureError` when the sink cannot keep up.

Replacing `sink` cancels input queued for its previous assignment with
`TerminalDisconnectedError`, including when a sink is removed and later reused.
An old write's completion or failure cannot write to the replacement sink or
emit an error into its connection. Assigning the same sink again keeps its
queued input. Output remains available when the source or sink changes.

Output bytes are written to xterm.js and retained as the most recent
`maxOutputBytes` bytes (1 MiB by default). `profile.scrollback` controls the
xterm scrollback row limit. Input frames are limited to 64 KiB and pending sink
writes to 32. These limits make a stalled or untrusted transport observable
instead of allowing unbounded memory growth.

The element emits `terminal-output`, `terminal-input`,
`terminal-broadcast-input`, `terminal-broadcast-state`, `terminal-error`, and
`terminal-complete`. Event `detail` values are `Uint8Array`, `boolean`, or a
`TerminalError` according to the event. The element unsubscribes its source,
disposes xterm.js, and rejects queued writes when disconnected. It does not
close a caller-owned sink on disconnect; call `closeSink()` or
`dispose({ closeSink: true })` when that ownership is explicit.

### Search and clipboard

`findNext`, `findPrevious`, and `clearSearch` operate on xterm.js' retained
scrollback. `copySelection`, `copyAll`, and `paste` use the browser clipboard
by default or an injected `terminal.clipboard` implementation. Clipboard
permission or availability failures emit a `TerminalError` with code
`clipboard` and return `false`.

With the renderer available, `paste()` uses xterm's active bracketed-paste mode
and normalizes line endings before sending one bounded input frame. The input
byte limit includes any bracketed-paste delimiters. Its promise waits for the
primary sink write and returns `false` if that write fails or its queue is full;
the existing input error is reported once.

A clipboard read belongs to the renderer lifecycle, input sink assignment, and
broadcast targets that requested it. Replacing or removing either sink, changing
broadcast mode, disconnecting, disposing, entering read-only mode, or restoring
offline output invalidates a pending read. Late text and errors are discarded
without affecting a newer connection. Assigning the same sinks or broadcast mode
keeps the request valid. Disconnected, read-only and restoring elements refuse
paste before accessing the clipboard.

Once paste has dispatched its input frame, a broadcast change only discards the
pending secondary copy; the paste result still reflects the primary write.

### IME composition

`TerminalImeCompositionBridge` is a small, DOM-free state machine for hosts
that need to adapt browser or native composition events. `start()` and
`update()` never write candidate text to the terminal sink; `end(data)`
writes only the committed, non-empty final text. `cancel()` and `blur()`
discard a pending composition so a late `compositionend` cannot leak
candidate text after focus changes. The custom element uses this bridge for
events outside xterm.js' helper textarea and delegates helper-textarea events
to xterm.js, preventing duplicate writes. The bridge is testable in a browser
or a no-DOM host; platform-specific IME behavior still requires desktop
verification.

### Broadcast input

Broadcast is opt-in and requires a confirmation callback because one keystroke
can affect several sessions. The caller provides a secondary `broadcastSink`:

```ts
terminal.broadcastSink = (bytes) => broadcastTransport.send(bytes);
const enabled = await terminal.setBroadcastInput(true, () => confirm("Send input to every selected session?"));
```

When enabled, the component exposes a visible `Broadcast input on` status
indicator and emits a broadcast event. A failed secondary write is reported
without making the primary session input fail.

Queued input retains its broadcast targets. Changing the broadcast sink or mode
discards its pending secondary copy without interrupting an already started
primary write. Replacing a target from a broadcast event also prevents that
frame from reaching the replacement. Reassigning the same sink or mode preserves
the copy; old secondary write failures do not report into a new target assignment.

## Tabs and split panes

`TerminalWorkspace` is a pure layout model. It owns tab titles, pane identity,
active-tab state, remembered pane focus, nested horizontal or vertical splits, and subscriptions. It
does not own sessions, credentials, or transports:

```ts
import { TerminalWorkspace } from "@scoplen/terminal";

const workspace = new TerminalWorkspace();
const firstPane = workspace.openTab({ id: "shell", title: "Shell" });
workspace.splitPane(firstPane, "vertical", "pane:logs");
const layout = workspace.snapshot();
```

The client or web console attaches a `scoplen-terminal` element and its
caller-owned source/sink to each pane. A tab owns its own layout; switching tabs
changes `snapshot().layout` without altering another tab's panes. Closing a tab
removes all of its panes; no connection is silently created or destroyed by
this model. `snapshot().layouts` and `focusedPaneIds` project every tab; `layout`
and `activePaneId` project the selected tab, or null after `setActiveTab(null)`.
`restoreTab(tab, tree, focusedPaneId)` appends a complete binary tree with unique
pane identities. `focusPane` and `moveFocus(-1 | 1)` select metadata in depth-first
order, wrapping inside the tab. Call the selected terminal element's `focusInput()`
to move actual keyboard input into its xterm textarea.

After the caller successfully checkpoints and closes a session, `closePane(id)`
removes its leaf and collapses the parent to its sibling. Focus stays on a surviving
pane, choosing the preceding leaf when the selected leaf closes. The last leaf closes
its tab and selects the preceding tab or no tab. Render pane components under a stable
parent and position them from layout metadata; recursively reparenting a custom element
disconnects its source. The new required snapshot fields are a pre-Stable source change;
callers constructing snapshots must supply complete layouts and focus.

## React

```tsx
import { Terminal } from "@scoplen/terminal/react";

<Terminal
  source={source}
  sink={sink}
  profile={{ scrollback: 2_000, cursorBlink: true }}
  broadcastSink={broadcastSink}
  onTerminalOutput={(bytes) => recordOutput(bytes)}
  onTerminalError={(error) => report(error)}
/>;
```

The binding only assigns element properties and subscribes to element events.
It does not know about Tauri or Scoplen client state, and removes its event
listeners when the component unmounts.

## Unicode character widths

Every renderer uses Unicode 15.0.0 codepoint widths, including supplementary CJK
and Unicode 15 emoji. Wide and fullwidth characters occupy two columns;
ambiguous characters occupy one. Nonspacing/enclosing marks (`Mn`, `Me`) and
format characters (`Cf`) occupy zero, except soft hyphen (U+00AD), which keeps
one column. Hangul Jamo U+1160-U+11FF and C0/C1 controls keep xterm's existing
zero-width policy. Zero-width characters join a preceding occupied cell without
changing its width. This is ordinary codepoint mode: ZWJ sequences and variation
selectors do not introduce grapheme-dependent width changes.

The provider uses four generated interval tables and adds no runtime dependency.
Its `charProperties` packing follows the pinned xterm 6 provider API; xterm upgrades
must retain the combining, cursor-report, wrapping and restoration regressions.
Data comes from the official [UnicodeData.txt](https://www.unicode.org/Public/15.0.0/ucd/UnicodeData.txt)
and [EastAsianWidth.txt](https://www.unicode.org/Public/15.0.0/ucd/EastAsianWidth.txt).
Unicode's copyright and permission notice ships in `licenses/UNICODE.txt` under
Unicode-3.0; package source remains Apache-2.0.

To regenerate, download those two versioned files to a local directory and run:

```bash
node web/terminal/scripts/generate-unicode15.mjs /path/to/ucd-15.0.0
node web/terminal/scripts/generate-unicode15.mjs /path/to/ucd-15.0.0 --check
```

The Node-only generator rejects inputs unless their SHA-256 matches
`806e9aed65037197f1ec85e12be6e8cd870fc5608b4de0fffd990f689f376a73`
and `743e7bc435c04ab1a8459710b1c3cad56eedced5b806b4659b6e69b85d0adf2a`,
respectively. Normal build and test commands are offline and use the checked-in
tables. The full-codepoint regression uses an independent dense width reference
derived from those inputs with Python `csv` and `bytearray`; integration tests
consume the built public package through its binary source/sink and snapshot API.

## Current boundaries

The following are deliberately not claimed by this slice:

- WebGL renderer;
- SIXEL and iTerm2 image protocols;
- IME behavior verified on every desktop platform;
- `vttest`, `esctest`, and recorded full-screen program compatibility runs.

The xterm.js core can render an accessible DOM surface with screen-reader mode
enabled. If a host cannot initialize the renderer, the element keeps the
bounded text preview, reports a `renderer` error, and remains keyboard and
screen-reader addressable.

## Serialization

`await element.serialize()` returns version 1 rendered state and grid dimensions only after
pending writes are processed. Its encoded JSON representation is limited to 1 MiB. Invalid
dimensions, oversized output or an unavailable renderer reject without producing a snapshot.
`await element.restore(snapshot)` restores the saved grid and state before fitting the current
view. The raw suffix returned by `getOutput()` still respects `maxOutputBytes`, while the renderer
restores the complete bounded snapshot. It requires no source or sink; attaching one during restoration is rejected. Parser
replies and input are discarded until restoration completes. Set `readOnly` (also supported by
the React binding) to keep keyboard, paste and broadcast input disabled for offline viewing.
Transport ownership, encrypted persistence, retention and reconnect consent belong to callers.
This API does not create sessions or restore remote processes or workspace layout.

## Development

```bash
pnpm --dir web/terminal typecheck
pnpm --dir web/terminal test
pnpm --dir web/terminal build
```

Typecheck and test commands build the package first so public-package tests work
on a fresh checkout.
