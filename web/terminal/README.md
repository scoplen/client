# @scoplen/terminal

`@scoplen/terminal` is the session-agnostic terminal boundary shared by the
Scoplen desktop client and the server web console. It has no Tauri, IPC, client
store, network, or cryptography dependency. Callers own the binary source and
sink and decide which session or transport they represent.

The package now provides the first terminal experience slice: xterm.js core
emulation with bounded output retention and scrollback, search, copy and paste,
profiles, accessible fallback rendering, explicitly confirmed broadcast input,
and a DOM-free IME composition bridge. `TerminalWorkspace` provides tabs and
split-pane layout state without pretending to create a connection. WebGL,
Unicode width addons, serialization, image protocols, platform-wide IME
verification, and the compatibility suite remain planned work.

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

## Tabs and split panes

`TerminalWorkspace` is a pure layout model. It owns tab titles, pane identity,
active-tab state, nested horizontal or vertical splits, and subscriptions. It
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
this model.

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

## Current boundaries

The following are deliberately not claimed by this slice:

- WebGL renderer and Unicode 15 width provider;
- scrollback serialization for reconnect and workspace restoration;
- SIXEL and iTerm2 image protocols;
- IME behavior verified on every desktop platform;
- `vttest`, `esctest`, and recorded full-screen program compatibility runs.

The xterm.js core can render an accessible DOM surface with screen-reader mode
enabled. If a host cannot initialize the renderer, the element keeps the
bounded text preview, reports a `renderer` error, and remains keyboard and
screen-reader addressable.

## Development

```bash
pnpm --dir web/terminal typecheck
pnpm --dir web/terminal test
pnpm --dir web/terminal build
```
