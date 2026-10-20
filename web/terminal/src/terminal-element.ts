// SPDX-License-Identifier: Apache-2.0
/* eslint-disable @typescript-eslint/no-invalid-void-type */
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon, type ISearchOptions } from "@xterm/addon-search";
import { Terminal as XtermTerminal, type ITerminalOptions } from "@xterm/xterm";
import {
  TerminalBackpressureError,
  TerminalBoundsError,
  TerminalDisconnectedError,
  TerminalError,
  type TerminalBytes,
  type TerminalBroadcastConfirmation,
  type TerminalClipboard,
  type TerminalElementEventMap,
  type TerminalObjectSink,
  type TerminalProfile,
  type TerminalSink,
  type TerminalSize,
  type TerminalSource,
  type TerminalSubscription,
} from "./types";
import { TerminalImeCompositionBridge } from "./ime";

export const TERMINAL_TAG_NAME = "scoplen-terminal";
export const DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024;
export const DEFAULT_MAX_INPUT_BYTES = 64 * 1024;
export const DEFAULT_MAX_PENDING_WRITES = 32;

const DEFAULT_PROFILE: TerminalProfile = {
  cursorBlink: false,
  cursorStyle: "block",
  fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace",
  fontSize: 14,
  scrollback: 1000,
  theme: {
    background: "#111827",
    foreground: "#f3f4f6",
    cursor: "#f3f4f6",
    selectionBackground: "#334155",
  },
};

// eslint-disable-next-line @typescript-eslint/no-extraneous-class
const HTMLElementBase = (typeof HTMLElement === "undefined" ? class {} : HTMLElement) as typeof HTMLElement;

function isBytes(value: unknown): value is TerminalBytes {
  return value instanceof Uint8Array || Object.prototype.toString.call(value) === "[object Uint8Array]";
}

function cloneBytes(value: TerminalBytes): TerminalBytes {
  return new Uint8Array(value);
}

function normalizeUnsubscribe(value: TerminalSubscription | (() => void) | void): () => void {
  if (typeof value === "function") {
    return value;
  }
  if (value && typeof value.unsubscribe === "function") {
    return () => value.unsubscribe();
  }
  return () => undefined;
}

function positiveLimit(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${name} must be a positive safe integer`);
  }
  return value;
}

function nonNegativeLimit(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${name} must be a non-negative safe integer`);
  }
  return value;
}

function isReadableStream(source: TerminalSource): source is ReadableStream<TerminalBytes> {
  return typeof ReadableStream !== "undefined" && source instanceof ReadableStream;
}

function isAsyncIterable(source: TerminalSource): source is AsyncIterable<TerminalBytes> {
  return typeof (source as AsyncIterable<TerminalBytes>)[Symbol.asyncIterator] === "function";
}

function isWritableStream(sink: TerminalSink): sink is WritableStream<TerminalBytes> {
  return typeof WritableStream !== "undefined" && sink instanceof WritableStream;
}

function isObjectSink(sink: TerminalSink): sink is TerminalObjectSink {
  return typeof sink === "object" && sink !== null && "write" in sink && typeof sink.write === "function";
}

function cloneProfile(profile: TerminalProfile): TerminalProfile {
  const next = { ...profile };
  if (next.scrollback !== undefined) {
    next.scrollback = nonNegativeLimit(next.scrollback, "profile.scrollback");
  }
  if (next.fontSize !== undefined && (!Number.isFinite(next.fontSize) || next.fontSize <= 0)) {
    throw new RangeError("profile.fontSize must be positive");
  }
  if (next.theme) {
    next.theme = { ...next.theme, extendedAnsi: next.theme.extendedAnsi?.slice() };
  }
  return next;
}

function profileWithDefaults(profile: TerminalProfile): TerminalProfile {
  return cloneProfile({ ...DEFAULT_PROFILE, ...profile, theme: { ...DEFAULT_PROFILE.theme, ...profile.theme } });
}

function toBinary(value: string): TerminalBytes {
  return new TextEncoder().encode(value);
}

function toLatin1(value: string): TerminalBytes {
  const bytes = new Uint8Array(value.length);
  for (let index = 0; index < value.length; index += 1) {
    bytes[index] = value.charCodeAt(index) & 0xff;
  }
  return bytes;
}

function cameFromXtermHelper(event: Event): boolean {
  const path = typeof event.composedPath === "function" ? event.composedPath() : [event.target];
  return path.some(
    (entry) =>
      typeof HTMLElement !== "undefined" &&
      entry instanceof HTMLElement &&
      entry.classList.contains("xterm-helper-textarea"),
  );
}

/** A bounded terminal surface; transport remains a caller-owned binary source/sink. */
export class ScoplenTerminalElement extends HTMLElementBase {
  private _source: TerminalSource | null = null;
  private _sink: TerminalSink | null = null;
  private _broadcastSink: TerminalSink | null = null;
  private _clipboard: TerminalClipboard | null = null;
  private _profile: TerminalProfile = profileWithDefaults({});
  private _maxOutputBytes = DEFAULT_MAX_OUTPUT_BYTES;
  private _maxInputBytes = DEFAULT_MAX_INPUT_BYTES;
  private _maxPendingWrites = DEFAULT_MAX_PENDING_WRITES;
  private outputBytes = new Uint8Array();
  private terminalHost: HTMLElement | null = null;
  private fallbackOutput: HTMLElement | null = null;
  private broadcastIndicator: HTMLElement | null = null;
  private terminal: XtermTerminal | null = null;
  private searchAddon: SearchAddon | null = null;
  private fitAddon: FitAddon | null = null;
  private resizeObserver: ResizeObserver | null = null;
  private fitFrame = 0;
  private terminalDisposables: Array<{ dispose(): void }> = [];
  private sourceAbort: AbortController | null = null;
  private sourceUnsubscribe: (() => void) | null = null;
  private sinkWriter: WritableStreamDefaultWriter<TerminalBytes> | null = null;
  private broadcastSinkWriter: WritableStreamDefaultWriter<TerminalBytes> | null = null;
  private writeTail: Promise<void> = Promise.resolve();
  private pendingWrites = 0;
  private lifecycleGeneration = 0;
  private sinkGeneration = 0;
  private connected = false;
  private listenersAttached = false;
  private _broadcastInput = false;
  private readonly ime = new TerminalImeCompositionBridge((text) => {
    void this.send(toBinary(text)).catch(() => undefined);
  });

  constructor() {
    super();
    if (typeof this.attachShadow !== "function") {
      return;
    }
    const shadow = this.attachShadow({ mode: "open" });
    const xtermStyles = document.createElement("link");
    xtermStyles.rel = "stylesheet";
    xtermStyles.href = new URL("./xterm.css", import.meta.url).href;
    const style = document.createElement("style");
    style.textContent =
      ":host{display:block;contain:content;background:var(--scoplen-terminal-background,#111827);color:#f3f4f6;min-height:4rem;position:relative;overflow:hidden}:host(:focus-visible){outline:2px solid #60a5fa;outline-offset:2px}.terminal-host{height:100%;width:100%;min-height:inherit}.terminal-host[hidden]{display:none}.fallback-output{box-sizing:border-box;height:100%;min-height:inherit;margin:0;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;padding:.75rem;font:14px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}.broadcast-indicator{position:absolute;right:.5rem;top:.5rem;border:1px solid #fbbf24;background:#422006;color:#fde68a;padding:.125rem .375rem;font:600 11px/1.4 ui-sans-serif,system-ui,sans-serif;letter-spacing:.02em}.broadcast-indicator[hidden]{display:none}.xterm{height:100%;width:100%;min-height:inherit}.xterm .xterm-viewport{background-color:transparent!important}";
    this.terminalHost = document.createElement("div");
    this.terminalHost.className = "terminal-host";
    this.terminalHost.setAttribute("part", "terminal");
    this.fallbackOutput = document.createElement("pre");
    this.fallbackOutput.className = "fallback-output";
    this.fallbackOutput.setAttribute("part", "output");
    this.fallbackOutput.setAttribute("role", "log");
    this.fallbackOutput.setAttribute("aria-live", "polite");
    this.broadcastIndicator = document.createElement("span");
    this.broadcastIndicator.className = "broadcast-indicator";
    this.broadcastIndicator.setAttribute("part", "broadcast-indicator");
    this.broadcastIndicator.setAttribute("role", "status");
    this.broadcastIndicator.setAttribute("aria-live", "polite");
    this.broadcastIndicator.textContent = "Broadcast input on";
    this.broadcastIndicator.hidden = true;
    shadow.append(xtermStyles, style, this.terminalHost, this.fallbackOutput, this.broadcastIndicator);
  }

  get source(): TerminalSource | null {
    return this._source;
  }

  set source(source: TerminalSource | null) {
    this._source = source;
    if (this.connected) {
      this.attachSource();
    }
  }

  get sink(): TerminalSink | null {
    return this._sink;
  }

  set sink(sink: TerminalSink | null) {
    if (this._sink === sink) return;
    this.releaseSinkWriter();
    this._sink = sink;
    this.sinkGeneration += 1;
  }

  get broadcastSink(): TerminalSink | null {
    return this._broadcastSink;
  }

  set broadcastSink(sink: TerminalSink | null) {
    this.releaseBroadcastSinkWriter();
    this._broadcastSink = sink;
  }

  get clipboard(): TerminalClipboard | null {
    return this._clipboard;
  }

  set clipboard(value: TerminalClipboard | null) {
    this._clipboard = value;
  }

  get profile(): TerminalProfile {
    return cloneProfile(this._profile);
  }

  set profile(value: TerminalProfile) {
    this._profile = profileWithDefaults({
      ...this._profile,
      ...value,
      theme: { ...this._profile.theme, ...value.theme },
    });
    this.applyProfile();
  }

  get broadcastInput(): boolean {
    return this._broadcastInput;
  }

  get maxOutputBytes(): number {
    return this._maxOutputBytes;
  }

  set maxOutputBytes(value: number) {
    this._maxOutputBytes = positiveLimit(value, "maxOutputBytes");
    if (this.outputBytes.byteLength > this._maxOutputBytes) {
      this.outputBytes = this.outputBytes.slice(-this._maxOutputBytes);
      this.renderFallbackOutput();
    }
  }

  get maxInputBytes(): number {
    return this._maxInputBytes;
  }

  set maxInputBytes(value: number) {
    this._maxInputBytes = positiveLimit(value, "maxInputBytes");
  }

  get maxPendingWrites(): number {
    return this._maxPendingWrites;
  }

  set maxPendingWrites(value: number) {
    this._maxPendingWrites = positiveLimit(value, "maxPendingWrites");
  }

  connectedCallback(): void {
    if (this.connected) {
      return;
    }
    this.connected = true;
    this.lifecycleGeneration += 1;
    this.setAttribute("role", "application");
    if (!this.hasAttribute("aria-label")) this.setAttribute("aria-label", "Terminal");
    this.tabIndex = 0;
    if (!this.listenersAttached) {
      this.addEventListener("keydown", this.onKeyDown);
      this.addEventListener("compositionstart", this.onCompositionStart);
      this.addEventListener("compositionupdate", this.onCompositionUpdate);
      this.addEventListener("compositionend", this.onCompositionEnd);
      this.addEventListener("compositioncancel", this.onCompositionCancel);
      this.addEventListener("blur", this.onBlur, true);
      this.listenersAttached = true;
    }
    this.ensureTerminal();
    this.attachSource();
  }

  disconnectedCallback(): void {
    if (!this.connected) {
      return;
    }
    this.connected = false;
    this.lifecycleGeneration += 1;
    this.ime.cancel();
    this.detachSource();
    this.teardownTerminal();
    this.writeTail = this.writeTail.catch(() => undefined);
  }

  /** Stop the source, clear rendered bytes, and optionally close an owned sink. */
  async dispose(options: { closeSink?: boolean } = {}): Promise<void> {
    this.detachSource();
    this.teardownTerminal();
    this.clearOutput();
    if (options.closeSink) {
      await this.closeSink();
    }
  }

  async closeSink(): Promise<void> {
    const sink = this._sink;
    if (sink === null) {
      return;
    }
    if (isWritableStream(sink)) {
      const writer = this.getSinkWriter(sink);
      await writer.close();
      return;
    }
    if (isObjectSink(sink) && sink.close) {
      await sink.close();
    }
  }

  /** Send one binary input frame to the configured sink. */
  send(chunk: TerminalBytes): Promise<void> {
    if (!isBytes(chunk)) {
      return Promise.reject(new TypeError("terminal input must be a Uint8Array"));
    }
    if (chunk.byteLength > this._maxInputBytes) {
      const error = new TerminalBoundsError("input", this._maxInputBytes, chunk.byteLength);
      this.reportError(error);
      return Promise.reject(error);
    }
    if (this.pendingWrites >= this._maxPendingWrites) {
      const error = new TerminalBackpressureError(this._maxPendingWrites);
      this.reportError(error);
      return Promise.reject(error);
    }

    const bytes = cloneBytes(chunk);
    const generation = this.lifecycleGeneration;
    const sinkGeneration = this.sinkGeneration;
    const sink = this._sink;
    const isCurrent = () =>
      this.connected && generation === this.lifecycleGeneration && sinkGeneration === this.sinkGeneration;
    this.pendingWrites += 1;
    const task = this.writeTail.then(async () => {
      if (!isCurrent()) {
        throw new TerminalDisconnectedError();
      }
      if (sink === null) {
        this.dispatchInput(bytes);
      } else {
        try {
          await this.writeSink(sink, bytes, false);
        } catch (error) {
          if (!isCurrent()) throw new TerminalDisconnectedError();
          this.reportError(error);
          throw error;
        }
      }
      if (!isCurrent()) throw new TerminalDisconnectedError();
      if (this._broadcastInput) {
        this.dispatchEvent(new CustomEvent<TerminalBytes>("terminal-broadcast-input", { detail: cloneBytes(bytes) }));
        if (!isCurrent()) throw new TerminalDisconnectedError();
        if (this._broadcastSink) {
          try {
            await this.writeSink(this._broadcastSink, bytes, true);
          } catch (error) {
            if (!isCurrent()) throw new TerminalDisconnectedError();
            this.reportError(error);
          }
        }
      }
      if (!isCurrent()) throw new TerminalDisconnectedError();
    });
    this.writeTail = task.catch(() => undefined);
    return task.finally(() => {
      this.pendingWrites -= 1;
    });
  }

  /** Enable or disable broadcast input after an explicit user confirmation. */
  async setBroadcastInput(enabled: boolean, confirm?: TerminalBroadcastConfirmation): Promise<boolean> {
    if (enabled && !this._broadcastInput) {
      if (!confirm) {
        return false;
      }
      try {
        if (!(await confirm())) {
          return false;
        }
      } catch (error) {
        this.reportError(error);
        return false;
      }
    }
    this._broadcastInput = enabled;
    if (this.broadcastIndicator) {
      this.broadcastIndicator.hidden = !enabled;
    }
    this.dispatchEvent(new CustomEvent<boolean>("terminal-broadcast-state", { detail: enabled }));
    return true;
  }

  findNext(term: string, options?: ISearchOptions): boolean {
    if (term.length === 0) {
      return false;
    }
    if (this.searchAddon && this.terminal) {
      return this.searchAddon.findNext(term, options);
    }
    return term.length > 0 && new TextDecoder().decode(this.outputBytes).includes(term);
  }

  findPrevious(term: string, options?: ISearchOptions): boolean {
    if (term.length === 0) {
      return false;
    }
    if (this.searchAddon && this.terminal) {
      return this.searchAddon.findPrevious(term, options);
    }
    return term.length > 0 && new TextDecoder().decode(this.outputBytes).includes(term);
  }

  clearSearch(): void {
    this.searchAddon?.clearDecorations();
    this.terminal?.clearSelection();
  }

  async copySelection(): Promise<boolean> {
    const text = this.terminal?.getSelection() ?? "";
    if (!text) {
      return false;
    }
    return this.writeClipboard(text);
  }

  async copyAll(): Promise<boolean> {
    if (this.terminal) {
      this.terminal.selectAll();
      const text = this.terminal.getSelection();
      this.terminal.clearSelection();
      return this.writeClipboard(text);
    }
    return this.writeClipboard(new TextDecoder().decode(this.outputBytes));
  }

  async paste(): Promise<boolean> {
    const clipboard = this._clipboard ?? (typeof navigator !== "undefined" ? navigator.clipboard : undefined);
    if (!clipboard?.readText) {
      this.reportError(new TerminalError("clipboard", "clipboard read is unavailable"));
      return false;
    }
    try {
      const text = await clipboard.readText();
      if (this.terminal) {
        this.terminal.input(text, true);
      } else {
        await this.send(toBinary(text));
      }
      return true;
    } catch (error) {
      this.reportError(new TerminalError("clipboard", String(error)));
      return false;
    }
  }

  getOutput(): TerminalBytes {
    return cloneBytes(this.outputBytes);
  }

  clearOutput(): void {
    this.outputBytes = new Uint8Array();
    this.terminal?.clear();
    this.renderFallbackOutput();
  }

  scrollToBottom(): void {
    this.terminal?.scrollToBottom();
  }

  private ensureTerminal(): void {
    if (this.terminal || !this.terminalHost || !this.connected) {
      return;
    }
    try {
      const terminal = new XtermTerminal(this.xtermOptions());
      terminal.open(this.terminalHost);
      this.terminal = terminal;
      this.searchAddon = new SearchAddon();
      terminal.loadAddon(this.searchAddon);
      this.fitAddon = new FitAddon();
      terminal.loadAddon(this.fitAddon);
      this.terminalDisposables = [
        terminal.onResize(({ cols, rows }) => {
          this.dispatchEvent(new CustomEvent<TerminalSize>("terminal-resize", { detail: { columns: cols, rows } }));
        }),
        terminal.onData((data) => {
          void this.send(toBinary(data)).catch(() => undefined);
        }),
        terminal.onBinary((data) => {
          void this.send(toLatin1(data)).catch(() => undefined);
        }),
      ];
      this.setFallbackVisibility(false);
      if (this.outputBytes.byteLength > 0) {
        terminal.write(this.outputBytes);
      }
      // The grid follows the element: as many rows and columns as fit.
      if (typeof ResizeObserver === "function") {
        this.resizeObserver = new ResizeObserver(() => this.scheduleFit());
        this.resizeObserver.observe(this);
      }
      this.scheduleFit();
    } catch (error) {
      this.terminal = null;
      this.searchAddon = null;
      this.setFallbackVisibility(true);
      this.reportError(new TerminalError("renderer", `xterm.js could not initialize: ${String(error)}`));
    }
  }

  /** The terminal's grid size, once it has one. */
  get size(): TerminalSize | null {
    return this.terminal ? { columns: this.terminal.cols, rows: this.terminal.rows } : null;
  }

  /** Fits the grid to the element on the next frame; a hidden element keeps its size. */
  private scheduleFit(): void {
    if (typeof requestAnimationFrame !== "function") return;
    cancelAnimationFrame(this.fitFrame);
    this.fitFrame = requestAnimationFrame(() => {
      if (!this.terminal || !this.fitAddon || this.offsetWidth === 0 || this.offsetHeight === 0) return;
      try {
        this.fitAddon.fit();
      } catch {
        // A renderer that has not measured its cells yet is fitted on the next resize.
      }
    });
  }

  private teardownTerminal(): void {
    if (typeof cancelAnimationFrame === "function") cancelAnimationFrame(this.fitFrame);
    this.resizeObserver?.disconnect();
    this.resizeObserver = null;
    this.fitAddon?.dispose();
    this.fitAddon = null;
    for (const disposable of this.terminalDisposables) {
      disposable.dispose();
    }
    this.terminalDisposables = [];
    this.searchAddon?.dispose();
    this.searchAddon = null;
    this.terminal?.dispose();
    this.terminal = null;
    this.setFallbackVisibility(true);
  }

  private xtermOptions(): ITerminalOptions {
    return {
      ...this._profile,
      screenReaderMode: true,
      scrollOnUserInput: true,
      logLevel: "off",
    };
  }

  private applyProfile(): void {
    // The rows rarely fill the element exactly; whatever is left below the last
    // row shows the element's own background, so it takes the theme's.
    this.style.setProperty("--scoplen-terminal-background", this._profile.theme?.background ?? "#111827");
    if (this.terminal) {
      // xterm's options object also exposes constructor-only dimensions such as
      // `cols` and `rows`; copying it back would make a profile update throw.
      this.terminal.options = { ...this._profile };
      // A new font or size changes how many cells fit.
      this.scheduleFit();
    }
  }

  private setFallbackVisibility(fallback: boolean): void {
    if (this.terminalHost) {
      this.terminalHost.hidden = fallback;
    }
    if (this.fallbackOutput) {
      this.fallbackOutput.hidden = !fallback;
    }
    if (fallback) {
      this.renderFallbackOutput();
    }
  }

  private renderFallbackOutput(): void {
    if (this.fallbackOutput) {
      this.fallbackOutput.textContent = new TextDecoder().decode(this.outputBytes);
    }
  }

  private attachSource(): void {
    this.detachSource();
    const source = this._source;
    if (!source || !this.connected) {
      return;
    }
    const abort = new AbortController();
    this.sourceAbort = abort;
    try {
      if (isReadableStream(source)) {
        const reader = source.getReader();
        this.sourceUnsubscribe = () => {
          abort.abort();
          void reader.cancel();
          reader.releaseLock();
        };
        void this.consumeReader(reader, abort.signal);
      } else if (isAsyncIterable(source)) {
        const iterator = source[Symbol.asyncIterator]();
        this.sourceUnsubscribe = () => {
          abort.abort();
          if (iterator.return) {
            void iterator.return();
          }
        };
        void this.consumeIterator(iterator, abort.signal);
      } else {
        this.sourceUnsubscribe = normalizeUnsubscribe(
          source.subscribe((chunk) => this.receiveOutput(chunk), { signal: abort.signal }),
        );
      }
    } catch (error) {
      this.reportError(error);
      this.detachSource();
    }
  }

  private detachSource(): void {
    this.sourceAbort?.abort();
    this.sourceAbort = null;
    const unsubscribe = this.sourceUnsubscribe;
    this.sourceUnsubscribe = null;
    if (unsubscribe) {
      try {
        unsubscribe();
      } catch (error) {
        this.reportError(error);
      }
    }
  }

  private async consumeReader(reader: ReadableStreamDefaultReader<TerminalBytes>, signal: AbortSignal): Promise<void> {
    try {
      while (!signal.aborted) {
        const result = await reader.read();
        if (result.done) {
          this.dispatchEvent(new Event("terminal-complete"));
          break;
        }
        this.receiveOutput(result.value);
      }
    } catch (error) {
      if (!signal.aborted) {
        this.reportError(error);
      }
    } finally {
      reader.releaseLock();
    }
  }

  private async consumeIterator(iterator: AsyncIterator<TerminalBytes>, signal: AbortSignal): Promise<void> {
    try {
      while (!signal.aborted) {
        const result = await iterator.next();
        if (result.done) {
          this.dispatchEvent(new Event("terminal-complete"));
          break;
        }
        this.receiveOutput(result.value);
      }
    } catch (error) {
      if (!signal.aborted) {
        this.reportError(error);
      }
    }
  }

  private receiveOutput(chunk: TerminalBytes): void {
    if (!this.connected) {
      return;
    }
    if (!isBytes(chunk)) {
      this.reportError(new TypeError("terminal output must be a Uint8Array"));
      return;
    }
    const output = cloneBytes(chunk);
    this.dispatchEvent(new CustomEvent<TerminalBytes>("terminal-output", { detail: cloneBytes(output) }));
    const actualOutputBytes = this.outputBytes.byteLength + output.byteLength;
    const exceeded = actualOutputBytes > this._maxOutputBytes;
    if (output.byteLength >= this._maxOutputBytes) {
      this.outputBytes = output.slice(-this._maxOutputBytes);
    } else {
      const merged = new Uint8Array(this.outputBytes.byteLength + output.byteLength);
      merged.set(this.outputBytes);
      merged.set(output, this.outputBytes.byteLength);
      this.outputBytes = merged.byteLength > this._maxOutputBytes ? merged.slice(-this._maxOutputBytes) : merged;
    }
    if (this.terminal) {
      this.terminal.write(output);
    } else {
      this.renderFallbackOutput();
    }
    if (exceeded) {
      this.reportError(new TerminalBoundsError("output", this._maxOutputBytes, actualOutputBytes));
    }
  }

  private async writeSink(sink: TerminalSink, bytes: TerminalBytes, broadcast: boolean): Promise<void> {
    if (typeof sink === "function") {
      await sink(cloneBytes(bytes));
    } else if (isWritableStream(sink)) {
      await (broadcast ? this.getBroadcastSinkWriter(sink) : this.getSinkWriter(sink)).write(cloneBytes(bytes));
    } else {
      await sink.write(cloneBytes(bytes));
    }
  }

  private async writeClipboard(text: string): Promise<boolean> {
    const clipboard = this._clipboard ?? (typeof navigator !== "undefined" ? navigator.clipboard : undefined);
    if (!clipboard?.writeText) {
      this.reportError(new TerminalError("clipboard", "clipboard write is unavailable"));
      return false;
    }
    try {
      await clipboard.writeText(text);
      return true;
    } catch (error) {
      this.reportError(new TerminalError("clipboard", String(error)));
      return false;
    }
  }

  private getSinkWriter(stream: WritableStream<TerminalBytes>): WritableStreamDefaultWriter<TerminalBytes> {
    return (this.sinkWriter ??= stream.getWriter());
  }

  private getBroadcastSinkWriter(stream: WritableStream<TerminalBytes>): WritableStreamDefaultWriter<TerminalBytes> {
    return (this.broadcastSinkWriter ??= stream.getWriter());
  }

  private releaseSinkWriter(): void {
    this.sinkWriter?.releaseLock();
    this.sinkWriter = null;
  }

  private releaseBroadcastSinkWriter(): void {
    this.broadcastSinkWriter?.releaseLock();
    this.broadcastSinkWriter = null;
  }

  private dispatchInput(bytes: TerminalBytes): void {
    this.dispatchEvent(new CustomEvent<TerminalBytes>("terminal-input", { detail: cloneBytes(bytes) }));
  }

  private reportError(error: unknown): void {
    const normalized = error instanceof TerminalError ? error : new TerminalError("stream", String(error));
    this.dispatchEvent(new CustomEvent<TerminalError>("terminal-error", { detail: normalized }));
  }

  private readonly onKeyDown = (event: KeyboardEvent): void => {
    if (cameFromXtermHelper(event) || (this.terminal && event.target !== this)) {
      return;
    }
    if (event.isComposing || event.metaKey) {
      return;
    }
    const bytes = keyBytes(event);
    if (!bytes) {
      return;
    }
    event.preventDefault();
    void this.send(bytes).catch(() => undefined);
  };

  private readonly onCompositionStart = (event: CompositionEvent): void => {
    if (!cameFromXtermHelper(event)) {
      this.ime.start(event.data);
    }
  };

  private readonly onCompositionUpdate = (event: CompositionEvent): void => {
    if (!cameFromXtermHelper(event)) {
      this.ime.update(event.data);
    }
  };

  private readonly onCompositionEnd = (event: CompositionEvent): void => {
    if (!cameFromXtermHelper(event)) {
      this.ime.end(event.data);
    }
  };

  private readonly onCompositionCancel = (event: Event): void => {
    if (!cameFromXtermHelper(event)) {
      this.ime.cancel();
    }
  };

  private readonly onBlur = (event: FocusEvent): void => {
    if (!cameFromXtermHelper(event)) {
      this.ime.blur();
    }
  };
}

function keyBytes(event: KeyboardEvent): TerminalBytes | null {
  const named: Record<string, string> = {
    Enter: "\r",
    Backspace: "\x7f",
    Tab: "\t",
    Escape: "\x1b",
    ArrowUp: "\x1b[A",
    ArrowDown: "\x1b[B",
    ArrowRight: "\x1b[C",
    ArrowLeft: "\x1b[D",
    Home: "\x1b[H",
    End: "\x1b[F",
    Delete: "\x1b[3~",
    PageUp: "\x1b[5~",
    PageDown: "\x1b[6~",
  };
  let value = named[event.key] ?? (event.key.length === 1 && !event.ctrlKey && !event.altKey ? event.key : null);
  if (event.ctrlKey && event.key.length === 1) {
    const code = event.key.toUpperCase().charCodeAt(0);
    if (code >= 64 && code <= 95) {
      value = String.fromCharCode(code & 31);
    }
  }
  if (event.altKey && event.key.length === 1) {
    value = `\x1b${event.key}`;
  }
  return value === null ? null : toBinary(value);
}

export function defineTerminalElement(tagName = TERMINAL_TAG_NAME): typeof ScoplenTerminalElement | undefined {
  if (typeof customElements === "undefined") {
    return undefined;
  }
  const existing = customElements.get(tagName);
  if (existing) {
    return existing as typeof ScoplenTerminalElement;
  }
  customElements.define(tagName, ScoplenTerminalElement);
  return ScoplenTerminalElement;
}

if (typeof customElements !== "undefined" && !customElements.get(TERMINAL_TAG_NAME)) {
  customElements.define(TERMINAL_TAG_NAME, ScoplenTerminalElement);
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface HTMLElementEventMap extends TerminalElementEventMap {}
}
