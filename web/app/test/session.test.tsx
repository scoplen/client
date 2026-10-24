// SPDX-License-Identifier: Apache-2.0
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import type { Channel } from "@tauri-apps/api/core";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { StrictMode, type ComponentProps } from "react";
import { AppearanceProvider } from "@scoplen/ui";
import { I18nProvider } from "../src/i18n";
import { TerminalColorsProvider } from "../src/terminal-colors";
import { SessionTerminal } from "../src/session";
import type {
  PreparationEvent,
  PreparationContext,
  SessionEvent,
  SessionTransferQueueSnapshot,
  SessionTransferItem,
} from "../src/ipc/bindings";
import type { ScoplenTerminalElement } from "@scoplen/terminal";

afterEach(() => clearMocks());

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

function fixture() {
  const calls: Array<{ command: string; args: Record<string, unknown> }> = [];
  let transferState: Partial<SessionTransferQueueSnapshot> = {};
  const connections: Array<{
    sessionId: string;
    messages: Channel<SessionEvent | ArrayBuffer>;
    finish: ReturnType<typeof deferred<null>>;
  }> = [];
  const pending = new Map<string, Array<ReturnType<typeof deferred<unknown>>>>();
  const delay = (command: string) => {
    const reply = deferred<unknown>();
    pending.set(command, [...(pending.get(command) ?? []), reply]);
    return reply;
  };
  mockIPC((command, args) => {
    const payload = (args ?? {}) as Record<string, unknown>;
    calls.push({ command, args: payload });
    if (command === "session_connect") {
      const finish = deferred<null>();
      connections.push({ ...(payload as unknown as (typeof connections)[number]), finish });
      return finish.promise;
    }
    if (command === "session_transfer_queue")
      return (
        pending.get(command)?.shift()?.promise ?? {
          sessionId: payload.sessionId,
          queueId: "queue-1",
          revision: "1",
          capacity: 16,
          outstanding: 0,
          pickerBusy: false,
          blocksFileOperations: false,
          items: [],
          recent: [],
          ...transferState,
        }
      );
    return pending.get(command)?.shift()?.promise ?? null;
  });
  return {
    connections,
    delay,
    setQueue: (state: Partial<SessionTransferQueueSnapshot>) => {
      transferState = state;
    },
    matching: (command: string) => calls.filter((c) => c.command === command),
  };
}

function sessionView(
  locale: "en" | "zh-Hans" = "en",
  active = true,
  onClose = vi.fn(),
  onStateChange = vi.fn(),
  options: Partial<ComponentProps<typeof SessionTerminal>> = {},
) {
  return (
    <AppearanceProvider>
      <TerminalColorsProvider>
        <I18nProvider locale={locale}>
          <SessionTerminal
            profileId="profile-1"
            label="Silent server"
            active={active}
            onClose={onClose}
            onStateChange={onStateChange}
            {...options}
          />
        </I18nProvider>
      </TerminalColorsProvider>
    </AppearanceProvider>
  );
}

async function connect(f: ReturnType<typeof fixture>, index = 0) {
  await waitFor(() => expect(f.connections).toHaveLength(index + 1));
  const connection = f.connections[index]!;
  const channel = connection.messages;
  const start = async (automatic = false) => {
    const transportId = crypto.randomUUID();
    await act(() => channel.onmessage({ kind: "starting", transportId, automatic }));
    return {
      transportId,
      ready: () => act(() => channel.onmessage({ kind: "ready", transportId })),
      prepare: (event: PreparationEvent) => act(() => channel.onmessage({ kind: "preparation", transportId, event })),
      output: (text: string) => act(() => channel.onmessage(outputFrame(transportId, text))),
    };
  };
  return {
    ...connection,
    start,
    emit: (event: SessionEvent) => act(() => channel.onmessage(event)),
    ...(await start()),
  };
}

function outputFrame(transportId: string, text: string): ArrayBuffer {
  const data = new TextEncoder().encode(text);
  const bytes = new Uint8Array(16 + data.length);
  const uuid = transportId.replaceAll("-", "");
  for (let index = 0; index < 16; index++) bytes[index] = Number.parseInt(uuid.slice(index * 2, index * 2 + 2), 16);
  bytes.set(data, 16);
  return bytes.buffer;
}

function context(position = 1): PreparationContext {
  return {
    profileId: `profile-${position}`,
    hostId: `host-${position}`,
    login: `Login ${position}`,
    host: `Host ${position}`,
    username: "ops",
    address: `jump${position}.example`,
    port: 2222,
    position,
    total: 3,
    target: position === 3,
  };
}
function trust(position = 1, changed = false): Extract<PreparationEvent, { kind: "trust" }> {
  return {
    kind: "trust",
    context: context(position),
    promptId: `trust-${position}`,
    hostKey: {
      algorithm: "ssh-ed25519",
      key: `public-${position}`,
      fingerprint: `SHA256:hop-${position}`,
      changed,
      review: null,
      previousSource: null,
    },
  };
}

function verified(position = 1, imported = false): Extract<PreparationEvent, { kind: "verified" }> {
  return {
    kind: "verified",
    context: context(position),
    algorithm: "ssh-ed25519",
    fingerprint: `SHA256:hop-${position}`,
    source: {
      deviceId: "other-device",
      deviceName: "Office Mac",
      acceptedAt: "1792800000000",
      imported,
      current: false,
    },
  };
}
function passphrase(position = 1, incorrect = false): PreparationEvent {
  return { kind: "passphrase", context: context(position), promptId: `pass-${position}-${incorrect}`, incorrect };
}

it("reserves once in StrictMode, routes input/resize to the exact attempt, and closes", async () => {
  const f = fixture();
  const close = vi.fn();
  const view = render(<StrictMode>{sessionView("en", true, close)}</StrictMode>);
  const c = await connect(f);
  const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  await act(() => terminal.dispatchEvent(new CustomEvent("terminal-resize", { detail: { columns: 120, rows: 40 } })));
  expect(f.matching("session_resize")).toHaveLength(0);
  await c.ready();
  expect(screen.getByRole("status").textContent).toContain("Connected");
  await waitFor(() =>
    expect(f.matching("session_resize").at(-1)?.args).toMatchObject({
      sessionId: c.sessionId,
      transportId: c.transportId,
      columns: 120,
      rows: 40,
    }),
  );
  await terminal.send(new Uint8Array([108, 115, 13]));
  expect(f.matching("session_input").at(-1)?.args).toMatchObject({
    sessionId: c.sessionId,
    transportId: c.transportId,
    data: [108, 115, 13],
  });
  expect(f.connections).toHaveLength(1);
  await userEvent.click(screen.getByRole("button", { name: "Close session" }));
  expect(close).not.toHaveBeenCalled();
  expect(f.matching("session_stop_reconnecting")).toHaveLength(1);
  await c.emit({ kind: "closed" });
  await waitFor(() => expect(close).toHaveBeenCalledOnce());
  expect(f.matching("session_close_transport").at(-1)?.args.sessionId).toBe(c.sessionId);
});

it("opens Files only while connected and restores focus after closing its panel", async () => {
  const f = fixture();
  const listing = f.delay("session_list_files");
  render(sessionView());
  const c = await connect(f);
  expect(screen.queryByRole("button", { name: "Open files" })).toBeNull();
  await c.ready();
  const toggle = screen.getByRole("button", { name: "Open files" });
  await userEvent.click(toggle);
  expect(toggle.getAttribute("aria-pressed")).toBe("true");
  await waitFor(() => expect(f.matching("session_list_files")).toHaveLength(1));
  expect(f.matching("session_list_files")[0]?.args).toMatchObject({
    sessionId: c.sessionId,
    transportId: c.transportId,
    path: [46],
  });
  await userEvent.click(
    within(screen.getByRole("region", { name: "Files" })).getByRole("button", { name: "Close files" }),
  );
  expect(document.activeElement).toBe(toggle);
  expect(toggle.getAttribute("aria-pressed")).toBe("false");
  expect(f.matching("session_cancel_file_operation")[0]?.args).toMatchObject({
    sessionId: c.sessionId,
    transportId: c.transportId,
    operationId: f.matching("session_list_files")[0]?.args.operationId,
  });
  await act(() => listing.resolve(null));
});

it("starts Files at home on a replacement transport and ignores old directory results", async () => {
  const f = fixture();
  const home = f.delay("session_list_files");
  render(sessionView());
  const connection = await connect(f);
  await connection.ready();
  await userEvent.click(screen.getByRole("button", { name: "Open files" }));
  await waitFor(() => expect(f.matching("session_list_files")).toHaveLength(1));
  const logs = [46, 47, 108, 111, 103, 115];
  await act(() => home.resolve({ entries: [{ name: "logs", path: logs, kind: "directory", sizeBytes: null }] }));

  const oldDirectory = f.delay("session_list_files");
  await userEvent.click(await screen.findByRole("button", { name: "logs" }));
  await waitFor(() => expect(f.matching("session_list_files")).toHaveLength(2));
  expect(f.matching("session_list_files")[1]?.args.path).toEqual(logs);
  await connection.emit({ kind: "retrying", attempt: 1, delaySeconds: 1, error: "Network connection lost" });
  const replacement = await connection.start(true);
  await replacement.ready();
  expect(screen.getByRole("button", { name: "Open files" }).getAttribute("aria-pressed")).toBe("false");

  const newHome = f.delay("session_list_files");
  await userEvent.click(screen.getByRole("button", { name: "Open files" }));
  await waitFor(() => expect(f.matching("session_list_files")).toHaveLength(3));
  expect(f.matching("session_list_files")[2]?.args).toMatchObject({ transportId: replacement.transportId, path: [46] });
  await act(() =>
    newHome.resolve({ entries: [{ name: "fresh.bin", path: [46, 47, 102], kind: "file", sizeBytes: "1" }] }),
  );
  await act(() =>
    oldDirectory.resolve({ entries: [{ name: "old.bin", path: [46, 47, 111], kind: "file", sizeBytes: "1" }] }),
  );
  expect(screen.getByRole("button", { name: "Download fresh.bin" })).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Download old.bin" })).toBeNull();
});

it("retains a Rust-owned transfer when Files hides and a transport is replaced", async () => {
  const f = fixture();
  const oldHome = f.delay("session_list_files");
  const upload = f.delay("session_enqueue_upload");
  render(sessionView());
  const connection = await connect(f);
  await connection.ready();
  await userEvent.click(screen.getByRole("button", { name: "Open files" }));
  await waitFor(() => expect(f.matching("session_list_files")).toHaveLength(1));
  await act(() => oldHome.resolve({ entries: [] }));
  await userEvent.click(screen.getByRole("button", { name: "Upload file" }));
  expect(f.matching("session_enqueue_upload")[0]?.args).toMatchObject({
    transportId: connection.transportId,
    directoryPath: [46],
    locale: "en",
  });
  await act(() =>
    upload.resolve({ status: "queued", queueId: "queue-1", itemId: "item-1", executionId: "execution-1" }),
  );
  await userEvent.click(
    within(screen.getByRole("region", { name: "Files" })).getByRole("button", { name: "Close files" }),
  );
  expect(f.matching("session_cancel_transfer")).toHaveLength(0);
  f.setQueue({ revision: "2", outstanding: 1, items: [unknownTransfer(connection.transportId)] });
  expect((await screen.findByRole("alert")).textContent).toContain("A transfer result is unknown");
  await connection.emit({ kind: "retrying", attempt: 1, delaySeconds: 1, error: "Network connection lost" });
  const replacement = await connection.start(true);
  await replacement.ready();
  const home = f.delay("session_list_files");
  await userEvent.click(screen.getByRole("button", { name: "Review transfers" }));
  await waitFor(() => expect(f.matching("session_list_files")).toHaveLength(2));
  await act(() => home.resolve({ entries: [] }));
  expect(screen.getByText("Save result unknown")).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: "Dismiss unknown-result reminder for backup.bin" }));
  expect(f.matching("session_acknowledge_transfer")[0]?.args).toMatchObject({
    sessionId: connection.sessionId,
    queueId: "queue-1",
    itemId: "item-1",
    executionId: "execution-1",
  });
  expect(screen.queryByText("Saved")).toBeNull();
  expect(f.matching("session_enqueue_upload")).toHaveLength(1);
  expect(f.matching("session_cancel_transfer")).toHaveLength(0);
});

it("keeps an uncertain remote deletion visible after Files closes without replaying it", async () => {
  const f = fixture();
  const listing = f.delay("session_list_files");
  const deletion = f.delay("session_delete_remote_entry");
  render(sessionView());
  const connection = await connect(f);
  await connection.ready();
  await userEvent.click(screen.getByRole("button", { name: "Open files" }));
  await waitFor(() => expect(f.matching("session_list_files")).toHaveLength(1));
  const remotePath = [46, 47, 255, 46, 98, 105, 110];
  await act(() => listing.resolve({ entries: [{ name: "raw.bin", path: remotePath, kind: "file", sizeBytes: "4" }] }));
  await userEvent.click(screen.getByRole("button", { name: "Delete raw.bin" }));
  await waitFor(() => expect(f.matching("session_delete_remote_entry")).toHaveLength(1));
  expect(f.matching("session_delete_remote_entry")[0]?.args).toMatchObject({
    sessionId: connection.sessionId,
    transportId: connection.transportId,
    directoryPath: [46],
    entryPath: remotePath,
    locale: "en",
  });
  await userEvent.click(
    within(screen.getByRole("region", { name: "Files" })).getByRole("button", { name: "Close files" }),
  );
  await act(() => deletion.resolve({ status: "unknown", message: null }));
  expect(screen.getByRole("alert").textContent).toContain("remote file operations have an unknown result");
  expect(f.matching("session_delete_remote_entry")).toHaveLength(1);
  await userEvent.click(screen.getByRole("button", { name: "Dismiss" }));
  expect(screen.queryByRole("alert")).toBeNull();
});

it("allows retained unknown download results to be reviewed after the connection ends", async () => {
  const f = fixture();
  render(sessionView());
  const connection = await connect(f);
  await connection.ready();
  f.setQueue({ revision: "2", outstanding: 1, items: [unknownTransfer(connection.transportId, "download")] });
  await screen.findByRole("button", { name: "Review transfers" });
  await connection.emit({ kind: "closed" });
  await userEvent.click(screen.getByRole("button", { name: "Review transfers" }));
  expect(screen.getByText("Save result unknown")).toBeTruthy();
  expect(screen.getByRole("button", { name: "Upload file" }).hasAttribute("disabled")).toBe(true);
  expect(f.matching("session_list_files")).toHaveLength(0);
  expect(f.matching("session_enqueue_download")).toHaveLength(0);
});

it("keeps logical transfer identity when manually reconnecting an ended run", async () => {
  const f = fixture();
  render(sessionView());
  const connection = await connect(f);
  await connection.ready();
  f.setQueue({ revision: "2", outstanding: 1, items: [unknownTransfer(connection.transportId)] });
  await screen.findByRole("button", { name: "Review transfers" });
  await act(() => connection.finish.resolve(null));
  const closes = f.matching("session_close_transport").length;
  await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
  const replacement = await connect(f, 1);
  expect(replacement.sessionId).toBe(connection.sessionId);
  await replacement.ready();
  expect(f.matching("session_close_transport")).toHaveLength(closes);
  expect(screen.getByRole("alert").textContent).toContain("A transfer result is unknown");
});

it("closes the logical session when a fallback reconnect and unmount share one batch", async () => {
  const f = fixture();
  const view = render(sessionView());
  const connection = await connect(f);
  await connection.ready();
  await act(() => connection.finish.resolve(null));
  const closes = f.matching("session_close_transport").length;
  const reconnect = screen.getByRole("button", { name: "Reconnect" });
  act(() => {
    reconnect.click();
    view.unmount();
  });
  expect(f.matching("session_close_transport")).toHaveLength(closes + 1);
  expect(f.matching("session_close_transport").at(-1)?.args.sessionId).toBe(connection.sessionId);
  expect(f.matching("session_reserve_transport")).toHaveLength(1);
});

it("retains cleanup warnings after a known terminal result leaves the outstanding queue", async () => {
  const f = fixture();
  render(sessionView());
  const connection = await connect(f);
  await connection.ready();
  f.setQueue({
    revision: "2",
    recent: [
      { ...unknownTransfer(connection.transportId), state: "failed", canAcknowledge: false, stagingMayRemain: true },
    ],
  });
  expect((await screen.findByRole("alert")).textContent).toContain("Temporary file cleanup could not be confirmed");
  expect(screen.getByRole("button", { name: "Review transfers" })).toBeTruthy();
  expect(f.matching("session_enqueue_upload")).toHaveLength(0);
});

it("reports a native selection refused after Files unmounts during reconnect", async () => {
  const f = fixture();
  const home = f.delay("session_list_files");
  const picker = f.delay("session_enqueue_upload");
  render(sessionView());
  const connection = await connect(f);
  await connection.ready();
  await userEvent.click(screen.getByRole("button", { name: "Open files" }));
  await waitFor(() => expect(f.matching("session_list_files")).toHaveLength(1));
  await act(() => home.resolve({ entries: [] }));
  await userEvent.click(screen.getByRole("button", { name: "Upload file" }));
  await connection.emit({ kind: "retrying", attempt: 1, delaySeconds: 1, error: "Network connection lost" });
  const replacement = await connection.start(true);
  await replacement.ready();
  await act(() => picker.reject("transportEnded"));
  expect(screen.getByRole("alert").textContent).toContain("SSH connection ended");
  expect(f.matching("session_enqueue_upload")).toHaveLength(1);
  expect(f.matching("session_cancel_transfer")).toHaveLength(0);
  expect(screen.getByRole("button", { name: "Review transfers" })).toBeTruthy();
});

it("fences a delayed picker error after a newer transport has added a transfer", async () => {
  const f = fixture();
  const oldHome = f.delay("session_list_files");
  const oldPicker = f.delay("session_enqueue_upload");
  render(sessionView());
  const connection = await connect(f);
  await connection.ready();
  await userEvent.click(screen.getByRole("button", { name: "Open files" }));
  await waitFor(() => expect(f.matching("session_list_files")).toHaveLength(1));
  await act(() => oldHome.resolve({ entries: [] }));
  await userEvent.click(screen.getByRole("button", { name: "Upload file" }));
  await connection.emit({ kind: "retrying", attempt: 1, delaySeconds: 1, error: "Network connection lost" });
  const replacement = await connection.start(true);
  await replacement.ready();
  const home = f.delay("session_list_files");
  const picker = f.delay("session_enqueue_upload");
  await userEvent.click(screen.getByRole("button", { name: "Open files" }));
  await waitFor(() => expect(f.matching("session_list_files")).toHaveLength(2));
  await act(() => home.resolve({ entries: [] }));
  await userEvent.click(screen.getByRole("button", { name: "Upload file" }));
  await act(() => picker.resolve({ status: "queued", queueId: "queue-1", itemId: "new", executionId: "new" }));
  await act(() => oldPicker.reject("transportEnded"));
  await userEvent.click(
    within(screen.getByRole("region", { name: "Files" })).getByRole("button", { name: "Close files" }),
  );
  expect(screen.queryByRole("alert")).toBeNull();
  expect(f.matching("session_enqueue_upload")).toHaveLength(2);
  expect(f.matching("session_enqueue_upload")[1]?.args.transportId).toBe(replacement.transportId);
  expect(f.matching("session_cancel_transfer")).toHaveLength(0);
});

function unknownTransfer(transportId: string, direction: "upload" | "download" = "upload"): SessionTransferItem {
  return {
    itemId: "item-1",
    executionId: "execution-1",
    transportId,
    name: "backup.bin",
    direction,
    state: "unknown",
    transferredBytes: "4",
    totalBytes: "4",
    canCancel: false,
    canPause: false,
    canResume: false,
    canAcknowledge: true,
    issue: "publicationUnknown",
    stagingMayRemain: false,
  };
}

describe("saved terminal output", () => {
  beforeEach(() => {
    vi.stubGlobal("matchMedia", () => ({
      matches: false,
      addListener() {},
      removeListener() {},
      addEventListener() {},
      removeEventListener() {},
    }));
  });
  afterEach(() => vi.unstubAllGlobals());
  afterEach(() => vi.restoreAllMocks());

  function checkpointTimer() {
    const interval = vi.spyOn(globalThis, "setInterval");
    return () =>
      act(() => {
        const tick = interval.mock.calls.filter(([, delay]) => delay === 5_000).at(-1)?.[0];
        expect(tick).toBeTypeOf("function");
        (tick as () => void)();
      });
  }

  it("opens read-only offline even in StrictMode and connects only after explicit Reconnect", async () => {
    const f = fixture();
    const view = render(
      <StrictMode>
        {sessionView("en", true, vi.fn(), vi.fn(), {
          savedOutput: { version: 1, columns: 90, rows: 30, data: "retained output\x1b[6n" },
        })}
      </StrictMode>,
    );
    const element = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
    await waitFor(() => expect(element.findNext("retained output")).toBe(true));
    expect(screen.getByRole("status").textContent).toContain("Offline, read-only");
    await element.send(new TextEncoder().encode("must not send"));
    expect(f.matching("session_input")).toHaveLength(0);
    expect(f.matching("session_reserve_transport")).toHaveLength(0);
    expect(f.connections).toHaveLength(0);
    await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
    const c = await connect(f);
    await c.prepare(trust());
    expect(screen.getByRole("dialog")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
    await c.ready();
    expect(element.findNext("retained output")).toBe(true);
    expect(f.matching("session_input")).toHaveLength(0);
  });

  it("awaits final processed output after Stop before permitting a close", async () => {
    const f = fixture();
    let close!: (discard?: boolean) => Promise<boolean>;
    render(
      sessionView("en", true, vi.fn(), vi.fn(), {
        registerClose: (controller) => {
          close = controller;
          return () => undefined;
        },
      }),
    );
    const c = await connect(f);
    await c.ready();
    await c.output("saved before stop\r\n");
    let completion!: Promise<boolean>;
    await act(() => {
      completion = close();
    });
    expect(f.matching("session_save_output")).toHaveLength(0);
    await c.output("final tail\r\n");
    await c.emit({ kind: "closed" });
    expect(await completion).toBe(true);
    const checkpoint = f.matching("session_save_output")[0]!;
    expect(checkpoint.args).toMatchObject({ sessionId: c.sessionId, transportId: c.transportId, sequence: 1 });
    expect((checkpoint.args.snapshot as { data: string }).data).toContain("final tail");
    expect(f.matching("session_close_transport")).toHaveLength(0);
  });

  it("keeps the tab on a save failure and offers explicit close without saving", async () => {
    const f = fixture();
    let close!: (discard?: boolean) => Promise<boolean>;
    const onClose = vi.fn();
    render(
      sessionView("zh-Hans", true, onClose, vi.fn(), {
        registerClose: (controller) => {
          close = controller;
          return () => undefined;
        },
      }),
    );
    const c = await connect(f);
    await c.ready();
    await c.output("still visible");
    await c.emit({ kind: "closed" });
    const failure = f.delay("session_save_output");
    void failure.promise.catch(() => undefined);
    failure.reject("storage");
    let result = true;
    await act(async () => {
      result = await close();
    });
    expect(result).toBe(false);
    expect(screen.getByRole("alert").textContent).toContain("之前保存的内容仍会保留");
    expect(onClose).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "不保存并关闭" }));
    expect(onClose).toHaveBeenCalledWith(true);
    await act(async () => {
      expect(await close(true)).toBe(true);
    });
    expect(f.matching("session_save_output")).toHaveLength(1);
  });

  it.each(["stop failure", "drain timeout"])("can explicitly discard and close after a %s", async (failure) => {
    const f = fixture();
    const stop = failure === "stop failure" ? f.delay("session_stop_reconnecting") : null;
    const timers = vi.spyOn(globalThis, "setTimeout");
    let close!: (discard?: boolean) => Promise<boolean>;
    const onClose = vi.fn(async (discard?: boolean) => {
      if (await close(discard)) view.unmount();
    });
    const view = render(
      sessionView("en", true, onClose, vi.fn(), {
        registerClose: (controller) => {
          close = controller;
          return () => undefined;
        },
      }),
    );
    const c = await connect(f);
    await c.ready();
    await c.output("output retained after a failed close");
    let completion!: Promise<boolean>;
    await act(() => {
      completion = close();
    });
    await act(async () => {
      if (stop) stop.reject("stop failed");
      else {
        const timeout = timers.mock.calls.find(([, delay]) => delay === 10_000)?.[0];
        expect(timeout).toBeTypeOf("function");
        (timeout as () => void)();
      }
      expect(await completion).toBe(false);
    });
    expect(screen.getByRole("alert").textContent).toContain("close without saving");
    await userEvent.click(screen.getByRole("button", { name: "Close without saving" }));
    await waitFor(() => expect(view.container.querySelector("scoplen-terminal")).toBeNull());
    expect(onClose).toHaveBeenCalledWith(true);
    expect(f.matching("session_stop_reconnecting")).toHaveLength(1);
    expect(f.matching("session_save_output")).toHaveLength(0);
    expect(f.matching("session_close_transport").at(-1)?.args.sessionId).toBe(c.sessionId);
  });

  it("ignores a delayed checkpoint failure after replacing an ended run", async () => {
    const tick = checkpointTimer();
    const f = fixture();
    const pending = f.delay("session_save_output");
    const view = render(sessionView());
    const first = await connect(f);
    await first.ready();
    await first.output("first logical session");
    await tick();
    await waitFor(() => expect(f.matching("session_save_output")).toHaveLength(1));
    await tick();
    await act(() => first.finish.resolve(null));
    await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
    const second = await connect(f, 1);
    expect(second.sessionId).toBe(first.sessionId);
    expect(second.transportId).not.toBe(first.transportId);
    await second.ready();
    await second.output("new logical session");
    await act(() => pending.reject("staleCheckpoint"));
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByRole("status").textContent).toContain("Connected");
    expect(f.matching("session_save_output")).toHaveLength(1);
    await tick();
    await waitFor(() => expect(f.matching("session_save_output")).toHaveLength(2));
    expect(f.matching("session_save_output").at(-1)?.args).toMatchObject({
      sessionId: second.sessionId,
      transportId: second.transportId,
    });
    const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
    await terminal.send(new Uint8Array([13]));
    expect(f.matching("session_input").at(-1)?.args.transportId).toBe(second.transportId);
  });

  it.each(["logical session", "automatic transport"])(
    "ignores an old renderer failure in a new %s",
    async (replacement) => {
      const tick = checkpointTimer();
      const f = fixture();
      const view = render(sessionView());
      const first = await connect(f);
      await first.ready();
      await first.output("old renderer output");
      const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
      const pending = deferred<Awaited<ReturnType<typeof terminal.serialize>>>();
      vi.spyOn(terminal, "serialize").mockImplementationOnce(() => pending.promise);
      await tick();
      let second: Awaited<ReturnType<typeof first.start>>;
      if (replacement === "logical session") {
        await act(() => first.finish.resolve(null));
        await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
        second = await connect(f, 1);
      } else {
        await first.emit({ kind: "retrying", attempt: 1, delaySeconds: 1, error: "Network connection lost" });
        second = await first.start(true);
      }
      await second.ready();
      await second.output("new renderer output");
      await act(() => pending.reject(new Error("old renderer disconnected")));
      expect(screen.queryByRole("alert")).toBeNull();
      expect(screen.getByRole("status").textContent).toContain("Connected");
      expect(f.matching("session_save_output")).toHaveLength(0);
      await tick();
      await waitFor(() => expect(f.matching("session_save_output")).toHaveLength(1));
      expect(f.matching("session_save_output")[0]?.args.transportId).toBe(second.transportId);
    },
  );

  it("ignores an old checkpoint rejection after an automatic transport replacement", async () => {
    const tick = checkpointTimer();
    const f = fixture();
    const pending = f.delay("session_save_output");
    render(sessionView());
    const first = await connect(f);
    await first.ready();
    await first.output("first transport");
    await tick();
    await waitFor(() => expect(f.matching("session_save_output")).toHaveLength(1));
    await first.emit({ kind: "retrying", attempt: 1, delaySeconds: 1, error: "Network connection lost" });
    const second = await first.start(true);
    await second.ready();
    await second.output("second transport");
    await act(() => pending.reject("staleCheckpoint"));
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByRole("status").textContent).toContain("Connected");
    await tick();
    await waitFor(() => expect(f.matching("session_save_output")).toHaveLength(2));
    expect(f.matching("session_save_output").at(-1)?.args.transportId).toBe(second.transportId);
  });
});

it.each(["completion", "failure"])("ignores old source %s while a replacement is active", async (ending) => {
  const f = fixture();
  const view = render(sessionView());
  const first = await connect(f);
  await first.ready();
  const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  const source = terminal.source;
  act(() => {
    terminal.source = source;
  });
  const second = await connect(f, 1);
  await second.ready();
  await act(() => (ending === "completion" ? first.finish.resolve(null) : first.finish.reject("old failure")));
  await second.output("current output");
  expect(new TextDecoder().decode(terminal.getOutput())).toBe("current output");
  expect(screen.getByRole("status").textContent).toContain("Connected");
  expect(screen.queryByRole("alert")).toBeNull();
});

it.each(["connecting", "connected"])("keeps the transport when locale changes while %s", async (state) => {
  const f = fixture();
  const view = render(sessionView());
  const c = await connect(f);
  if (state === "connected") await c.ready();
  view.rerender(sessionView("zh-Hans"));
  expect(screen.getByRole("status").textContent).toContain(state === "connected" ? "已连接" : "正在连接");
  expect(f.connections).toHaveLength(1);
  expect(f.matching("session_close_transport")).toHaveLength(0);
});

it.each(["closed", "failed"] as const)(
  "reconnects a %s attempt with retained output and no stale input/output",
  async (ending) => {
    const f = fixture();
    const view = render(sessionView());
    const c = await connect(f);
    const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
    await c.ready();
    await c.output("first session\r\n");
    await c.emit(
      ending === "closed" ? { kind: "closed" } : { kind: "failed", error: "disconnected", exhausted: false },
    );
    await c.ready();
    await c.output("stale");
    expect(screen.getByRole("status").textContent).toContain(ending);
    const button = screen.getByRole("button", { name: "Reconnect" });
    act(() => {
      button.click();
      button.click();
    });
    expect(f.matching("session_retry_transport")).toHaveLength(1);
    const second = await c.start();
    expect(second.transportId).not.toBe(c.transportId);
    expect(f.connections).toHaveLength(1);
    expect(view.container.querySelector("scoplen-terminal")).toBe(terminal);
    await c.prepare(trust());
    await c.output("stale");
    expect(screen.queryByRole("dialog")).toBeNull();
    await second.prepare(trust(2, true));
    expect(screen.getByRole("heading", { name: "Host key changed" })).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
    await second.ready();
    await second.output("second");
    expect(new TextDecoder().decode(terminal.getOutput())).toBe("first session\r\nsecond");
    await terminal.send(new Uint8Array([13]));
    expect(f.matching("session_input").at(-1)?.args).toMatchObject({
      sessionId: c.sessionId,
      transportId: second.transportId,
    });
  },
);

it("keeps the first frame delivered immediately after starting on the same channel", async () => {
  const f = fixture();
  const view = render(sessionView());
  await waitFor(() => expect(f.connections).toHaveLength(1));
  const channel = f.connections[0]!.messages;
  const transportId = crypto.randomUUID();
  await act(() => {
    channel.onmessage({ kind: "starting", transportId, automatic: false });
    channel.onmessage(outputFrame(transportId, "first prompt"));
    channel.onmessage({ kind: "ready", transportId });
  });
  const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  expect(new TextDecoder().decode(terminal.getOutput())).toBe("first prompt");
});

it("renders automatic backoff and waits for Stop cleanup before allowing manual retry", async () => {
  const f = fixture();
  const view = render(sessionView());
  const c = await connect(f);
  await c.ready();
  await c.output("old output");
  await c.emit({ kind: "retrying", attempt: 2, delaySeconds: 2, error: "Network connection lost" });
  expect(screen.getByRole("status").textContent).toContain("Retry 2 of 5 in 2 seconds");
  expect(screen.getByText("Reconnecting starts a new remote shell. Your terminal output stays here.")).toBeTruthy();
  await c.output("stale");
  const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  expect(new TextDecoder().decode(terminal.getOutput())).toBe("old output");
  await userEvent.click(screen.getByRole("button", { name: "Stop reconnecting" }));
  expect(f.matching("session_stop_reconnecting")).toHaveLength(1);
  expect(screen.getByRole("button", { name: "Reconnect" })).toHaveProperty("disabled", true);
  await c.ready();
  expect(screen.getByRole("status").textContent).toContain("closed");
  await c.emit({ kind: "closed" });
  expect(screen.getByRole("button", { name: "Reconnect" })).toHaveProperty("disabled", false);
});

it("reports a failed Stop intent without leaving controls stuck", async () => {
  const f = fixture();
  const pending = f.delay("session_stop_reconnecting");
  render(sessionView());
  const c = await connect(f);
  await c.emit({ kind: "retrying", attempt: 1, delaySeconds: 1, error: "Network connection lost" });
  await userEvent.click(screen.getByRole("button", { name: "Stop reconnecting" }));
  await act(() => pending.reject("session control unavailable"));
  expect(screen.getByRole("alert").textContent).toBe("session control unavailable");
  expect(screen.getByRole("button", { name: "Reconnect" })).toHaveProperty("disabled", false);
});

it.each(["reservation", "manager"])("recreates a failed %s and retains the terminal", async (failure) => {
  const f = fixture();
  const pending = failure === "reservation" ? f.delay("session_reserve_transport") : null;
  const view = render(sessionView());
  const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  if (pending) {
    await waitFor(() => expect(f.matching("session_reserve_transport")).toHaveLength(1));
    await act(() => pending.reject("reservation failed"));
  } else {
    const c = await connect(f);
    await c.ready();
    await c.output("keep this");
    await act(() => c.finish.reject("manager failed"));
  }
  const oldId = f.matching("session_reserve_transport")[0]!.args.sessionId;
  await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
  await waitFor(() => expect(f.matching("session_reserve_transport")).toHaveLength(2));
  expect(f.matching("session_reserve_transport")[1]?.args.sessionId).toBe(oldId);
  expect(f.matching("session_retry_transport")).toHaveLength(0);
  expect(view.container.querySelector("scoplen-terminal")).toBe(terminal);
  if (!pending) expect(new TextDecoder().decode(terminal.getOutput())).toBe("keep this");
});

it("closes a late reservation ACK after tab closure without starting SSH", async () => {
  const f = fixture();
  const pending = f.delay("session_reserve_transport");
  const view = render(sessionView());
  await waitFor(() => expect(f.matching("session_reserve_transport")).toHaveLength(1));
  const oldId = f.matching("session_reserve_transport")[0]!.args.sessionId;
  view.unmount();
  const count = f.matching("session_close_transport").length;
  await act(() => pending.resolve(null));
  expect(f.connections).toHaveLength(0);
  expect(f.matching("session_close_transport")).toHaveLength(count + 1);
  expect(f.matching("session_close_transport").at(-1)?.args.sessionId).toBe(oldId);
});

it("accepts each hop's exact current prompt without renderer-supplied trust data", async () => {
  const f = fixture();
  render(sessionView());
  const c = await connect(f);
  await c.prepare({ kind: "progress", context: context(2), phase: "connecting" });
  expect(screen.getByText("Jump host · 2 / 3")).toBeTruthy();
  for (const position of [1, 2, 3]) {
    await c.prepare(trust(position, position === 2));
    expect(screen.getByText(`Host ${position} · Login ${position}`)).toBeTruthy();
    expect(screen.getByText(`ops@jump${position}.example:2222`)).toBeTruthy();
    expect(screen.getByText(`SHA256:hop-${position}`)).toBeTruthy();
    if (position === 2) expect(screen.getByRole("heading", { name: "Host key changed" })).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
    expect(f.matching("session_respond").at(-1)?.args).toEqual({
      sessionId: c.sessionId,
      promptId: `trust-${position}`,
      intent: { kind: "acceptHostKey" },
    });
  }
  await c.ready();
  expect(screen.getByRole("status").textContent).toContain("Connected");
});

it("shows each verified source and time without another prompt and fences old-attempt details", async () => {
  const f = fixture();
  const view = render(sessionView());
  const c = await connect(f);
  await c.prepare(verified(1));
  await c.prepare(verified(2, true));
  await c.ready();
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(f.matching("session_respond")).toHaveLength(0);
  await userEvent.click(screen.getByRole("button", { name: "Connection details" }));
  expect(screen.getByRole("heading", { name: "Connection details" })).toBeTruthy();
  expect(screen.getAllByText("Office Mac")).toHaveLength(2);
  expect(screen.getByText("Manually confirmed")).toBeTruthy();
  expect(screen.getByText("Imported from known_hosts")).toBeTruthy();
  expect(view.baseElement.querySelector("time")?.getAttribute("datetime")).toBe(new Date(1792800000000).toISOString());
  await userEvent.keyboard("{Escape}");
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(document.activeElement).toBe(screen.getByRole("button", { name: "Connection details" }));
  await c.emit({ kind: "closed" });
  await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
  const next = await c.start();
  await c.prepare(verified(3));
  expect(screen.queryByRole("button", { name: "Connection details" })).toBeNull();
  await next.prepare(verified(3));
  await userEvent.click(screen.getByRole("button", { name: "Connection details" }));
  expect(screen.getByText("SHA256:hop-3")).toBeTruthy();
  expect(screen.queryByText("SHA256:hop-1")).toBeNull();
});

it.each(["revokedDevice", "unverifiedSource"] as const)(
  "requires a fresh exact-key confirmation for %s",
  async (review) => {
    const f = fixture();
    render(sessionView());
    const c = await connect(f);
    const prompt = trust();
    prompt.hostKey.review = review;
    prompt.hostKey.previousSource = review === "revokedDevice" ? verified().source : null;
    await c.prepare(prompt);
    expect(screen.getByRole("heading", { name: "Confirm this host key again" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Host key changed" })).toBeNull();
    if (review === "revokedDevice") {
      expect(screen.getByText("Office Mac")).toBeTruthy();
      expect(screen.getByText(/The device that trusted this key has been revoked/)).toBeTruthy();
    } else {
      expect(screen.queryByText("Office Mac")).toBeNull();
      expect(screen.getByText(/This saved key has no verified source/)).toBeTruthy();
    }
    expect(f.matching("session_respond")).toHaveLength(0);
    await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
    expect(f.matching("session_respond").at(-1)?.args).toEqual({
      sessionId: c.sessionId,
      promptId: "trust-1",
      intent: { kind: "acceptHostKey" },
    });
  },
);

it("clears one-time passphrases, handles incorrect replies, and asks again on a fresh attempt", async () => {
  const f = fixture();
  render(sessionView());
  const c = await connect(f);
  await c.prepare(passphrase());
  await userEvent.click(screen.getByRole("button", { name: "Unlock and connect" }));
  expect(screen.getByText("Enter the key passphrase to connect.")).toBeTruthy();
  for (const [value, incorrect] of [
    ["wrong-disposable", false],
    ["correct-disposable", true],
  ] as const) {
    if (incorrect) {
      await c.prepare(passphrase(1, true));
      expect(screen.getByText("That passphrase did not unlock the key. Check it and try again.")).toBeTruthy();
    }
    const input = screen.getByLabelText("Key passphrase") as HTMLInputElement;
    expect(input.value).toBe("");
    await userEvent.type(input, value);
    await userEvent.keyboard("{Enter}");
    expect(input.value).toBe("");
    expect(f.matching("session_respond").at(-1)?.args).toMatchObject({
      promptId: `pass-1-${incorrect}`,
      intent: { kind: "passphrase", value },
    });
  }
  await c.emit({ kind: "failed", error: "connection lost", exhausted: false });
  await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
  const second = await c.start();
  await second.prepare(passphrase(3));
  await c.prepare(passphrase(1, true));
  expect(screen.getByText("Host 3 · Login 3")).toBeTruthy();
  expect((screen.getByLabelText("Key passphrase") as HTMLInputElement).value).toBe("");
});

it("fences delayed prompt responses and duplicate trust intents", async () => {
  const f = fixture();
  const first = f.delay("session_respond");
  render(sessionView());
  const c = await connect(f);
  await c.prepare(trust());
  const button = screen.getByRole("button", { name: "Trust and connect" });
  act(() => {
    button.click();
    button.click();
  });
  expect(f.matching("session_respond")).toHaveLength(1);
  await c.prepare(trust(2));
  await act(() => first.resolve(null));
  expect(screen.getByText("SHA256:hop-2")).toBeTruthy();
  const rejected = f.delay("session_respond");
  await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
  await act(() => rejected.reject("store unavailable"));
  expect(screen.getByRole("alert").textContent).toBe("store unavailable");
  const pending = f.delay("session_respond");
  await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
  await userEvent.keyboard("{Escape}");
  await act(() => pending.resolve(null));
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(screen.getByRole("status").textContent).toContain("closed");
});

it.each(["trust", "passphrase"])(
  "cancels a %s prompt and waits for cleanup without destroying its logical session",
  async (kind) => {
    const f = fixture();
    render(sessionView());
    const c = await connect(f);
    await c.prepare(kind === "trust" ? trust() : passphrase());
    await userEvent.click(screen.getAllByRole("button", { name: "Cancel" }).at(-1)!);
    expect(f.matching("session_stop_reconnecting").at(-1)?.args.sessionId).toBe(c.sessionId);
    expect(f.matching("session_close_transport")).toHaveLength(0);
    await c.prepare(trust(2));
    await c.ready();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("button", { name: "Reconnect" })).toHaveProperty("disabled", true);
    await c.emit({ kind: "closed" });
    expect(screen.getByRole("button", { name: "Reconnect" })).toHaveProperty("disabled", false);
    expect(screen.getByRole("alert").textContent).toContain("cancelled");
    await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
    expect(f.matching("session_retry_transport").at(-1)?.args.sessionId).toBe(c.sessionId);
    const second = await c.start();
    await second.prepare(trust(3));
    expect(screen.getByText("SHA256:hop-3")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
    await second.ready();
    expect(screen.getByRole("status").textContent).toContain("Connected");
    expect(f.connections).toHaveLength(1);
  },
);

it("waits for renderer failure cleanup and rejects late readiness", async () => {
  const f = fixture();
  const view = render(sessionView());
  const c = await connect(f);
  const terminal = view.container.querySelector("scoplen-terminal")!;
  act(() => terminal.dispatchEvent(new CustomEvent("terminal-error", { detail: { message: "write failed" } })));
  expect(f.matching("session_fail_transport")).toHaveLength(1);
  expect(screen.getByRole("button", { name: "Reconnect" })).toHaveProperty("disabled", true);
  await c.ready();
  expect(screen.getByRole("status").textContent).toContain("failed");
  await c.emit({ kind: "failed", error: "terminal unusable", exhausted: false });
  expect(screen.getByRole("alert").textContent).toBe("write failed");
  await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
  expect(f.matching("session_retry_transport")).toHaveLength(1);
});

it("cancels pending and queued old input without failing an automatic replacement", async () => {
  const f = fixture();
  const pending = f.delay("session_input");
  const view = render(sessionView());
  const c = await connect(f);
  const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  await c.ready();
  const cancelled = Promise.allSettled([terminal.send(new Uint8Array([13])), terminal.send(new Uint8Array([14]))]);
  await waitFor(() => expect(f.matching("session_input")).toHaveLength(1));
  await c.emit({ kind: "retrying", attempt: 1, delaySeconds: 1, error: "Network connection lost" });
  const second = await c.start(true);
  await second.ready();
  await act(async () => {
    pending.reject("old input failed");
    expect((await cancelled).map((r) => r.status)).toEqual(["rejected", "rejected"]);
  });
  expect(screen.getByRole("status").textContent).toContain("Connected");
  expect(screen.queryByRole("alert")).toBeNull();
  expect(f.matching("session_input")).toHaveLength(1);
  await terminal.send(new Uint8Array([15]));
  expect(f.matching("session_input").at(-1)?.args.transportId).toBe(second.transportId);
});

it("defers background prompts until selection and discards hidden passphrase input", async () => {
  const f = fixture();
  const view = render(sessionView("en", false));
  const c = await connect(f);
  await c.prepare(trust());
  expect(screen.queryByRole("dialog")).toBeNull();
  view.rerender(sessionView());
  expect(screen.getByRole("dialog")).toBeTruthy();
  await c.prepare(passphrase());
  await userEvent.type(screen.getByLabelText("Key passphrase"), "discard-when-hidden");
  view.rerender(sessionView("en", false));
  expect(screen.queryByRole("dialog")).toBeNull();
  view.rerender(sessionView());
  expect((screen.getByLabelText("Key passphrase") as HTMLInputElement).value).toBe("");
  expect(f.matching("session_stop_reconnecting")).toHaveLength(0);
});

it("ignores late prompts, readiness, output and replies after tab closure", async () => {
  const f = fixture();
  const pending = f.delay("session_respond");
  const report = vi.fn();
  const view = render(sessionView("en", true, vi.fn(), report));
  const c = await connect(f);
  await c.prepare(trust());
  await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
  view.unmount();
  report.mockClear();
  await act(() => pending.resolve(null));
  await c.prepare(passphrase());
  await c.ready();
  await c.output("stale");
  await act(() => c.finish.reject("late failure"));
  expect(report).not.toHaveBeenCalled();
  expect(f.matching("session_respond")).toHaveLength(1);
  expect(f.matching("session_close_transport").at(-1)?.args.sessionId).toBe(c.sessionId);
});
