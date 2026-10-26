// SPDX-License-Identifier: Apache-2.0
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import type { Channel } from "@tauri-apps/api/core";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppearanceProvider } from "@scoplen/ui";
import type { ScoplenTerminalElement } from "@scoplen/terminal";
import { I18nProvider } from "../src/i18n";
import { Shell } from "../src/shell";
import { TerminalColorsProvider } from "../src/terminal-colors";
import type { PreparationContext, PreparationEvent, SavedTerminalOutput, SessionEvent } from "../src/ipc/bindings";

vi.mock("../src/inventory/home", () => ({
  HostsHome: ({
    onConnect,
    onViewOutput,
  }: {
    onConnect: (id: string, label: string) => void;
    onViewOutput: (output: SavedTerminalOutput) => void;
  }) => (
    <>
      <button onClick={() => onConnect("login-first", "First host")}>Start first</button>
      <button onClick={() => onConnect("login-second", "Second host")}>Start second</button>
      <button
        onClick={() =>
          onViewOutput({
            target: { profileId: "login-first", hostName: "Saved host", loginName: "ops" },
            snapshot: { version: 1, columns: 80, rows: 24, data: "offline output" },
          })
        }
      >
        View saved output
      </button>
    </>
  ),
}));

beforeEach(() => {
  vi.stubGlobal("matchMedia", () => ({
    matches: false,
    addListener() {},
    removeListener() {},
    addEventListener() {},
    removeEventListener() {},
  }));
});

afterEach(async () => {
  await act(async () => cleanup());
  clearMocks();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}

function fixture() {
  const calls: Array<{ command: string; args: Record<string, unknown> }> = [];
  const connections: Array<{
    profileId: string;
    sessionId: string;
    messages: Channel<SessionEvent | ArrayBuffer>;
    finish: ReturnType<typeof deferred<null>>;
  }> = [];
  const saveFailures = new Map<string, number>();
  const saved = { id: "saved-workspace", name: "Operations", tabCount: 2, issue: null };
  let workspaces: Array<typeof saved> = [];
  let opened: unknown;
  mockIPC(
    (command, args) => {
      const payload = (args ?? {}) as Record<string, unknown>;
      calls.push({ command, args: payload });
      if (command === "session_connect") {
        const finish = deferred<null>();
        connections.push({ ...(payload as unknown as (typeof connections)[number]), finish });
        return finish.promise;
      }
      if (command === "session_stop_reconnecting") {
        const connection = connections.find((entry) => entry.sessionId === payload.sessionId)!;
        connection.messages.onmessage({ kind: "closed" });
        connection.finish.resolve(null);
      }
      if (command === "session_save_output") {
        const id = payload.sessionId as string;
        const remaining = saveFailures.get(id) ?? 0;
        if (remaining) {
          saveFailures.set(id, remaining - 1);
          return Promise.reject("storage");
        }
      }
      if (command === "session_transfer_queue")
        return {
          sessionId: payload.sessionId,
          queueId: `queue-${payload.sessionId}`,
          revision: "1",
          capacity: 16,
          outstanding: 0,
          pickerBusy: false,
          blocksFileOperations: false,
          items: [],
          recent: [],
        };
      if (command === "forward_list") return [];
      if (command === "workspaces_list") return workspaces;
      if (command === "workspaces_create") {
        workspaces = [saved];
        return saved;
      }
      if (command === "workspaces_open") return opened;
      if (command === "snippets_list")
        return [
          {
            id: "snippet-marker",
            name: "Pane marker",
            template: "printf pane-marker",
            variables: [],
            tags: [],
            folder: null,
            readOnly: false,
            issue: null,
          },
        ];
      if (command === "snippets_prepare") return { snippetId: "snippet-marker", command: "printf pane-marker" };
      return null;
    },
    { shouldMockEvents: true },
  );
  return {
    calls,
    connections,
    saveFailures,
    matching: (command: string) => calls.filter((call) => call.command === command),
    openWith: (value: unknown) => {
      opened = value;
    },
  };
}

function shell(locale: "en" | "zh-Hans" = "en") {
  return render(
    <AppearanceProvider>
      <TerminalColorsProvider>
        <I18nProvider locale={locale}>
          <Shell
            info={{ version: "0.1.0", platform: "windows", locale }}
            status={{ state: "open", protection: "keystore" }}
            onStatus={vi.fn()}
          />
        </I18nProvider>
      </TerminalColorsProvider>
    </AppearanceProvider>,
  );
}

function panes(container: HTMLElement) {
  return Array.from(container.querySelectorAll<HTMLDivElement>("[data-pane-id]")).map((pane) => ({
    pane,
    terminal: pane.querySelector<ScoplenTerminalElement>("scoplen-terminal")!,
  }));
}

function outputFrame(transportId: string, text: string) {
  const data = new TextEncoder().encode(text);
  const frame = new Uint8Array(16 + data.length);
  const uuid = transportId.replaceAll("-", "");
  for (let index = 0; index < 16; index++) frame[index] = Number.parseInt(uuid.slice(index * 2, index * 2 + 2), 16);
  frame.set(data, 16);
  return frame.buffer;
}

async function connect(f: ReturnType<typeof fixture>, index: number, ready = true) {
  await waitFor(() => expect(f.connections.length).toBeGreaterThan(index));
  const connection = f.connections[index]!;
  const transportId = crypto.randomUUID();
  const emit = (event: SessionEvent | ArrayBuffer) => act(() => connection.messages.onmessage(event));
  await emit({ kind: "starting", transportId, automatic: false });
  if (ready) await emit({ kind: "ready", transportId });
  return {
    ...connection,
    transportId,
    ready: () => emit({ kind: "ready", transportId }),
    output: (text: string) => emit(outputFrame(transportId, text)),
    prepare: (event: PreparationEvent) => emit({ kind: "preparation", transportId, event }),
  };
}

async function focusPane(button: "Previous pane" | "Next pane", terminal: ScoplenTerminalElement) {
  const control = screen.getByRole("button", { name: button });
  control.focus();
  await userEvent.keyboard("{Enter}");
  await waitFor(() => expect(document.activeElement).toBe(terminal));
}

it("splits into independent ordinary sessions while preserving surviving terminals through focus, tabs and collapse", async () => {
  const f = fixture();
  const view = shell();
  await userEvent.click(screen.getByRole("button", { name: "Start first" }));
  const first = await connect(f, 0);
  const original = panes(view.container)[0]!;
  await first.output("first-pane-only\r\n");
  await userEvent.click(screen.getByRole("button", { name: "Split right" }));
  const second = await connect(f, 1);
  const sibling = panes(view.container)[1]!;
  await second.output("second-pane-only\r\n");
  expect(panes(view.container)[0]!.terminal).toBe(original.terminal);
  expect(f.matching("session_reserve_transport")).toHaveLength(2);
  expect(f.matching("session_connect").map((call) => call.args)).toEqual([
    expect.objectContaining({ profileId: "login-first", sessionId: first.sessionId, command: null, pty: true }),
    expect.objectContaining({ profileId: "login-first", sessionId: second.sessionId, command: null, pty: true }),
  ]);
  expect(second.sessionId).not.toBe(first.sessionId);
  expect(first.transportId).not.toBe(second.transportId);
  await focusPane("Previous pane", original.terminal);
  await userEvent.keyboard("a");
  await waitFor(() => expect(f.matching("session_input")).toHaveLength(1));
  expect(f.matching("session_input")[0]!.args).toEqual({
    sessionId: first.sessionId,
    transportId: first.transportId,
    data: [97],
  });
  await focusPane("Next pane", sibling.terminal);
  await userEvent.keyboard("b");
  await waitFor(() => expect(f.matching("session_input")).toHaveLength(2));
  expect(f.matching("session_input")[1]!.args).toEqual({
    sessionId: second.sessionId,
    transportId: second.transportId,
    data: [98],
  });
  await first.output("background-first\r\n");
  expect(document.activeElement).toBe(sibling.terminal);
  await waitFor(() => expect(original.terminal.findNext("background-first")).toBe(true));
  expect(sibling.terminal.findNext("first-pane-only")).toBe(false);
  expect(original.terminal.findNext("second-pane-only")).toBe(false);
  await act(() => {
    original.terminal.dispatchEvent(new CustomEvent("terminal-resize", { detail: { columns: 91, rows: 31 } }));
    sibling.terminal.dispatchEvent(new CustomEvent("terminal-resize", { detail: { columns: 47, rows: 19 } }));
  });
  expect(
    f
      .matching("session_resize")
      .slice(-2)
      .map((call) => call.args),
  ).toEqual([
    { sessionId: first.sessionId, transportId: first.transportId, columns: 91, rows: 31 },
    { sessionId: second.sessionId, transportId: second.transportId, columns: 47, rows: 19 },
  ]);
  await userEvent.click(within(sibling.pane).getByRole("button", { name: "Split below" }));
  const third = await connect(f, 2);
  const nested = panes(view.container)[2]!;
  await third.output("third-pane-only\r\n");
  await focusPane("Previous pane", sibling.terminal);
  await userEvent.click(within(sibling.pane).getByRole("button", { name: "Close session" }));
  await waitFor(() => expect(panes(view.container)).toHaveLength(2));
  expect(panes(view.container).map((entry) => entry.terminal)).toEqual([original.terminal, nested.terminal]);
  expect(original.pane.style.width).toBe("50%");
  expect(nested.pane.style.height).toBe("100%");
  expect(f.matching("session_close_transport").map((call) => call.args.sessionId)).toEqual([second.sessionId]);
  await userEvent.click(screen.getByRole("tab", { name: "Hosts" }));
  await userEvent.click(screen.getByRole("button", { name: "Start second" }));
  await connect(f, 3);
  await userEvent.click(screen.getByRole("tab", { name: /^First host/ }));
  await waitFor(() => expect(document.activeElement).toBe(original.terminal));
  await focusPane("Previous pane", nested.terminal);
  await userEvent.click(screen.getByRole("tab", { name: /^Second host/ }));
  await userEvent.click(screen.getByRole("tab", { name: /^First host/ }));
  await waitFor(() => expect(document.activeElement).toBe(nested.terminal));
  expect(panes(view.container)[0]!.terminal).toBe(original.terminal);
  expect(panes(view.container)[1]!.terminal).toBe(nested.terminal);
  expect(original.terminal.findNext("first-pane-only")).toBe(true);
  expect(nested.terminal.findNext("third-pane-only")).toBe(true);
  expect(f.matching("session_reserve_transport")).toHaveLength(4);
  expect(f.connections).toHaveLength(4);
  expect(f.matching("session_stop_reconnecting").map((call) => call.args.sessionId)).toEqual([second.sessionId]);
  expect(f.matching("session_close_transport")).toHaveLength(1);
});

it("keeps several pending preparations separate and shows only the selected pane's dialog", async () => {
  const f = fixture();
  const view = shell();
  await userEvent.click(screen.getByRole("button", { name: "Start first" }));
  const first = await connect(f, 0, false);
  await userEvent.click(screen.getByRole("button", { name: "Split right" }));
  const second = await connect(f, 1, false);
  await userEvent.click(screen.getAllByRole("button", { name: "Split below" })[1]!);
  const third = await connect(f, 2, false);
  const context: PreparationContext = {
    profileId: "login-first",
    hostId: "host-first",
    host: "First host",
    login: "ops",
    username: "ops",
    address: "first.example",
    port: 22,
    position: 1,
    total: 1,
    target: true,
  };
  await first.prepare({ kind: "passphrase", context, promptId: "first-key", incorrect: false });
  await second.prepare({
    kind: "keyboardInteractive",
    context,
    promptId: "second-challenge",
    name: "Pane two challenge",
    instruction: "Enter a fresh code",
    prompts: [{ text: "Pane two code", echo: false }],
  });
  expect(screen.queryByRole("dialog")).toBeNull();
  await third.prepare({
    kind: "trust",
    context,
    promptId: "third-trust",
    hostKey: {
      algorithm: "ssh-ed25519",
      key: "fixture-key",
      fingerprint: "SHA256:third",
      changed: false,
      review: null,
      previousSource: null,
    },
  });
  expect(screen.getAllByRole("dialog")).toHaveLength(1);
  await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
  expect(f.matching("session_respond").at(-1)!.args).toMatchObject({
    sessionId: third.sessionId,
    promptId: "third-trust",
  });
  await third.ready();
  await userEvent.click(screen.getByRole("button", { name: "Previous pane" }));
  expect(screen.getAllByRole("dialog")).toHaveLength(1);
  const code = screen.getByLabelText("Pane two code");
  await waitFor(() => expect(document.activeElement).toBe(code));
  await userEvent.type(code, "123456");
  await userEvent.click(screen.getByRole("button", { name: "Continue" }));
  expect(f.matching("session_respond").at(-1)!.args).toMatchObject({
    sessionId: second.sessionId,
    transportId: second.transportId,
    promptId: "second-challenge",
    intent: { kind: "keyboardInteractive", answers: ["123456"] },
  });
  await second.ready();
  expect(
    panes(view.container).map(
      ({ pane }) => (within(pane).getByRole("button", { name: "Split right" }) as HTMLButtonElement).disabled,
    ),
  ).toEqual([true, false, true]);
  await userEvent.click(screen.getByRole("button", { name: "Previous pane" }));
  await screen.findByRole("dialog", { name: "Unlock this SSH key" });
  expect(screen.getAllByRole("dialog")).toHaveLength(1);
  const key = screen.getByLabelText("Key passphrase") as HTMLInputElement;
  expect(key.value).toBe("");
  await waitFor(() => expect(document.activeElement).toBe(key));
  await userEvent.type(key, "fixture-unlock");
  await userEvent.click(screen.getByRole("button", { name: "Unlock and connect" }));
  expect(f.matching("session_respond").at(-1)!.args).toMatchObject({
    sessionId: first.sessionId,
    promptId: "first-key",
  });
  await first.ready();
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(panes(view.container)).toHaveLength(3);
  expect(f.matching("session_reserve_transport")).toHaveLength(3);
  expect(f.matching("session_stop_reconnecting")).toHaveLength(0);
  expect(f.matching("session_close_transport")).toHaveLength(0);
});

it("closes a whole tab in depth-first order, retains and focuses checkpoint failures, then permits retry and discard", async () => {
  const f = fixture();
  const view = shell();
  await userEvent.click(screen.getByRole("button", { name: "Start first" }));
  const first = await connect(f, 0);
  await first.output("first retained output\r\n");
  await userEvent.click(screen.getByRole("button", { name: "Split right" }));
  const second = await connect(f, 1);
  await second.output("second saved output\r\n");
  await userEvent.click(screen.getAllByRole("button", { name: "Split below" })[1]!);
  const third = await connect(f, 2);
  await third.output("third retained output\r\n");
  const before = panes(view.container);
  f.saveFailures.set(first.sessionId, 1);
  f.saveFailures.set(third.sessionId, 1);
  await userEvent.click(screen.getByRole("button", { name: "Close First host" }));
  await waitFor(() => expect(panes(view.container)).toHaveLength(2));
  await waitFor(() => expect(document.activeElement).toBe(before[0]!.terminal));
  expect(panes(view.container).map((entry) => entry.terminal)).toEqual([before[0]!.terminal, before[2]!.terminal]);
  expect(f.matching("session_stop_reconnecting").map((call) => call.args.sessionId)).toEqual([
    first.sessionId,
    second.sessionId,
    third.sessionId,
  ]);
  expect(f.matching("session_save_output").map((call) => call.args.sessionId)).toEqual([
    first.sessionId,
    second.sessionId,
    third.sessionId,
  ]);
  expect(f.matching("session_close_transport").map((call) => call.args.sessionId)).toEqual([second.sessionId]);
  expect(within(before[0]!.pane).getByRole("alert")).toBeTruthy();
  expect(within(before[2]!.pane).getByRole("alert")).toBeTruthy();
  expect(before[0]!.terminal.findNext("first retained output")).toBe(true);
  await userEvent.click(within(before[0]!.pane).getByRole("button", { name: "Close session" }));
  await waitFor(() => expect(panes(view.container)).toHaveLength(1));
  expect(panes(view.container)[0]!.terminal).toBe(before[2]!.terminal);
  expect(f.matching("session_save_output").at(-1)!.args.sessionId).toBe(first.sessionId);
  const saves = f.matching("session_save_output").length;
  await userEvent.click(within(before[2]!.pane).getByRole("button", { name: "Close without saving" }));
  await waitFor(() => expect(panes(view.container)).toHaveLength(0));
  expect(f.matching("session_save_output")).toHaveLength(saves);
  expect(screen.getByRole("tab", { name: "Hosts" }).getAttribute("aria-selected")).toBe("true");
  expect(f.matching("session_close_transport").map((call) => call.args.sessionId)).toEqual([
    second.sessionId,
    first.sessionId,
    third.sessionId,
  ]);
  expect(f.connections).toHaveLength(3);
});

it("targets snippets at the selected ordinary pane without broadcasting to its sibling", async () => {
  const f = fixture();
  const view = shell();
  await userEvent.click(screen.getByRole("button", { name: "Start first" }));
  const first = await connect(f, 0);
  await userEvent.click(screen.getByRole("button", { name: "Split right" }));
  const second = await connect(f, 1);
  expect(screen.getAllByRole("button", { name: "Snippets" })).toHaveLength(1);
  await userEvent.click(screen.getByRole("button", { name: "Snippets" }));
  await userEvent.click(await screen.findByRole("button", { name: "Use snippet" }));
  await userEvent.click(screen.getByRole("button", { name: "Review command" }));
  await userEvent.click(await screen.findByRole("button", { name: "Send command" }));
  expect(f.matching("session_input").at(-1)!.args).toEqual({
    sessionId: second.sessionId,
    transportId: second.transportId,
    data: Array.from(new TextEncoder().encode("printf pane-marker\r")),
  });
  await userEvent.keyboard("{Escape}");
  await focusPane("Previous pane", panes(view.container)[0]!.terminal);
  await userEvent.click(screen.getByRole("button", { name: "Snippets" }));
  await userEvent.click(await screen.findByRole("button", { name: "Use snippet" }));
  await userEvent.click(screen.getByRole("button", { name: "Review command" }));
  await userEvent.click(await screen.findByRole("button", { name: "Send command" }));
  expect(f.matching("session_input")).toHaveLength(2);
  expect(f.matching("session_input").at(-1)!.args).toEqual({
    sessionId: first.sessionId,
    transportId: first.transportId,
    data: Array.from(new TextEncoder().encode("printf pane-marker\r")),
  });
});

it("saves complete active and inactive trees and focus, then explicitly opens them into fresh ordinary sessions", async () => {
  const f = fixture();
  const app = shell();
  await userEvent.click(screen.getByRole("button", { name: "Workspaces" }));
  await screen.findByText(/No saved workspaces/);
  expect(f.connections).toHaveLength(0);
  await userEvent.keyboard("{Escape}");
  await userEvent.click(screen.getByRole("button", { name: "Start first" }));
  await connect(f, 0);
  await userEvent.click(screen.getByRole("button", { name: "Split right" }));
  await connect(f, 1);
  await userEvent.click(screen.getAllByRole("button", { name: "Split below" })[1]!);
  await connect(f, 2);
  await focusPane("Previous pane", panes(app.container)[1]!.terminal);
  await userEvent.click(screen.getByRole("tab", { name: "Hosts" }));
  await userEvent.click(screen.getByRole("button", { name: "Start second" }));
  await connect(f, 3);
  await userEvent.click(screen.getByRole("button", { name: "Split below" }));
  await connect(f, 4);
  await focusPane("Previous pane", panes(app.container)[3]!.terminal);
  await userEvent.click(screen.getByRole("tab", { name: /^First host/ }));
  await userEvent.click(screen.getByRole("button", { name: "Workspaces" }));
  await screen.findByText(/No saved workspaces/);
  await userEvent.type(screen.getByRole("textbox", { name: "Workspace name" }), "Operations");
  await userEvent.click(screen.getByRole("button", { name: "Save current tabs" }));
  await screen.findByText("Operations");
  const firstLeaf = { kind: "terminal", profileId: "login-first" };
  const secondLeaf = { kind: "terminal", profileId: "login-second" };
  expect(f.matching("workspaces_create")[0]!.args.input).toEqual({
    name: "Operations",
    tabs: [
      {
        tree: {
          kind: "split",
          direction: "horizontal",
          first: firstLeaf,
          second: { kind: "split", direction: "vertical", first: firstLeaf, second: firstLeaf },
        },
        focused: 1,
      },
      { tree: { kind: "split", direction: "vertical", first: secondLeaf, second: secondLeaf }, focused: 0 },
    ],
    active: 0,
  });
  expect(f.matching("workspaces_open")).toHaveLength(0);
  await act(async () => app.unmount());
  const reopened = shell();
  await userEvent.click(screen.getByRole("button", { name: "Workspaces" }));
  await screen.findByText("Operations");
  expect(f.connections).toHaveLength(5);
  expect(panes(reopened.container)).toHaveLength(0);
  await userEvent.keyboard("{Escape}");
  await userEvent.click(screen.getByRole("button", { name: "Start second" }));
  const existing = await connect(f, 5);
  const original = panes(reopened.container)[0]!.terminal;
  await existing.output("existing retained output\r\n");
  const ids = Array.from({ length: 5 }, () => crypto.randomUUID());
  const restored = (index: number, profileId: string, label: string) => ({
    kind: "terminal",
    terminal: { sessionId: ids[index]!, profileId, label },
  });
  f.openWith({
    tabs: [
      {
        tree: {
          kind: "split",
          direction: "horizontal",
          first: restored(0, "login-first", "Restored first"),
          second: {
            kind: "split",
            direction: "vertical",
            first: restored(1, "login-first", "Restored second"),
            second: restored(2, "login-first", "Restored third"),
          },
        },
        focusedSessionId: ids[1],
      },
      {
        tree: {
          kind: "split",
          direction: "vertical",
          first: restored(3, "login-second", "Restored fourth"),
          second: restored(4, "login-second", "Restored fifth"),
        },
        focusedSessionId: ids[3],
      },
    ],
    active: 0,
  });
  await userEvent.click(screen.getByRole("button", { name: "Workspaces" }));
  await userEvent.click(await screen.findByRole("button", { name: "Open workspace" }));
  await waitFor(() => expect(f.connections).toHaveLength(11));
  for (let index = 6; index < 11; index++) await connect(f, index);
  expect(f.connections.slice(6).map((connection) => connection.sessionId)).toEqual(ids);
  expect(
    f
      .matching("session_connect")
      .slice(6)
      .map((call) => call.args),
  ).toEqual(
    ids.map((sessionId, index) =>
      expect.objectContaining({
        sessionId,
        profileId: index < 3 ? "login-first" : "login-second",
        pty: true,
        command: null,
      }),
    ),
  );
  expect(panes(reopened.container)[0]!.terminal).toBe(original);
  expect(original.findNext("existing retained output")).toBe(true);
  expect(screen.getByRole("tab", { name: /^Restored first/ }).getAttribute("aria-selected")).toBe("true");
  const restoredPanes = panes(reopened.container).slice(1);
  expect(restoredPanes[0]!.pane.style.width).toBe("50%");
  expect(restoredPanes[1]!.pane.style.height).toBe("50%");
  expect(restoredPanes[2]!.pane.style.top).toBe("50%");
  expect(within(restoredPanes[1]!.pane).getByRole("button", { name: "Snippets" })).toBeTruthy();
  await userEvent.click(screen.getByRole("tab", { name: /^Restored fourth/ }));
  await waitFor(() => expect(document.activeElement).toBe(restoredPanes[3]!.terminal));
  await userEvent.click(screen.getByRole("tab", { name: /^Restored first/ }));
  await waitFor(() => expect(document.activeElement).toBe(restoredPanes[1]!.terminal));
  expect(f.matching("session_input")).toHaveLength(0);
  expect(f.matching("session_stop_reconnecting")).toHaveLength(0);
  expect(
    f.matching("session_close_transport").filter((call) => call.args.sessionId === existing.sessionId),
  ).toHaveLength(0);
}, 15_000);

it.each(["en", "zh-Hans"] as const)(
  "refuses splitting offline output and saving the whole tab set in %s",
  async (locale) => {
    const f = fixture();
    const view = shell(locale);
    await userEvent.click(screen.getByRole("button", { name: "Start first" }));
    await connect(f, 0);
    await userEvent.click(screen.getByRole("tab", { name: locale === "en" ? "Hosts" : "主机" }));
    await userEvent.click(screen.getByRole("button", { name: "View saved output" }));
    const offline = panes(view.container)[1]!.terminal;
    await waitFor(() => expect(offline.findNext("offline output")).toBe(true));
    const right = screen.getByRole("button", { name: locale === "en" ? "Split right" : "向右分屏" });
    const below = screen.getByRole("button", { name: locale === "en" ? "Split below" : "向下分屏" });
    expect((right as HTMLButtonElement).disabled).toBe(true);
    expect((below as HTMLButtonElement).disabled).toBe(true);
    await userEvent.click(right);
    await userEvent.click(below);
    expect(f.connections).toHaveLength(1);
    expect(f.matching("session_reserve_transport")).toHaveLength(1);
    await userEvent.click(screen.getByRole("button", { name: locale === "en" ? "Workspaces" : "工作区" }));
    const save = await screen.findByRole("button", { name: locale === "en" ? "Save current tabs" : "保存当前标签" });
    expect((save as HTMLButtonElement).disabled).toBe(true);
    await userEvent.click(save);
    expect(f.matching("workspaces_create")).toHaveLength(0);
    expect(f.matching("workspaces_open")).toHaveLength(0);
    expect(panes(view.container)[1]!.terminal).toBe(offline);
  },
);
