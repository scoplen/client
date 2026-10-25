// SPDX-License-Identifier: Apache-2.0
import { emit } from "@tauri-apps/api/event";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import { sampleHosts, sampleInventory } from "../src/gallery/sample-inventory";
import { InventoryContext } from "../src/inventory/api";
import { TunnelsHome } from "../src/inventory/tunnels";
import { HostsHome } from "../src/inventory/home";
import type { ForwardSnapshot, PreparationEvent } from "../src/ipc/bindings";
import { ForwardsContext, useForwards, type ForwardController } from "../src/use-forwards";
import { violations } from "../../ui/test/axe";

afterEach(() => {
  cleanup();
  clearMocks();
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}

function snapshot(overrides: Partial<ForwardSnapshot> = {}): ForwardSnapshot {
  return {
    runId: "run-1",
    configuration: {
      forwardId: "f-db",
      name: "postgres-prod",
      profileId: "l-3",
      bindAddress: "127.0.0.1",
      bindPort: 5433,
      targetHost: "prod-db",
      targetPort: 5432,
      login: challenge("trust").context,
    },
    phase: "listening",
    preparation: null,
    boundAddress: "127.0.0.1:5433",
    activeConnections: 2,
    uploadedBytes: "9007199254740993",
    downloadedBytes: "42",
    rejectedConnections: "0",
    lastIssue: null,
    revision: "9007199254740993",
    ...overrides,
  };
}

function challenge(kind: "trust" | "passphrase" | "keyboardInteractive", promptId = "prompt-1"): PreparationEvent {
  const context = {
    profileId: "l-3",
    hostId: "h-db-1",
    login: "ops",
    host: "Database host",
    username: "ops",
    address: "db.example",
    port: 22,
    position: 2,
    total: 2,
    target: true,
  };
  if (kind === "trust")
    return {
      kind,
      context,
      promptId,
      hostKey: {
        algorithm: "ssh-ed25519",
        key: "ssh-ed25519 example-public-key",
        fingerprint: "SHA256:example",
        changed: true,
        review: null,
        previousSource: null,
      },
    };
  if (kind === "passphrase") return { kind, context, promptId, incorrect: false };
  return {
    kind,
    context,
    promptId,
    name: "<script>literal server text</script>",
    instruction: "Answer both prompts",
    prompts: [
      { text: "Account", echo: true },
      { text: "Code", echo: false },
    ],
  };
}

function fixture(
  options: {
    runs?: ForwardSnapshot[];
    pendingList?: ReturnType<typeof deferred<ForwardSnapshot[]>>;
    pendingStart?: ReturnType<typeof deferred<ForwardSnapshot>>;
    locale?: "en" | "zh-Hans";
    home?: boolean;
  } = {},
) {
  const calls: { command: string; args: Record<string, unknown> }[] = [];
  const api = sampleInventory(sampleHosts());
  const respond = deferred<null>();
  let listed = options.runs ?? [];
  mockIPC(
    (command, args) => {
      calls.push({ command, args: (args ?? {}) as Record<string, unknown> });
      if (command === "forward_list") return options.pendingList?.promise ?? listed;
      if (command === "forward_start")
        return (
          options.pendingStart?.promise ??
          snapshot({ phase: "preparing", boundAddress: null, preparation: challenge("trust") })
        );
      if (command === "forward_respond") return respond.promise;
      return null;
    },
    { shouldMockEvents: true },
  );
  let controller!: ForwardController;
  function Harness({ visible = true }: { visible?: boolean }) {
    controller = useForwards();
    return (
      <I18nProvider locale={options.locale ?? "en"}>
        <InventoryContext.Provider value={api}>
          <ForwardsContext.Provider value={controller}>
            <main>{!visible ? <p>Other view</p> : options.home ? <HostsHome manage /> : <TunnelsHome />}</main>
          </ForwardsContext.Provider>
        </InventoryContext.Provider>
      </I18nProvider>
    );
  }
  const view = render(<Harness />);
  return {
    ...view,
    api,
    calls,
    respond,
    setListed: (runs: ForwardSnapshot[]) => {
      listed = runs;
    },
    hide: () => view.rerender(<Harness visible={false} />),
    reopen: () => view.rerender(<Harness />),
    get controller() {
      return controller;
    },
    changed: (run: ForwardSnapshot) => act(() => emit("forward-changed", { snapshot: run })),
  };
}

it("subscribes before listing, fences older revisions without precision loss and detaches without Stop", async () => {
  const pendingList = deferred<ForwardSnapshot[]>();
  const f = fixture({ pendingList });
  await waitFor(() => expect(f.calls.some((call) => call.command === "forward_list")).toBe(true));
  await f.changed(snapshot({ uploadedBytes: "9007199254740995", revision: "9007199254740995" }));
  await act(() => pendingList.resolve([snapshot()]));
  expect(f.controller.snapshots[0]?.uploadedBytes).toBe("9007199254740995");
  await f.changed(snapshot({ uploadedBytes: "1", revision: "9007199254740994" }));
  expect(f.controller.snapshots[0]?.uploadedBytes).toBe("9007199254740995");
  expect(screen.getByText("9,007,199,254,740,995 B")).toBeTruthy();
  f.unmount();
  expect(f.calls.some((call) => call.command === "forward_stop")).toBe(false);
});

it("saves explicit local endpoints, discloses non-loopback access and never starts while saving", async () => {
  const f = fixture();
  const create = vi.spyOn(f.api, "createForward");
  await screen.findByText("postgres-prod");
  await userEvent.click(screen.getByRole("button", { name: "Add tunnel" }));
  const dialog = screen.getByRole("dialog", { name: "New tunnel" });
  expect((within(dialog).getByLabelText("Bind address") as HTMLInputElement).value).toBe("127.0.0.1");
  await userEvent.type(within(dialog).getByLabelText("Name"), "local-db");
  await userEvent.clear(within(dialog).getByLabelText("Bind address"));
  await userEvent.type(within(dialog).getByLabelText("Bind address"), "0.0.0.0");
  expect(within(dialog).getByText(/Other devices may reach/)).toBeTruthy();
  await userEvent.type(within(dialog).getByLabelText("Bind port"), "15432");
  await userEvent.type(within(dialog).getByLabelText("Target host"), "db.internal");
  await userEvent.type(within(dialog).getByLabelText("Target port"), "5432");
  await userEvent.click(within(dialog).getByRole("button", { name: "Save changes" }));
  expect(create).toHaveBeenCalledWith({
    name: "local-db",
    kind: "local",
    bindAddress: "0.0.0.0",
    bindPort: 15432,
    targetHost: "db.internal",
    targetPort: 5432,
    profile: null,
  });
  expect(await screen.findByText("local-db")).toBeTruthy();
  expect(f.calls.some((call) => call.command === "forward_start" || call.command.startsWith("session_"))).toBe(false);
});

it("starts an independent run using a selected Login and retains its Stop after the definition disappears", async () => {
  const f = fixture();
  await screen.findByText("postgres-prod");
  await waitFor(() => expect(f.controller.loading).toBe(false));
  await waitFor(() => expect(screen.getByRole("button", { name: "Start" }).hasAttribute("disabled")).toBe(false));
  await userEvent.click(screen.getByRole("button", { name: "Start" }));
  const dialog = screen.getByRole("dialog", { name: "Start postgres-prod" });
  await userEvent.click(within(dialog).getByRole("button", { name: "Start" }));
  expect(f.calls.find((call) => call.command === "forward_start")?.args).toEqual({
    forwardId: "f-db",
    profileId: "l-3",
  });
  expect(await screen.findByRole("dialog", { name: "Host key changed" })).toBeTruthy();
  expect(f.calls.some((call) => call.command.startsWith("session_"))).toBe(false);
  f.api.forwards = async () => ({ status: "ok", data: [] });
  await act(() => f.api.setFavorite("h-db-1", true));
  await screen.findByText(/No saved tunnels yet/);
  await userEvent.click(screen.getAllByRole("button", { name: "Cancel" })[0]!);
  expect(f.calls.find((call) => call.command === "forward_stop")?.args).toEqual({ runId: "run-1" });
});

it.each(["trust", "passphrase", "keyboardInteractive"] as const)(
  "reuses %s preparation without opening a terminal and cancels the exact run",
  async (kind) => {
    const f = fixture({ runs: [snapshot({ phase: "preparing", preparation: challenge(kind), boundAddress: null })] });
    await screen.findByText("Needs attention");
    await userEvent.click(screen.getByRole("button", { name: "Continue setup" }));
    if (kind === "trust") {
      expect(screen.getByText("SHA256:example")).toBeTruthy();
      await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
    } else if (kind === "passphrase") {
      const field = screen.getByLabelText("Key passphrase") as HTMLInputElement;
      await userEvent.type(field, "once-only");
      await userEvent.click(screen.getByRole("button", { name: "Unlock and connect" }));
      expect(field.value).toBe("");
    } else {
      expect(screen.getByText("<script>literal server text</script>")).toBeTruthy();
      const account = screen.getByLabelText("Account") as HTMLInputElement;
      const code = screen.getByLabelText("Code") as HTMLInputElement;
      expect(account.type).toBe("text");
      expect(code.type).toBe("password");
      await userEvent.type(account, "operator");
      await userEvent.type(code, "once-only");
      await userEvent.click(screen.getByRole("button", { name: "Continue" }));
      expect(account.value).toBe("");
      expect(code.value).toBe("");
    }
    const response = f.calls.find((call) => call.command === "forward_respond");
    expect(response?.args).toEqual({
      runId: "run-1",
      promptId: "prompt-1",
      intent:
        kind === "trust"
          ? { kind: "acceptHostKey" }
          : kind === "passphrase"
            ? { kind: "passphrase", value: "once-only" }
            : { kind: "keyboardInteractive", answers: ["operator", "once-only"] },
    });
    await f.changed(
      snapshot({ phase: "preparing", preparation: challenge(kind, "new-prompt"), revision: "9007199254740994" }),
    );
    await act(() => f.respond.resolve(null));
    await userEvent.click(screen.getAllByRole("button", { name: "Cancel" })[0]!);
    expect(f.calls.filter((call) => call.command === "forward_stop")).toHaveLength(1);
  },
);

it("clears Interactive input on view changes, leaves the owner running and recovers the current challenge", async () => {
  const f = fixture({
    home: true,
    runs: [snapshot({ phase: "preparing", preparation: challenge("keyboardInteractive"), boundAddress: null })],
  });
  await userEvent.click(screen.getByRole("button", { name: /^Tunnels/ }));
  await screen.findByText("Needs attention");
  await userEvent.click(screen.getByRole("button", { name: "Continue setup" }));
  const account = screen.getByLabelText("Account") as HTMLInputElement;
  await userEvent.type(account, "discard-me");
  f.hide();
  expect(account.value).toBe("");
  expect(f.calls.some((call) => call.command === "forward_stop")).toBe(false);
  f.reopen();
  await userEvent.click(screen.getByRole("button", { name: /^Tunnels/ }));
  await screen.findByText("Needs attention");
  await userEvent.click(screen.getByRole("button", { name: "Continue setup" }));
  expect((screen.getByLabelText("Account") as HTMLInputElement).value).toBe("");
  expect(f.calls.some((call) => call.command === "forward_start")).toBe(false);
  expect(f.calls.filter((call) => call.command === "forward_list")).toHaveLength(1);
});

it("keeps Chinese stopping and failed runs accessible with visible final counters", async () => {
  const f = fixture({
    locale: "zh-Hans",
    runs: [snapshot({ phase: "stopping" }), snapshot({ runId: "run-2", phase: "failed", lastIssue: "listenFailed" })],
  });
  await screen.findByText("停止中");
  expect(screen.getByRole("button", { name: "停止" }).hasAttribute("disabled")).toBe(true);
  expect(screen.getByText("失败")).toBeTruthy();
  expect(screen.getByText(/本地地址或端口不可用/)).toBeTruthy();
  expect(await violations(f.container)).toEqual([]);
});

it("retains form input after a rejected save and explains referenced-definition deletion", async () => {
  const f = fixture();
  f.api.updateForward = vi
    .fn()
    .mockResolvedValue({ status: "error", error: { kind: "invalidForward", field: "targetHost" } });
  f.api.deleteForward = vi.fn().mockResolvedValue({ status: "error", error: { kind: "inUse" } });
  await screen.findByText("postgres-prod");
  await userEvent.click(screen.getByRole("button", { name: "Edit postgres-prod" }));
  const dialog = screen.getByRole("dialog", { name: "Edit tunnel" });
  await userEvent.clear(within(dialog).getByLabelText("Target host"));
  await userEvent.type(within(dialog).getByLabelText("Target host"), "keep-my-input");
  await userEvent.click(within(dialog).getByRole("button", { name: "Save changes" }));
  expect(
    await within(dialog).findByText("Enter a hostname or IP address without spaces, up to 1024 UTF-8 bytes."),
  ).toBeTruthy();
  expect((within(dialog).getByLabelText("Target host") as HTMLInputElement).value).toBe("keep-my-input");
  await userEvent.click(within(dialog).getAllByRole("button", { name: "Cancel" })[0]!);
  await userEvent.click(screen.getByRole("button", { name: "Delete postgres-prod" }));
  const confirmation = screen.getByRole("alertdialog", { name: "Delete postgres-prod?" });
  await userEvent.click(within(confirmation).getByRole("button", { name: "Delete postgres-prod" }));
  expect(await within(confirmation).findByText(/A Login or Workspace still uses/)).toBeTruthy();
});

it("rejects an old prompt before IPC after the current challenge changes", async () => {
  const f = fixture({ runs: [snapshot({ phase: "preparing", preparation: challenge("trust") })] });
  await waitFor(() => expect(f.controller.loading).toBe(false));
  await f.changed(
    snapshot({ phase: "preparing", preparation: challenge("trust", "replacement"), revision: "9007199254740994" }),
  );
  expect(await f.controller.respond("run-1", "prompt-1", { kind: "acceptHostKey" })).toBe("expired");
  expect(f.calls.some((call) => call.command === "forward_respond")).toBe(false);
});

it("discards an in-flight Start result after refreshing the observed store", async () => {
  const pendingStart = deferred<ForwardSnapshot>();
  const f = fixture({ pendingStart });
  await waitFor(() => expect(f.controller.loading).toBe(false));
  const started = f.controller.start("f-db", "l-3");
  await act(() => f.controller.refresh());
  await waitFor(() => expect(f.calls.filter((call) => call.command === "forward_list")).toHaveLength(2));
  await act(() => pendingStart.resolve(snapshot()));
  expect(await started).toBeNull();
  expect(f.controller.snapshots).toEqual([]);
  expect(f.controller.issue).toBeNull();
  expect(f.calls.some((call) => call.command === "forward_stop")).toBe(false);
});

it("clears a pending challenge on refresh and fences its late reply", async () => {
  const f = fixture({ runs: [snapshot({ phase: "preparing", preparation: challenge("keyboardInteractive") })] });
  await waitFor(() => expect(f.controller.loading).toBe(false));
  await userEvent.click(screen.getByRole("button", { name: "Continue setup" }));
  const field = screen.getByLabelText("Code") as HTMLInputElement;
  await userEvent.type(field, "discard-on-refresh");
  const replied = f.controller.respond("run-1", "prompt-1", { kind: "keyboardInteractive", answers: ["", ""] });
  f.setListed([]);
  await act(() => f.controller.refresh());
  expect(field.value).toBe("");
  await act(() => f.respond.resolve(null));
  expect(await replied).toBe("expired");
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(f.controller.snapshots).toEqual([]);
  expect(f.calls.some((call) => call.command === "forward_stop")).toBe(false);
});

it("keeps a running Login identity fixed after inventory Logins change or disappear", async () => {
  const f = fixture({ runs: [snapshot()] });
  await screen.findByText("Database host · ops");
  const read = vi.spyOn(f.api, "accessProfiles").mockResolvedValue({ status: "ok", data: [] });
  await act(() => f.api.setFavorite("h-db-1", true));
  await waitFor(() => expect(read).toHaveBeenCalled());
  expect(screen.getByText("Database host · ops")).toBeTruthy();
  expect(screen.getByText("ops@db.example:22")).toBeTruthy();
});
