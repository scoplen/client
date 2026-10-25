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
import type { ForwardIssue, ForwardSnapshot, PreparationEvent } from "../src/ipc/bindings";
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
      kind: "local",
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

function dynamicSnapshot(overrides: Partial<ForwardSnapshot> = {}): ForwardSnapshot {
  return snapshot({
    configuration: {
      kind: "dynamic",
      forwardId: "f-socks",
      name: "staging-socks",
      profileId: "l-3",
      bindAddress: "::",
      bindPort: 1080,
      login: challenge("trust").context,
    },
    boundAddress: "[::]:1080",
    ...overrides,
  });
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
    startRun?: ForwardSnapshot;
    listIssue?: ForwardIssue;
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
      if (command === "forward_list")
        return options.listIssue ? Promise.reject(options.listIssue) : (options.pendingList?.promise ?? listed);
      if (command === "forward_start")
        return (
          options.pendingStart?.promise ??
          options.startRun ??
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

it("saves Dynamic with a loopback default, no fixed target and keyboard form submission", async () => {
  const f = fixture();
  const create = vi.spyOn(f.api, "createForward");
  await screen.findByText("postgres-prod");
  await userEvent.click(screen.getByRole("button", { name: "Add tunnel" }));
  const dialog = screen.getByRole("dialog", { name: "New tunnel" });
  await userEvent.type(within(dialog).getByLabelText("Name"), "dynamic-test");
  await userEvent.tab();
  const mode = within(dialog).getByRole("combobox", { name: "Mode" });
  expect(document.activeElement).toBe(mode);
  await userEvent.selectOptions(mode, "dynamic");
  await userEvent.tab();
  expect(document.activeElement).toBe(within(dialog).getByLabelText("Bind address"));
  expect((within(dialog).getByLabelText("Bind address") as HTMLInputElement).value).toBe("127.0.0.1");
  expect(within(dialog).queryByLabelText("Target host")).toBeNull();
  expect(within(dialog).queryByLabelText("Target port")).toBeNull();
  expect(within(dialog).getByText(/SOCKS4\/4a and SOCKS5 CONNECT without proxy authentication/)).toBeTruthy();
  expect(within(dialog).queryByRole("note")).toBeNull();
  await userEvent.type(within(dialog).getByLabelText("Bind port"), "1081");
  await userEvent.tab();
  expect(document.activeElement).toBe(within(dialog).getByRole("combobox", { name: "Default Login" }));
  await userEvent.tab();
  await userEvent.tab();
  expect(document.activeElement).toBe(within(dialog).getByRole("button", { name: "Save changes" }));
  await userEvent.keyboard("{Enter}");
  await waitFor(() =>
    expect(create).toHaveBeenCalledWith({
      name: "dynamic-test",
      kind: "dynamic",
      bindAddress: "127.0.0.1",
      bindPort: 1081,
      targetHost: null,
      targetPort: null,
      profile: null,
    }),
  );
  expect(await screen.findByText("dynamic-test")).toBeTruthy();
  expect(f.calls.some((call) => call.command === "forward_start" || call.command.startsWith("session_"))).toBe(false);
});

it("clears Local targets when saved as Dynamic and requires fresh targets when changed back", async () => {
  const f = fixture();
  const update = vi.spyOn(f.api, "updateForward");
  await screen.findByText("postgres-prod");
  await userEvent.click(screen.getByRole("button", { name: "Edit postgres-prod" }));
  let dialog = screen.getByRole("dialog", { name: "Edit tunnel" });
  await userEvent.selectOptions(within(dialog).getByLabelText("Mode"), "dynamic");
  await userEvent.clear(within(dialog).getByLabelText("Bind address"));
  await userEvent.type(within(dialog).getByLabelText("Bind address"), "0.0.0.0");
  expect(within(dialog).getByRole("note").textContent).toContain(
    "Any device that can reach this listener can request destinations through the selected SSH connection.",
  );
  expect(within(dialog).queryByLabelText("Target host")).toBeNull();
  await userEvent.click(within(dialog).getByRole("button", { name: "Save changes" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(update).toHaveBeenCalledWith(
    "f-db",
    expect.objectContaining({ kind: "dynamic", bindAddress: "0.0.0.0", targetHost: null, targetPort: null }),
  );
  const saved = screen.getByText("postgres-prod").closest("li")!;
  expect(within(saved).getByText("0.0.0.0:5433")).toBeTruthy();
  expect(within(saved).queryByText(/prod-db/)).toBeNull();
  await userEvent.click(within(saved).getByRole("button", { name: "Edit postgres-prod" }));
  dialog = screen.getByRole("dialog", { name: "Edit tunnel" });
  expect((within(dialog).getByLabelText("Mode") as HTMLSelectElement).value).toBe("dynamic");
  await userEvent.selectOptions(within(dialog).getByLabelText("Mode"), "local");
  expect((within(dialog).getByLabelText("Target host") as HTMLInputElement).value).toBe("");
  expect((within(dialog).getByLabelText("Target port") as HTMLInputElement).value).toBe("");
  expect((within(dialog).getByLabelText("Target host") as HTMLInputElement).required).toBe(true);
});

it.each(
  (["Add tunnel", "Edit staging-socks"] as const).flatMap((opener) =>
    (["escape", "cancel", "save"] as const).map((dismissal) => [opener, dismissal] as const),
  ),
)("returns focus to %s after Dynamic editor %s", async (opener, dismissal) => {
  fixture();
  const trigger = await screen.findByRole("button", { name: opener });
  await userEvent.click(trigger);
  const dialog = screen.getByRole("dialog", { name: opener === "Add tunnel" ? "New tunnel" : "Edit tunnel" });
  await userEvent.selectOptions(within(dialog).getByLabelText("Mode"), "dynamic");
  if (dismissal === "escape") await userEvent.keyboard("{Escape}");
  else if (dismissal === "cancel")
    await userEvent.click(within(dialog).getAllByRole("button", { name: "Cancel" }).at(-1)!);
  else {
    if (opener === "Add tunnel") {
      await userEvent.type(within(dialog).getByLabelText("Name"), "focus-test");
      await userEvent.type(within(dialog).getByLabelText("Bind port"), "1081");
    }
    await userEvent.click(within(dialog).getByRole("button", { name: "Save changes" }));
  }
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  await waitFor(() => expect(document.activeElement).toBe(trigger));
});

it("returns editor focus to Add tunnel if its saved row disappears", async () => {
  const f = fixture();
  const trigger = await screen.findByRole("button", { name: "Edit staging-socks" });
  await userEvent.click(trigger);
  await act(() => f.api.deleteForward("f-socks"));
  await waitFor(() => expect(trigger.isConnected).toBe(false));
  await userEvent.keyboard("{Escape}");
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: "Add tunnel" })));
});

it("starts saved Dynamic with the selected Login through the existing commands and stops its exact run", async () => {
  const f = fixture({ startRun: dynamicSnapshot() });
  await screen.findByText("staging-socks");
  await waitFor(() => expect(f.controller.loading).toBe(false));
  const saved = screen.getByText("staging-socks").closest("li")!;
  expect(within(saved).getByText("127.0.0.1:1080")).toBeTruthy();
  expect(within(saved).queryByText(/→/)).toBeNull();
  await userEvent.click(within(saved).getByRole("button", { name: "Start" }));
  const dialog = screen.getByRole("dialog", { name: "Start staging-socks" });
  expect(within(dialog).getByRole("button", { name: "Start" }).hasAttribute("disabled")).toBe(true);
  await userEvent.selectOptions(within(dialog).getByLabelText("Login"), "l-3");
  await userEvent.click(within(dialog).getByRole("button", { name: "Start" }));
  await screen.findByText("Listening");
  expect(f.calls.find((call) => call.command === "forward_start")?.args).toEqual({
    forwardId: "f-socks",
    profileId: "l-3",
  });
  await userEvent.click(screen.getByRole("button", { name: "Stop" }));
  expect(f.calls.find((call) => call.command === "forward_stop")?.args).toEqual({ runId: "run-1" });
  expect(f.calls.some((call) => call.command.startsWith("session_"))).toBe(false);
});

it("keeps Dynamic's fixed listener, disclosure and exact counters after saved edits and deletion", async () => {
  const f = fixture({ runs: [dynamicSnapshot()] });
  const runs = await screen.findByRole("list", { name: "Runs" });
  expect(within(runs).getByText("[::]:1080")).toBeTruthy();
  expect(within(runs).queryByText(/→/)).toBeNull();
  expect(within(runs).getByRole("note").textContent).toContain("Any device that can reach this listener");
  expect(within(runs).getByText("9,007,199,254,740,993 B")).toBeTruthy();
  expect(within(runs).getByText("42 B")).toBeTruthy();
  expect(within(runs).getByText("2")).toBeTruthy();
  await act(() =>
    f.api.updateForward("f-socks", {
      name: "changed-to-local",
      kind: "local",
      bindAddress: "127.0.0.1",
      bindPort: 9000,
      targetHost: "changed.example",
      targetPort: 443,
      profile: null,
    }),
  );
  await screen.findByText("changed-to-local");
  await act(() => f.api.deleteForward("f-socks"));
  await waitFor(() => expect(screen.queryByText("changed-to-local")).toBeNull());
  expect(within(runs).getByText("staging-socks")).toBeTruthy();
  expect(within(runs).getByText("[::]:1080")).toBeTruthy();
  expect(within(runs).getByRole("note")).toBeTruthy();
  await userEvent.click(within(runs).getByRole("button", { name: "Stop" }));
  expect(f.calls.find((call) => call.command === "forward_stop")?.args).toEqual({ runId: "run-1" });
});

it("starts an independent run using a selected Login and retains its Stop after the definition disappears", async () => {
  const f = fixture();
  await screen.findByText("postgres-prod");
  await waitFor(() => expect(f.controller.loading).toBe(false));
  const saved = screen.getByText("postgres-prod").closest("li")!;
  await waitFor(() =>
    expect(within(saved).getByRole("button", { name: "Start" }).hasAttribute("disabled")).toBe(false),
  );
  await userEvent.click(within(saved).getByRole("button", { name: "Start" }));
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

it.each(
  (["trust", "passphrase", "keyboardInteractive"] as const).flatMap((kind) =>
    (["local", "dynamic"] as const).map((mode) => [kind, mode] as const),
  ),
)("reuses %s preparation for %s without opening a terminal and cancels the exact run", async (kind, mode) => {
  const run = mode === "dynamic" ? dynamicSnapshot : snapshot;
  const f = fixture({ runs: [run({ phase: "preparing", preparation: challenge(kind), boundAddress: null })] });
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
    run({ phase: "preparing", preparation: challenge(kind, "new-prompt"), revision: "9007199254740994" }),
  );
  await act(() => f.respond.resolve(null));
  await userEvent.click(screen.getAllByRole("button", { name: "Cancel" })[0]!);
  expect(f.calls.filter((call) => call.command === "forward_stop")).toHaveLength(1);
});

it.each(["en", "zh-Hans"] as const)("renders Dynamic loading, peer phases and final counters in %s", async (locale) => {
  const pendingList = deferred<ForwardSnapshot[]>();
  const f = fixture({ locale, pendingList });
  const labels =
    locale === "en"
      ? { loading: "Loading tunnels…", runs: "Runs", stopping: "Stopping", stopped: "Stopped", stop: "Stop" }
      : { loading: "正在读取隧道…", runs: "运行记录", stopping: "停止中", stopped: "已停止", stop: "停止" };
  expect(screen.getAllByRole("status").some((element) => element.textContent === labels.loading)).toBe(true);
  await waitFor(() => expect(f.calls.some((call) => call.command === "forward_list")).toBe(true));
  await act(() => pendingList.resolve([dynamicSnapshot({ activeConnections: 3 })]));
  const runs = screen.getByRole("list", { name: labels.runs });
  expect(within(runs).getByText("3")).toBeTruthy();
  expect(within(runs).getByText("[::]:1080")).toBeTruthy();
  await f.changed(dynamicSnapshot({ phase: "stopping", activeConnections: 1, revision: "9007199254740994" }));
  expect(within(runs).getByText(labels.stopping)).toBeTruthy();
  expect(within(runs).getByRole("button", { name: labels.stop }).hasAttribute("disabled")).toBe(true);
  await f.changed(
    dynamicSnapshot({
      phase: "stopped",
      activeConnections: 0,
      uploadedBytes: "9007199254740995",
      downloadedBytes: "9007199254740997",
      revision: "9007199254740995",
    }),
  );
  expect(within(runs).getByText(labels.stopped)).toBeTruthy();
  expect(within(runs).queryByRole("button", { name: labels.stop })).toBeNull();
  expect(within(runs).getByText("9,007,199,254,740,995 B")).toBeTruthy();
  expect(within(runs).getByText("9,007,199,254,740,997 B")).toBeTruthy();
  expect(await violations(f.container)).toEqual([]);
});

it.each(["en", "zh-Hans"] as const)(
  "shows actionable Dynamic handshake issues in %s without stopping other peers",
  async (locale) => {
    const f = fixture({ locale, runs: [dynamicSnapshot({ lastIssue: "handshakeRejected" })] });
    expect(
      await screen.findByText(locale === "en" ? /A SOCKS request was refused/ : /一个 SOCKS 请求被拒绝/),
    ).toBeTruthy();
    await f.changed(dynamicSnapshot({ lastIssue: "handshakeTimedOut", revision: "9007199254740994" }));
    expect(screen.getByText(locale === "en" ? /A SOCKS handshake timed out/ : /一个 SOCKS 握手已超时/)).toBeTruthy();
    expect(screen.getByRole("button", { name: locale === "en" ? "Stop" : "停止" })).toBeTruthy();
    expect(f.calls.some((call) => call.command === "forward_stop")).toBe(false);
  },
);

it("retains Dynamic edits after an invalid save and disables the form while saving", async () => {
  const f = fixture();
  const pending = deferred<Awaited<ReturnType<typeof f.api.updateForward>>>();
  f.api.updateForward = vi.fn().mockReturnValue(pending.promise);
  await screen.findByText("staging-socks");
  await userEvent.click(screen.getByRole("button", { name: "Edit staging-socks" }));
  const dialog = screen.getByRole("dialog", { name: "Edit tunnel" });
  await userEvent.clear(within(dialog).getByLabelText("Bind address"));
  await userEvent.type(within(dialog).getByLabelText("Bind address"), "invalid-address");
  await userEvent.click(within(dialog).getByRole("button", { name: "Save changes" }));
  expect((within(dialog).getByLabelText("Mode") as HTMLSelectElement).disabled).toBe(true);
  expect((within(dialog).getByLabelText("Bind address") as HTMLInputElement).disabled).toBe(true);
  await act(() => pending.resolve({ status: "error", error: { kind: "invalidForward", field: "bindAddress" } }));
  expect(await within(dialog).findByText("Enter an IPv4 or IPv6 address.")).toBeTruthy();
  expect((within(dialog).getByLabelText("Bind address") as HTMLInputElement).value).toBe("invalid-address");
  expect((within(dialog).getByLabelText("Mode") as HTMLSelectElement).value).toBe("dynamic");
  expect(within(dialog).queryByLabelText("Target host")).toBeNull();
});

it("keeps Start unavailable after a run-list failure and offers refresh", async () => {
  fixture({ listIssue: "unavailable" });
  expect(await screen.findByText("Tunnel management is unavailable. Refresh runs to try again.")).toBeTruthy();
  expect(screen.getByRole("button", { name: "Refresh runs" })).toBeTruthy();
  await screen.findByText("staging-socks");
  for (const button of screen.getAllByRole("button", { name: "Start" }))
    expect(button.hasAttribute("disabled")).toBe(true);
  const unsupported = screen.getByText("metrics-remote").closest("li")!;
  expect(within(unsupported).queryByRole("button", { name: "Start" })).toBeNull();
  expect(within(unsupported).queryByRole("button", { name: "Edit metrics-remote" })).toBeNull();
});

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
