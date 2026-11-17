// SPDX-License-Identifier: Apache-2.0
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppearanceProvider } from "@scoplen/ui";
import { I18nProvider } from "../src/i18n";
import { Shell } from "../src/shell";
import { WorkspacesDialog } from "../src/workspaces";
import type { SessionTarget, WorkspaceInput, WorkspaceView } from "../src/ipc/bindings";
import { violations } from "../../ui/test/axe";
import { sampleHosts, sampleInventory } from "../src/gallery/sample-inventory";
import { selectOption } from "./select-option";

const api = vi.hoisted(() => ({
  workspacesList: vi.fn(),
  workspacesCreate: vi.fn(),
  workspacesOpen: vi.fn(),
  workspacesDelete: vi.fn(),
  forwardList: vi.fn(),
  forwardStart: vi.fn(),
  inventoryForwards: vi.fn(),
  inventoryAccessProfiles: vi.fn(),
}));
vi.mock("../src/account-profiles", () => ({
  useProfileCommands: () => api,
  useProfile: () => null,
  ProfileSwitcher: () => null,
}));
vi.mock("../src/ipc/store-events", () => ({ useStoreChanges: () => undefined }));
vi.mock("../src/ipc/bindings", async (original) => ({
  ...(await original<typeof import("../src/ipc/bindings")>()),
  events: { forwardChanged: { listen: () => Promise.resolve(() => undefined) } },
}));
vi.mock("../src/inventory/home", () => ({
  HostsHome: ({ onConnect }: { onConnect: (target: SessionTarget, name: string) => void }) => (
    <>
      <button onClick={() => onConnect({ kind: "personal", profileId: "login-first" }, "First host")}>
        Start first
      </button>
      <button onClick={() => onConnect({ kind: "personal", profileId: "login-second" }, "Second host")}>
        Start second
      </button>
    </>
  ),
}));
vi.mock("../src/session", () => ({
  SessionTerminal: ({ target, sessionId }: { target: SessionTarget; sessionId?: string }) => (
    <p data-testid="session" data-session={sessionId}>
      {target.profileId}
    </p>
  ),
}));

const saved: WorkspaceView = { id: "saved-workspace", name: "Operations", tabCount: 2, forwardCount: 0, issue: null };
const tabs: WorkspaceInput["tabs"] = [
  { tree: { kind: "terminal", profileId: "login-first", files: { kind: "closed" } }, focused: 0 },
  { tree: { kind: "terminal", profileId: "login-second", files: { kind: "closed" } }, focused: 0 },
];

const openedTab = (sessionId: string, profileId: string, label: string) => ({
  tree: { kind: "terminal", terminal: { sessionId, profileId, label, files: null } },
  focusedSessionId: sessionId,
});

it("refuses to save team terminals into a Personal workspace", async () => {
  render(
    <I18nProvider locale="en">
      <WorkspacesDialog tabs={tabs} active={0} teamSessions onOpen={vi.fn()} onClose={vi.fn()} />
    </I18nProvider>,
  );
  await screen.findByText("Team terminals cannot be saved in a Personal workspace yet.");
  await userEvent.type(screen.getByLabelText("Workspace name"), "Operations");
  expect((screen.getByRole("button", { name: "Save workspace" }) as HTMLButtonElement).disabled).toBe(true);
  expect(api.workspacesCreate).not.toHaveBeenCalled();
});

beforeEach(() => {
  vi.resetAllMocks();
  api.workspacesList.mockResolvedValue({ status: "ok", data: [] });
  api.workspacesCreate.mockResolvedValue({ status: "ok", data: saved });
  api.workspacesDelete.mockResolvedValue({ status: "ok", data: null });
  api.forwardList.mockResolvedValue({ status: "ok", data: [] });
  api.inventoryForwards.mockResolvedValue({ status: "ok", data: [] });
  api.inventoryAccessProfiles.mockResolvedValue({ status: "ok", data: [] });
});
afterEach(cleanup);

function shell() {
  return render(
    <AppearanceProvider>
      <I18nProvider locale="en">
        <Shell
          info={{ version: "0.1.0", platform: "windows", locale: "en" }}
          status={{ state: "open", protection: "keystore" }}
          onStatus={vi.fn()}
        />
      </I18nProvider>
    </AppearanceProvider>,
  );
}
function dialog(input: WorkspaceInput["tabs"] = tabs, locale: "en" | "zh-Hans" = "en") {
  const onOpen = vi.fn();
  const onClose = vi.fn();
  return {
    ...render(
      <I18nProvider locale={locale}>
        <WorkspacesDialog tabs={input} active={input.length === 0 ? null : 1} onOpen={onOpen} onClose={onClose} />
      </I18nProvider>,
    ),
    onOpen,
    onClose,
  };
}

it("saves actual terminal selection, survives app remount and connects only after explicit Open", async () => {
  const app = shell();
  expect(api.workspacesOpen).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Start first" }));
  await userEvent.click(screen.getByRole("tab", { name: "Hosts" }));
  await userEvent.click(screen.getByRole("button", { name: "Start second" }));
  await userEvent.click(screen.getByRole("button", { name: "Workspaces" }));
  await screen.findByText(/No saved workspaces/);
  api.workspacesList.mockResolvedValue({ status: "ok", data: [saved] });
  await userEvent.type(screen.getByRole("textbox", { name: "Workspace name" }), "Operations");
  await userEvent.click(screen.getByRole("button", { name: "Save workspace" }));
  await screen.findByText("Operations");
  expect(api.workspacesCreate).toHaveBeenCalledWith({ name: "Operations", tabs, active: 1, forwards: [] });
  expect(api.workspacesOpen).not.toHaveBeenCalled();
  app.unmount();
  shell();
  expect(screen.queryAllByTestId("session")).toHaveLength(0);
  await userEvent.click(screen.getByRole("button", { name: "Start first" }));
  const existingSessionId = screen.getByTestId("session").dataset.session;
  expect(existingSessionId).toBe(screen.getByTestId("session").closest<HTMLElement>("[data-pane-id]")!.dataset.paneId);
  await userEvent.click(screen.getByRole("button", { name: "Workspaces" }));
  await screen.findByText("Operations");
  expect(api.workspacesOpen).not.toHaveBeenCalled();
  api.workspacesOpen.mockResolvedValue({
    status: "ok",
    data: {
      tabs: [
        openedTab("fresh-first", "login-first", "Restored first"),
        openedTab("fresh-second", "login-second", "Restored second"),
      ],
      active: 1,
      forwards: [],
    },
  });
  await userEvent.click(screen.getByRole("button", { name: "Open workspace" }));
  await waitFor(() => expect(screen.getAllByTestId("session")).toHaveLength(3));
  expect(screen.getAllByTestId("session").map((entry) => entry.textContent)).toEqual([
    "login-first",
    "login-first",
    "login-second",
  ]);
  expect(screen.getAllByTestId("session").map((entry) => entry.dataset.session)).toEqual([
    existingSessionId,
    "fresh-first",
    "fresh-second",
  ]);
  expect(screen.getByRole("tab", { name: "Restored second" }).getAttribute("aria-selected")).toBe("true");
  api.workspacesOpen.mockResolvedValue({
    status: "ok",
    data: {
      tabs: [
        openedTab("fresh-third", "login-first", "Another first"),
        openedTab("fresh-fourth", "login-second", "Another second"),
      ],
      active: null,
      forwards: [],
    },
  });
  await userEvent.click(screen.getByRole("button", { name: "Workspaces" }));
  await userEvent.click(await screen.findByRole("button", { name: "Open workspace" }));
  await waitFor(() => expect(screen.getAllByTestId("session")).toHaveLength(5));
  expect(screen.getByRole("tab", { name: "Hosts" }).getAttribute("aria-selected")).toBe("true");
  expect(
    screen
      .getAllByTestId("session")
      .slice(-2)
      .map((entry) => entry.dataset.session),
  ).toEqual(["fresh-third", "fresh-fourth"]);
});

it("retains unavailable definitions separately, disables Open and explicitly deletes after review", async () => {
  const unavailable: WorkspaceView = {
    ...saved,
    id: "unavailable",
    name: "Future layout",
    issue: { kind: "unsupportedLayout" },
  };
  api.workspacesList.mockResolvedValue({ status: "ok", data: [saved, unavailable] });
  const fixture = dialog();
  const heading = await screen.findByRole("heading", { name: "Unavailable workspaces" });
  const section = heading.closest("section")!;
  expect((within(section).getByRole("button", { name: "Open workspace" }) as HTMLButtonElement).disabled).toBe(true);
  expect(api.workspacesOpen).not.toHaveBeenCalled();
  await userEvent.click(within(section).getByRole("button", { name: "Delete workspace" }));
  expect(api.workspacesDelete).not.toHaveBeenCalled();
  api.workspacesList.mockResolvedValue({ status: "ok", data: [saved] });
  await userEvent.click(screen.getByRole("button", { name: "Delete workspace" }));
  await waitFor(() => expect(api.workspacesDelete).toHaveBeenCalledWith("unavailable"));
  await waitFor(() => expect(screen.queryByText("Future layout")).toBeNull());
  expect(fixture.onOpen).not.toHaveBeenCalled();
});

it.each([{ input: [] }, { input: [...tabs, { tree: { kind: "savedOutput" }, focused: 0 }] }])(
  "refuses unsavable tab intent without omitting offline tabs",
  async ({ input }) => {
    dialog(input as WorkspaceInput["tabs"]);
    await screen.findByText(/No saved workspaces/);
    expect((screen.getByRole("button", { name: "Save workspace" }) as HTMLButtonElement).disabled).toBe(true);
    expect(api.workspacesCreate).not.toHaveBeenCalled();
    expect(api.workspacesOpen).not.toHaveBeenCalled();
  },
);

it("preserves existing tabs after Open failure and renders the fixed repair reason", async () => {
  api.workspacesList.mockResolvedValue({ status: "ok", data: [saved] });
  api.workspacesOpen.mockResolvedValue({ status: "error", error: { kind: "missingDependency" } });
  const fixture = dialog();
  await userEvent.click(await screen.findByRole("button", { name: "Open workspace" }));
  expect((await screen.findByRole("alert")).textContent).toContain("Repair the inventory");
  expect(fixture.onOpen).not.toHaveBeenCalled();
  expect(fixture.onClose).not.toHaveBeenCalled();
});

it.each(["en", "zh-Hans"] as const)(
  "provides localized loading/error/retry and keyboard actions in %s",
  async (locale) => {
    api.workspacesList.mockResolvedValueOnce({ status: "error", error: { kind: "storage" } });
    dialog(tabs, locale);
    await screen.findByRole("alert");
    api.workspacesList.mockResolvedValue({ status: "ok", data: [saved] });
    const refresh = screen.getByRole("button", { name: locale === "en" ? "Refresh workspaces" : "刷新工作区" });
    refresh.focus();
    await userEvent.keyboard("{Enter}");
    await screen.findByText("Operations");
    expect(await violations(screen.getByRole("dialog"))).toEqual([]);
    expect(api.workspacesOpen).not.toHaveBeenCalled();
  },
);

async function choices() {
  const inventory = sampleInventory(sampleHosts());
  const forwards = await inventory.forwards();
  const profiles = await inventory.accessProfiles();
  if (forwards.status !== "ok" || profiles.status !== "ok") throw new Error("fixture inventory unavailable");
  api.inventoryForwards.mockResolvedValue(forwards);
  api.inventoryAccessProfiles.mockResolvedValue(profiles);
  const profile = profiles.data.find((entry) => entry.id === "l-3")!;
  return { forwards: forwards.data, profile, label: `${profile.hostName} · ${profile.name ?? profile.username}` };
}

it.each([false, true])(
  "saves explicit saved tunnel Logins with tunnel-only=%s and starts nothing",
  async (onlyTunnels) => {
    const inventory = await choices();
    const app = dialog(onlyTunnels ? [] : tabs);
    const local = await screen.findByRole("combobox", { name: "Login for postgres-prod" });
    expect(screen.getByText("Login for postgres-prod", { selector: "label" })).toBeTruthy();
    expect(local.textContent).toContain("Do not include");
    await selectOption(local, inventory.label);
    await selectOption(screen.getByRole("combobox", { name: "Login for staging-socks" }), inventory.label);
    await userEvent.type(screen.getByRole("textbox", { name: "Workspace name" }), "Saved tunnels");
    await userEvent.click(screen.getByRole("button", { name: "Save workspace" }));
    await waitFor(() =>
      expect(api.workspacesCreate).toHaveBeenCalledWith({
        name: "Saved tunnels",
        tabs: onlyTunnels ? [] : tabs,
        active: onlyTunnels ? null : 1,
        forwards: [
          { forwardId: "f-db", profileId: "l-3" },
          { forwardId: "f-socks", profileId: "l-3" },
        ],
      }),
    );
    expect(api.forwardStart).not.toHaveBeenCalled();
    expect(api.workspacesOpen).not.toHaveBeenCalled();
    expect(app.onOpen).not.toHaveBeenCalled();
    expect(screen.getByRole("combobox", { name: "Login for postgres-prod" }).textContent).toContain("Do not include");
  },
);

it("keeps the full selected tunnel capture on save failure and inventory removal", async () => {
  const inventory = await choices();
  dialog([]);
  await selectOption(await screen.findByRole("combobox", { name: "Login for postgres-prod" }), inventory.label);
  api.workspacesCreate.mockResolvedValue({ status: "error", error: { kind: "missingDependency" } });
  await userEvent.type(screen.getByRole("textbox", { name: "Workspace name" }), "Retained selection");
  await userEvent.click(screen.getByRole("button", { name: "Save workspace" }));
  await screen.findByText(/Repair the inventory/);
  expect((screen.getByRole("textbox", { name: "Workspace name" }) as HTMLInputElement).value).toBe(
    "Retained selection",
  );
  api.inventoryForwards.mockResolvedValue({ status: "ok", data: [] });
  await userEvent.click(screen.getByRole("button", { name: "Refresh workspaces" }));
  await screen.findByText(/Selected tunnel f-db is unavailable/);
  await userEvent.click(screen.getByRole("button", { name: "Save workspace" }));
  expect(api.workspacesCreate).toHaveBeenLastCalledWith(
    expect.objectContaining({ forwards: [{ forwardId: "f-db", profileId: "l-3" }] }),
  );
  await userEvent.click(screen.getByRole("button", { name: "Do not include" }));
  expect((screen.getByRole("button", { name: "Save workspace" }) as HTMLButtonElement).disabled).toBe(true);
});

it("saves terminal-only intent without making unrelated tunnel inventory a dependency", async () => {
  api.inventoryForwards.mockRejectedValue(new Error("unavailable"));
  dialog();
  await screen.findByText(/Saved tunnels or Logins could not be loaded/);
  expect(screen.queryByText("Loading saved tunnels and Logins…")).toBeNull();
  await userEvent.type(screen.getByRole("textbox", { name: "Workspace name" }), "Preserved name");
  expect((screen.getByRole("button", { name: "Save workspace" }) as HTMLButtonElement).disabled).toBe(false);
  await userEvent.click(screen.getByRole("button", { name: "Save workspace" }));
  await waitFor(() =>
    expect(api.workspacesCreate).toHaveBeenCalledWith({ name: "Preserved name", tabs, active: 1, forwards: [] }),
  );
  api.inventoryForwards.mockResolvedValue({ status: "ok", data: [] });
  await userEvent.click(screen.getByRole("button", { name: "Refresh workspaces" }));
  await waitFor(() => expect(screen.queryByText(/Saved tunnels or Logins could not be loaded/)).toBeNull());
});

function pending<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

it("restores ordered saved starts, retains exact refusals and existing tabs, and dismisses only the report", async () => {
  api.workspacesList.mockResolvedValue({ status: "ok", data: [{ ...saved, forwardCount: 4 }] });
  const late = pending<{ status: "error"; error: "listenFailed" }>();
  const accepted = { runId: "accepted", revision: "1", phase: "preparing" };
  api.forwardStart
    .mockResolvedValueOnce({ status: "ok", data: accepted })
    .mockResolvedValueOnce({ status: "error", error: "alreadyRunning" })
    .mockResolvedValueOnce({ status: "error", error: "capacityReached" })
    .mockReturnValueOnce(late.promise);
  api.workspacesOpen.mockResolvedValue({
    status: "ok",
    data: {
      tabs: [openedTab("fresh", "login-second", "Restored terminal")],
      active: 0,
      forwards: ["first", "duplicate", "capacity", "endpoint"].map((name) => ({
        forwardId: name,
        profileId: `login-${name}`,
        name,
        label: `Host · ${name}`,
      })),
    },
  });
  shell();
  await userEvent.click(screen.getByRole("button", { name: "Start first" }));
  await userEvent.click(screen.getByRole("button", { name: "Workspaces" }));
  await userEvent.click(await screen.findByRole("button", { name: "Open workspace" }));
  const results = await screen.findByRole("list", { name: "Per-tunnel start results" });
  await waitFor(() => expect(api.forwardStart).toHaveBeenCalledTimes(4));
  expect(api.forwardStart.mock.calls.map(([intent]) => intent)).toEqual(
    ["first", "duplicate", "capacity", "endpoint"].map((name) => ({
      kind: "saved",
      forwardId: name,
      profileId: `login-${name}`,
    })),
  );
  expect(within(results).getByText("Start accepted")).toBeTruthy();
  expect(within(results).getByText(/already preparing, running or stopping/)).toBeTruthy();
  expect(within(results).getByText(/Waiting to start/)).toBeTruthy();
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(screen.getAllByTestId("session")).toHaveLength(2);
  expect(screen.getByRole("tab", { name: "Restored terminal" }).getAttribute("aria-selected")).toBe("true");
  expect((screen.getByRole("button", { name: "Workspaces" }) as HTMLButtonElement).disabled).toBe(true);
  await act(() => late.resolve({ status: "error", error: "listenFailed" }));
  expect(within(results).queryByText("Waiting to start")).toBeNull();
  expect(within(results).getAllByRole("listitem")).toHaveLength(4);
  expect((screen.getByRole("button", { name: "Workspaces" }) as HTMLButtonElement).disabled).toBe(false);
  await userEvent.click(screen.getByRole("button", { name: "Dismiss tunnel results" }));
  expect(screen.queryByRole("list", { name: "Per-tunnel start results" })).toBeNull();
  expect(screen.getAllByTestId("session")).toHaveLength(2);
});

it("opens a tunnel-only workspace on Hosts and offers the authoritative Tunnels page", async () => {
  api.workspacesList.mockResolvedValue({ status: "ok", data: [{ ...saved, tabCount: 0, forwardCount: 1 }] });
  api.forwardStart.mockResolvedValue({ status: "error", error: "alreadyRunning" });
  api.workspacesOpen.mockResolvedValue({
    status: "ok",
    data: {
      tabs: [],
      active: null,
      forwards: [{ forwardId: "saved", profileId: "chosen-login", name: "Saved tunnel", label: "Host · ops" }],
    },
  });
  shell();
  await userEvent.click(screen.getByRole("button", { name: "Start first" }));
  await userEvent.click(screen.getByRole("button", { name: "Workspaces" }));
  await userEvent.click(await screen.findByRole("button", { name: "Open workspace" }));
  await screen.findByText(/already preparing, running or stopping/);
  expect(screen.getByRole("tab", { name: "Hosts" }).getAttribute("aria-selected")).toBe("true");
  await userEvent.click(screen.getByRole("button", { name: "View tunnels" }));
  expect(screen.getAllByTestId("session")).toHaveLength(1);
  expect(api.forwardStart).toHaveBeenCalledTimes(1);
});

it("does not continue old-profile starts or show late results after unmount", async () => {
  api.workspacesList.mockResolvedValue({ status: "ok", data: [saved] });
  const late = pending<{ status: "error"; error: "unavailable" }>();
  api.forwardStart.mockReturnValue(late.promise);
  api.workspacesOpen.mockResolvedValue({
    status: "ok",
    data: {
      tabs: [],
      active: null,
      forwards: ["first", "second"].map((forwardId) => ({
        forwardId,
        profileId: "login",
        name: forwardId,
        label: "Host · ops",
      })),
    },
  });
  const app = shell();
  await userEvent.click(screen.getByRole("button", { name: "Workspaces" }));
  await userEvent.click(await screen.findByRole("button", { name: "Open workspace" }));
  await waitFor(() => expect(api.forwardStart).toHaveBeenCalledTimes(1));
  app.unmount();
  await act(() => late.resolve({ status: "error", error: "unavailable" }));
  expect(api.forwardStart).toHaveBeenCalledTimes(1);
});
