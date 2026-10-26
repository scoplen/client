// SPDX-License-Identifier: Apache-2.0
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppearanceProvider } from "@scoplen/ui";
import { I18nProvider } from "../src/i18n";
import { Shell } from "../src/shell";
import { WorkspacesDialog } from "../src/workspaces";
import type { WorkspaceInput, WorkspaceView } from "../src/ipc/bindings";
import { violations } from "../../ui/test/axe";

const api = vi.hoisted(() => ({
  workspacesList: vi.fn(),
  workspacesCreate: vi.fn(),
  workspacesOpen: vi.fn(),
  workspacesDelete: vi.fn(),
  forwardList: vi.fn(),
}));
vi.mock("../src/account-profiles", () => ({
  useProfileCommands: () => api,
  useProfile: () => null,
  ProfileSwitcher: () => null,
}));
vi.mock("../src/ipc/store-events", () => ({ useStoreChanges: () => undefined }));
vi.mock("../src/inventory/home", () => ({
  HostsHome: ({ onConnect }: { onConnect: (id: string, name: string) => void }) => (
    <>
      <button onClick={() => onConnect("login-first", "First host")}>Start first</button>
      <button onClick={() => onConnect("login-second", "Second host")}>Start second</button>
    </>
  ),
}));
vi.mock("../src/session", () => ({
  SessionTerminal: ({ profileId, sessionId }: { profileId: string; sessionId?: string }) => (
    <p data-testid="session" data-session={sessionId}>
      {profileId}
    </p>
  ),
}));

const saved: WorkspaceView = { id: "saved-workspace", name: "Operations", tabCount: 2, issue: null };
const tabs: WorkspaceInput["tabs"] = [
  { tree: { kind: "terminal", profileId: "login-first" }, focused: 0 },
  { tree: { kind: "terminal", profileId: "login-second" }, focused: 0 },
];

const openedTab = (sessionId: string, profileId: string, label: string) => ({
  tree: { kind: "terminal", terminal: { sessionId, profileId, label } },
  focusedSessionId: sessionId,
});

beforeEach(() => {
  vi.resetAllMocks();
  api.workspacesList.mockResolvedValue({ status: "ok", data: [] });
  api.workspacesCreate.mockResolvedValue({ status: "ok", data: saved });
  api.workspacesDelete.mockResolvedValue({ status: "ok", data: null });
  api.forwardList.mockResolvedValue({ status: "ok", data: [] });
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
        <WorkspacesDialog tabs={input} active={1} onOpen={onOpen} onClose={onClose} />
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
  await userEvent.click(screen.getByRole("button", { name: "Save current tabs" }));
  await screen.findByText("Operations");
  expect(api.workspacesCreate).toHaveBeenCalledWith({ name: "Operations", tabs, active: 1 });
  expect(api.workspacesOpen).not.toHaveBeenCalled();
  app.unmount();
  shell();
  expect(screen.queryAllByTestId("session")).toHaveLength(0);
  await userEvent.click(screen.getByRole("button", { name: "Start first" }));
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
    undefined,
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
    expect((screen.getByRole("button", { name: "Save current tabs" }) as HTMLButtonElement).disabled).toBe(true);
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
