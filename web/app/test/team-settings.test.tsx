// SPDX-License-Identifier: Apache-2.0
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import type { TeamCreationView, TeamPageView, TeamSummary } from "../src/ipc/bindings";
import { TeamSettings } from "../src/team-settings";
import { violations } from "../../ui/test/axe";

const commands = vi.hoisted(() => ({
  pendingTeamCreation: vi.fn(),
  teamsPage: vi.fn(),
  prepareTeamCreation: vi.fn(),
  submitTeamCreation: vi.fn(),
  discardTeamCreation: vi.fn(),
}));
vi.mock("../src/account-profiles", () => ({ useProfileCommands: () => commands }));

const team: TeamSummary = { id: "0199a653-8392-7355-8b91-70ab85182e3a", name: "Operations", roles: ["owner"] };
const pending: TeamCreationView = {
  operationId: "0199a653-8392-7355-8b91-70ab85182e3b",
  name: team.name,
  phase: "prepared",
  organization: null,
  retryUntil: null,
};
const confirmed: TeamCreationView = { ...pending, phase: "confirmed", organization: team };
const unknown: TeamCreationView = { ...pending, phase: "unknown", retryUntil: "1792886400000" };

beforeEach(() => {
  vi.resetAllMocks();
  commands.pendingTeamCreation.mockResolvedValue({ status: "ok", data: null });
  commands.teamsPage.mockResolvedValue({ status: "ok", data: { teams: [team], nextCursor: null } });
  commands.prepareTeamCreation.mockResolvedValue({ status: "ok", data: pending });
  commands.submitTeamCreation.mockResolvedValue({ status: "ok", data: confirmed });
  commands.discardTeamCreation.mockResolvedValue({ status: "ok", data: null });
});
afterEach(() => cleanup());

function fixture(authenticated = true, locale: "en" | "zh-Hans" = "en") {
  const busy = vi.fn();
  const rendered = render(
    <I18nProvider locale={locale}>
      <TeamSettings authenticated={authenticated} disabled={false} onBusyChange={busy} />
    </I18nProvider>,
  );
  return { ...rendered, busy };
}

async function ready() {
  await waitFor(() =>
    expect((screen.getByRole("button", { name: "Refresh teams" }) as HTMLButtonElement).disabled).toBe(false),
  );
}

it("only reads local pending state until membership discovery is explicitly requested by keyboard", async () => {
  const { container, busy } = fixture();
  await ready();
  expect(commands.pendingTeamCreation).toHaveBeenCalledTimes(1);
  expect(commands.teamsPage).not.toHaveBeenCalled();
  expect(commands.prepareTeamCreation).not.toHaveBeenCalled();
  const refresh = screen.getByRole("button", { name: "Refresh teams" });
  refresh.focus();
  await userEvent.keyboard("{Enter}");
  const list = await screen.findByRole("list", { name: "Your teams" });
  expect(within(list).getByText(team.name)).toBeTruthy();
  expect(within(list).getByText("Your roles: Owner")).toBeTruthy();
  expect(commands.teamsPage).toHaveBeenCalledExactlyOnceWith(null);
  expect(busy.mock.calls).toEqual([[true], [false]]);
  expect(document.activeElement).toBe(refresh);
  expect(await violations(container)).toEqual([]);
});

it("creates with one explicit intent, submitting only the original Rust preparation", async () => {
  fixture();
  await ready();
  await userEvent.type(screen.getByRole("textbox", { name: "Team name" }), team.name);
  await userEvent.click(screen.getByRole("button", { name: "Create team" }));
  expect(await screen.findByText(/Team creation confirmed/)).toBeTruthy();
  expect(commands.prepareTeamCreation).toHaveBeenCalledExactlyOnceWith(team.name);
  expect(commands.submitTeamCreation).toHaveBeenCalledExactlyOnceWith(pending.operationId);
  expect(commands.teamsPage).not.toHaveBeenCalled();
  expect(screen.queryByRole("textbox")).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Done" }));
  expect(commands.discardTeamCreation).toHaveBeenCalledExactlyOnceWith(pending.operationId);
  expect(((await screen.findByRole("textbox", { name: "Team name" })) as HTMLInputElement).value).toBe("");
});

it("preserves an invalid name, localizes the field failure and never submits it", async () => {
  commands.prepareTeamCreation.mockResolvedValue({ status: "error", error: "invalidName" });
  fixture();
  await ready();
  const input = screen.getByRole("textbox", { name: "Team name" }) as HTMLInputElement;
  await userEvent.type(input, " Team ");
  await userEvent.click(screen.getByRole("button", { name: "Create team" }));
  expect((await screen.findByRole("alert")).textContent).toContain("Shorten the team name");
  expect(input.value).toBe(" Team ");
  expect(input.getAttribute("aria-invalid")).toBe("true");
  expect(commands.submitTeamCreation).not.toHaveBeenCalled();
});

it("retains an unknown creation and only explicitly retries its original operation", async () => {
  commands.pendingTeamCreation.mockResolvedValue({ status: "ok", data: unknown });
  let finish!: (value: unknown) => void;
  commands.submitTeamCreation.mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  fixture();
  await ready();
  expect(screen.getByText(/result is unconfirmed/)).toBeTruthy();
  expect(screen.queryByRole("textbox")).toBeNull();
  expect(screen.queryByRole("button", { name: "Clear this preparation" })).toBeNull();
  expect(commands.submitTeamCreation).not.toHaveBeenCalled();
  await userEvent.dblClick(screen.getByRole("button", { name: "Retry original creation" }));
  expect(commands.submitTeamCreation).toHaveBeenCalledExactlyOnceWith(pending.operationId);
  await act(async () => finish({ status: "ok", data: confirmed }));
  expect(await screen.findByText(/Team creation confirmed/)).toBeTruthy();
  expect(commands.prepareTeamCreation).not.toHaveBeenCalled();
});

it("rereads retained state after an uncertain first submission instead of allowing a second creation", async () => {
  commands.submitTeamCreation.mockResolvedValue({ status: "error", error: "outcomeUnknown" });
  commands.pendingTeamCreation
    .mockResolvedValueOnce({ status: "ok", data: null })
    .mockResolvedValue({ status: "ok", data: unknown });
  fixture();
  await ready();
  await userEvent.type(screen.getByRole("textbox", { name: "Team name" }), team.name);
  await userEvent.click(screen.getByRole("button", { name: "Create team" }));
  expect(await screen.findByRole("button", { name: "Retry original creation" })).toBeTruthy();
  expect(screen.queryByRole("textbox")).toBeNull();
  expect(commands.prepareTeamCreation).toHaveBeenCalledTimes(1);
  expect(commands.submitTeamCreation).toHaveBeenCalledTimes(1);
});

it("requires fresh discovery before clearing an expired creation and does not resubmit it", async () => {
  commands.pendingTeamCreation.mockResolvedValue({ status: "ok", data: { ...unknown, phase: "expired" } });
  fixture();
  await ready();
  const clear = screen.getByRole("button", { name: "Clear this preparation" }) as HTMLButtonElement;
  expect(clear.disabled).toBe(true);
  expect(screen.queryByRole("button", { name: "Retry original creation" })).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Refresh teams" }));
  await screen.findByRole("list", { name: "Your teams" });
  expect(clear.disabled).toBe(false);
  await userEvent.click(clear);
  expect(commands.discardTeamCreation).toHaveBeenCalledExactlyOnceWith(pending.operationId);
  expect(commands.submitTeamCreation).not.toHaveBeenCalled();
  expect(await screen.findByRole("textbox", { name: "Team name" })).toBeTruthy();
});

it("appends only an explicitly requested next page and preserves the last results after failure", async () => {
  const second = { ...team, id: "0199a653-8392-7355-8b91-70ab85182e3c", name: "Platform", roles: ["member"] };
  const first: TeamPageView = { teams: [team], nextCursor: team.id };
  commands.teamsPage
    .mockResolvedValueOnce({ status: "ok", data: first })
    .mockResolvedValueOnce({ status: "ok", data: { teams: [second], nextCursor: null } })
    .mockResolvedValue({ status: "error", error: "network" });
  fixture();
  await ready();
  await userEvent.click(screen.getByRole("button", { name: "Refresh teams" }));
  await userEvent.click(await screen.findByRole("button", { name: "Load more teams" }));
  expect(await screen.findByText(second.name)).toBeTruthy();
  expect(commands.teamsPage.mock.calls).toEqual([[null], [team.id]]);
  await userEvent.click(screen.getByRole("button", { name: "Refresh teams" }));
  expect(await screen.findByRole("alert")).toBeTruthy();
  expect(screen.getByText(team.name)).toBeTruthy();
  expect(screen.getByText(second.name)).toBeTruthy();
});

it("renders remote names and unknown roles literally without exposing administration actions", async () => {
  commands.teamsPage.mockResolvedValue({
    status: "ok",
    data: { teams: [{ ...team, name: "<script>team</script>", roles: ["owner", "custom_role"] }], nextCursor: null },
  });
  const { container } = fixture();
  await ready();
  await userEvent.click(screen.getByRole("button", { name: "Refresh teams" }));
  expect(await screen.findByText("<script>team</script>")).toBeTruthy();
  expect(screen.getByText("Your roles: Owner, custom_role")).toBeTruthy();
  expect(container.querySelector("script")).toBeNull();
  expect(screen.queryByRole("button", { name: /admin|invite/i })).toBeNull();
});

it("shows an empty discovery with a visible creation action", async () => {
  commands.teamsPage.mockResolvedValue({ status: "ok", data: { teams: [], nextCursor: null } });
  fixture();
  await ready();
  await userEvent.click(screen.getByRole("button", { name: "Refresh teams" }));
  expect(await screen.findByText("You do not belong to any teams. Create one to become its owner.")).toBeTruthy();
  expect(screen.queryByRole("list", { name: "Your teams" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Load more teams" })).toBeNull();
  expect(screen.getByRole("button", { name: "Create team" })).toBeTruthy();
  expect(commands.prepareTeamCreation).not.toHaveBeenCalled();
});

it("localizes a refused creation and keeps the name for an explicit retry", async () => {
  commands.prepareTeamCreation.mockResolvedValue({ status: "error", error: "permissionDenied" });
  fixture(true, "zh-Hans");
  await waitFor(() => expect(screen.getByRole("button", { name: "刷新团队" }).hasAttribute("disabled")).toBe(false));
  const input = screen.getByRole("textbox", { name: "团队名称" }) as HTMLInputElement;
  await userEvent.type(input, team.name);
  await userEvent.click(screen.getByRole("button", { name: "创建团队" }));
  expect((await screen.findByRole("alert")).textContent).toContain("重新认证此设备");
  expect(input.value).toBe(team.name);
  expect(commands.submitTeamCreation).not.toHaveBeenCalled();
  expect(commands.prepareTeamCreation).toHaveBeenCalledTimes(1);
});

it("reads retained state offline in Chinese and keeps all network intents disabled", async () => {
  commands.pendingTeamCreation.mockResolvedValue({ status: "ok", data: unknown });
  fixture(false, "zh-Hans");
  expect(await screen.findByText(/创建结果尚未确认/)).toBeTruthy();
  expect(screen.getByRole("button", { name: "刷新团队" }).hasAttribute("disabled")).toBe(true);
  expect(screen.getByRole("button", { name: "重试原创建请求" }).hasAttribute("disabled")).toBe(true);
  expect(commands.teamsPage).not.toHaveBeenCalled();
  expect(commands.submitTeamCreation).not.toHaveBeenCalled();
});

it("does not dispatch after the captured view closes during preparation", async () => {
  let finish!: (value: unknown) => void;
  commands.prepareTeamCreation.mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const rendered = fixture();
  await ready();
  await userEvent.type(screen.getByRole("textbox", { name: "Team name" }), team.name);
  await userEvent.click(screen.getByRole("button", { name: "Create team" }));
  rendered.unmount();
  await act(async () => finish({ status: "ok", data: pending }));
  expect(commands.submitTeamCreation).not.toHaveBeenCalled();
});

it("redacts unexpected diagnostics and reloads the original pending operation", async () => {
  commands.submitTeamCreation.mockRejectedValue(new Error("private diagnostic and credentials"));
  commands.pendingTeamCreation
    .mockResolvedValueOnce({ status: "ok", data: null })
    .mockResolvedValue({ status: "ok", data: unknown });
  const { container } = fixture();
  await ready();
  await userEvent.type(screen.getByRole("textbox", { name: "Team name" }), team.name);
  await userEvent.click(screen.getByRole("button", { name: "Create team" }));
  expect(await screen.findByRole("alert")).toBeTruthy();
  expect(await screen.findByRole("button", { name: "Retry original creation" })).toBeTruthy();
  expect(container.textContent).not.toContain("private diagnostic");
});
