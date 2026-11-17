// SPDX-License-Identifier: Apache-2.0
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import type { TeamImportPending, TeamImportPreview } from "../src/ipc/bindings";
import { TeamInventoryImportSettings } from "../src/team-inventory-import";
import { violations } from "../../ui/test/axe";
import { selectOption } from "./select-option";

const commands = vi.hoisted(() => ({
  teamsPage: vi.fn(),
  retainedTeamInventoryImports: vi.fn(),
  chooseTeamInventoryImport: vi.fn(),
  clearTeamInventoryImportPreview: vi.fn(),
  prepareTeamInventoryImport: vi.fn(),
  pendingTeamInventoryImport: vi.fn(),
  submitTeamInventoryImport: vi.fn(),
  reviewTeamInventoryImport: vi.fn(),
  discardTeamInventoryImport: vi.fn(),
}));
vi.mock("../src/account-profiles", () => ({ useProfileCommands: () => commands }));
vi.mock("../src/team-assets", () => ({ TeamAssets: () => <div role="dialog" aria-label="Team inventory" /> }));
const team = { id: "0199a653-8392-7355-8b91-70ab85182e30", name: "Operations", roles: ["unknown-role"] };
const secondTeam = { ...team, id: "0199a653-8392-7355-8b91-70ab85182e39", name: "Engineering" };
const source = {
  origin: "https://sync.example",
  accountId: "0199a653-8392-7355-8b91-70ab85182e31",
  organizationId: team.id,
};
const fields = {
  name: "Imported production",
  address: "production.example",
  port: 2202,
  username: "deploy",
  loginName: "Primary",
};
const preview: TeamImportPreview = {
  ...source,
  previewId: "opaque-review",
  source: "openSsh",
  candidates: [
    { status: "ready", ordinal: 1, fields },
    { status: "blocked", ordinal: 2, diagnostic: { code: "unsupported_option", line: 8, record: null, field: null } },
    {
      status: "ready",
      ordinal: 3,
      fields: { ...fields, name: "Other imported", address: "other.example", loginName: null },
    },
  ],
};
const pending: TeamImportPending = {
  ...source,
  operationId: "0199a653-8392-7355-8b91-70ab85182e32",
  phase: "prepared",
  canArchive: false,
  rows: [{ hostId: "0199a653-8392-7355-8b91-70ab85182e33", loginId: "0199a653-8392-7355-8b91-70ab85182e34", fields }],
};
const ok = <T,>(data: T) => ({ status: "ok" as const, data });

beforeEach(() => {
  vi.resetAllMocks();
  commands.teamsPage.mockResolvedValue(ok({ teams: [team, secondTeam], nextCursor: null }));
  commands.retainedTeamInventoryImports.mockResolvedValue(ok({ organizationIds: [], nextCursor: null }));
  commands.pendingTeamInventoryImport.mockResolvedValue(ok(null));
  commands.chooseTeamInventoryImport.mockResolvedValue(ok(preview));
  commands.clearTeamInventoryImportPreview.mockResolvedValue(ok(null));
  commands.prepareTeamInventoryImport.mockResolvedValue(ok(pending));
  commands.discardTeamInventoryImport.mockResolvedValue(ok(null));
});
afterEach(cleanup);

function view(locale: "en" | "zh-Hans" = "en") {
  return render(
    <I18nProvider locale={locale}>
      <main>
        <TeamInventoryImportSettings />
      </main>
    </I18nProvider>,
  );
}
async function selectTeam() {
  await waitFor(() =>
    expect((screen.getByRole("combobox", { name: "Destination team" }) as HTMLButtonElement).disabled).toBe(false),
  );
  await selectOption(screen.getByRole("combobox", { name: "Destination team" }), "Operations");
  await screen.findByRole("button", { name: "Choose file and preview" });
}
async function choose() {
  await selectTeam();
  await selectOption(screen.getByRole("combobox", { name: "Source format" }), "Direct OpenSSH");
  await userEvent.click(screen.getByRole("button", { name: "Choose file and preview" }));
  await screen.findByRole("list", { name: "Complete source preview" });
}

it("uses owned Select, displays every candidate and requires explicit selection and disclosure", async () => {
  const rendered = view();
  await choose();
  expect(rendered.container.querySelector("select")).toBeNull();
  expect(commands.chooseTeamInventoryImport).toHaveBeenCalledExactlyOnceWith(team.id, "openSsh", "en");
  const list = screen.getByRole("list", { name: "Complete source preview" });
  expect(within(list).getAllByRole("listitem")).toHaveLength(3);
  expect(screen.getByText(/2\. Blocked/)).toBeTruthy();
  expect(screen.getByText(/Line 8/)).toBeTruthy();
  expect(screen.getAllByRole<HTMLInputElement>("checkbox").every((box) => !box.checked)).toBe(true);
  expect((screen.getByRole("button", { name: "Review 0 selected rows" }) as HTMLButtonElement).disabled).toBe(true);
  await userEvent.click(screen.getByRole("checkbox", { name: /1\. Ready/ }));
  await userEvent.click(screen.getByRole("button", { name: "Review 1 selected rows" }));
  await screen.findByRole("button", { name: "Import reviewed rows" });
  expect(commands.prepareTeamInventoryImport).toHaveBeenCalledExactlyOnceWith(team.id, preview.previewId, [1]);
  expect(commands.submitTeamInventoryImport).not.toHaveBeenCalled();
  expect(screen.queryByRole("list", { name: "Complete source preview" })).toBeNull();
  expect(screen.getByText(/adds 1 new Host\/default-Login pairs to Operations/)).toBeTruthy();
  for (const value of [fields.name, fields.address, String(fields.port), fields.username, fields.loginName])
    expect(screen.getByText(value)).toBeTruthy();
  expect(await violations(rendered.container)).toEqual([]);
});

it("selects all Ready rows only and clears unprepared state on source/team changes", async () => {
  view();
  await choose();
  await userEvent.click(screen.getByRole("button", { name: "Select all Ready rows" }));
  expect(screen.getAllByRole<HTMLInputElement>("checkbox").every((box) => box.checked)).toBe(true);
  await userEvent.click(screen.getByRole("button", { name: "Clear selection" }));
  expect(screen.getAllByRole<HTMLInputElement>("checkbox").some((box) => box.checked)).toBe(false);
  await selectOption(screen.getByRole("combobox", { name: "Source format" }), "CSV");
  expect(screen.queryByRole("list", { name: "Complete source preview" })).toBeNull();
  expect(commands.clearTeamInventoryImportPreview).toHaveBeenCalledWith(preview.previewId);
  await userEvent.click(screen.getByRole("button", { name: "Choose file and preview" }));
  await screen.findByRole("list", { name: "Complete source preview" });
  await selectOption(screen.getByRole("combobox", { name: "Destination team" }), "Engineering");
  expect(screen.queryByRole("list", { name: "Complete source preview" })).toBeNull();
  expect(commands.prepareTeamInventoryImport).not.toHaveBeenCalled();
});

it("handles picker cancellation and localized whole-file refusal without a prefix preview", async () => {
  commands.chooseTeamInventoryImport.mockResolvedValueOnce(ok(null)).mockResolvedValueOnce({
    status: "error",
    error: { kind: "source", detail: { code: "invalid_cell", record: 2, field: "port", line: null } },
  });
  view();
  await selectTeam();
  await userEvent.click(screen.getByRole("button", { name: "Choose file and preview" }));
  expect(screen.queryByRole("list")).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Choose file and preview" }));
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("Data record 2"));
  expect(screen.queryByRole("checkbox")).toBeNull();
  expect(commands.prepareTeamInventoryImport).not.toHaveBeenCalled();
});

it("recovers a lost prepare reply and removes its consumed preview", async () => {
  view();
  await choose();
  commands.prepareTeamInventoryImport.mockRejectedValue(new Error("lost reply"));
  commands.pendingTeamInventoryImport.mockResolvedValue(ok(pending));
  await userEvent.click(screen.getByRole("checkbox", { name: /1\. Ready/ }));
  await userEvent.click(screen.getByRole("button", { name: "Review 1 selected rows" }));
  await screen.findByRole("button", { name: "Import reviewed rows" });
  expect(screen.queryByRole("list", { name: "Complete source preview" })).toBeNull();
  expect(screen.queryByRole("checkbox")).toBeNull();
  expect(commands.submitTeamInventoryImport).not.toHaveBeenCalled();
});

it("reopens Unknown without automatic sending and reloads durable state after a lost submit reply", async () => {
  commands.pendingTeamInventoryImport.mockResolvedValue(ok({ ...pending, phase: "unknown" }));
  view();
  await waitFor(() =>
    expect((screen.getByRole("combobox", { name: "Destination team" }) as HTMLButtonElement).disabled).toBe(false),
  );
  await selectOption(screen.getByRole("combobox", { name: "Destination team" }), "Operations");
  await screen.findByRole("button", { name: "Confirm original import" });
  expect(commands.submitTeamInventoryImport).not.toHaveBeenCalled();
  commands.submitTeamInventoryImport.mockRejectedValue(new Error("lost reply"));
  await userEvent.click(screen.getByRole("button", { name: "Confirm original import" }));
  await waitFor(() => expect(commands.pendingTeamInventoryImport.mock.calls.length).toBeGreaterThan(1));
  expect(commands.submitTeamInventoryImport).toHaveBeenCalledExactlyOnceWith(team.id, pending.operationId);
  expect(screen.queryByRole("button", { name: "Cancel this import" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Choose file and preview" })).toBeNull();
});

it("disables sending when ambiguous IPC recovery cannot read the saved import", async () => {
  commands.pendingTeamInventoryImport.mockResolvedValue(ok(pending));
  view();
  await waitFor(() =>
    expect((screen.getByRole("combobox", { name: "Destination team" }) as HTMLButtonElement).disabled).toBe(false),
  );
  await selectOption(screen.getByRole("combobox", { name: "Destination team" }), "Operations");
  await screen.findByRole("button", { name: "Import reviewed rows" });
  commands.submitTeamInventoryImport.mockRejectedValue(new Error("lost reply"));
  commands.pendingTeamInventoryImport.mockRejectedValue(new Error("unavailable"));
  await userEvent.click(screen.getByRole("button", { name: "Import reviewed rows" }));
  await screen.findByRole("button", { name: "Reload saved import" });
  expect((screen.getByRole("button", { name: "Import reviewed rows" }) as HTMLButtonElement).disabled).toBe(true);
  commands.pendingTeamInventoryImport.mockResolvedValue(ok({ ...pending, phase: "unknown" }));
  await userEvent.click(screen.getByRole("button", { name: "Reload saved import" }));
  await screen.findByRole("button", { name: "Confirm original import" });
  expect(commands.submitTeamInventoryImport).toHaveBeenCalledTimes(1);
});

it("retains confirmation when current member inventory refresh fails", async () => {
  commands.pendingTeamInventoryImport.mockResolvedValue(ok(pending));
  commands.submitTeamInventoryImport.mockResolvedValue(ok({ ...pending, phase: "confirmed" }));
  commands.reviewTeamInventoryImport.mockResolvedValue(
    ok({ pending: { ...pending, phase: "confirmed" }, inventory: null, error: "permissionDenied" }),
  );
  view();
  await waitFor(() =>
    expect((screen.getByRole("combobox", { name: "Destination team" }) as HTMLButtonElement).disabled).toBe(false),
  );
  await selectOption(screen.getByRole("combobox", { name: "Destination team" }), "Operations");
  await screen.findByRole("button", { name: "Import reviewed rows" });
  commands.pendingTeamInventoryImport.mockResolvedValue(ok({ ...pending, phase: "confirmed" }));
  await userEvent.click(screen.getByRole("button", { name: "Import reviewed rows" }));
  await screen.findByRole("button", { name: "Open team inventory" });
  expect(screen.getByRole("alert").textContent).toContain("current access");
  expect(screen.queryByRole("button", { name: "Import reviewed rows" })).toBeNull();
  expect(commands.reviewTeamInventoryImport).toHaveBeenCalledExactlyOnceWith(team.id, pending.operationId);
});

it("requires an explicit inventory review attempt before expired archive even when access is refused", async () => {
  commands.pendingTeamInventoryImport.mockResolvedValue(ok({ ...pending, phase: "expired" }));
  commands.reviewTeamInventoryImport.mockResolvedValue(
    ok({ pending: { ...pending, phase: "expired", canArchive: true }, inventory: null, error: "permissionDenied" }),
  );
  view();
  await waitFor(() =>
    expect((screen.getByRole("combobox", { name: "Destination team" }) as HTMLButtonElement).disabled).toBe(false),
  );
  await selectOption(screen.getByRole("combobox", { name: "Destination team" }), "Operations");
  const archive = await screen.findByRole<HTMLButtonElement>("button", { name: "Archive expired import" });
  expect(archive.disabled).toBe(true);
  await userEvent.click(screen.getByRole("button", { name: "Refresh and review inventory" }));
  await waitFor(() => expect(archive.disabled).toBe(false));
  await userEvent.click(archive);
  await screen.findByRole("button", { name: "Choose file and preview" });
  expect(commands.submitTeamInventoryImport).not.toHaveBeenCalled();
  expect(commands.discardTeamInventoryImport).toHaveBeenCalledExactlyOnceWith(team.id, pending.operationId);
});

it("pages saved destination ids independently and makes unavailable teams recovery-only", async () => {
  commands.teamsPage.mockResolvedValue(ok({ teams: [], nextCursor: null }));
  commands.retainedTeamInventoryImports
    .mockResolvedValueOnce(ok({ organizationIds: [], nextCursor: "saved-page" }))
    .mockResolvedValueOnce(ok({ organizationIds: [team.id], nextCursor: null }));
  commands.pendingTeamInventoryImport.mockResolvedValue(ok({ ...pending, phase: "unknown" }));
  view();
  await userEvent.click(await screen.findByRole("button", { name: "Load more teams" }));
  await waitFor(() => expect(commands.retainedTeamInventoryImports).toHaveBeenCalledWith("saved-page"));
  await selectOption(screen.getByRole("combobox", { name: "Destination team" }), /Unavailable team/);
  await screen.findByRole("button", { name: "Confirm original import" });
  expect(screen.getByText(/current memberships do not include this team/)).toBeTruthy();
  expect(screen.queryByRole("combobox", { name: "Source format" })).toBeNull();
  expect(commands.teamsPage).toHaveBeenCalledTimes(1);
  expect(commands.submitTeamInventoryImport).not.toHaveBeenCalled();
});

it("discards late picker output when its Account-owned view unmounts", async () => {
  let deliver!: (result: ReturnType<typeof ok<TeamImportPreview>>) => void;
  commands.chooseTeamInventoryImport.mockImplementation(
    () =>
      new Promise((resolve) => {
        deliver = resolve;
      }),
  );
  const mounted = view();
  await selectTeam();
  await userEvent.click(screen.getByRole("button", { name: "Choose file and preview" }));
  mounted.unmount();
  await act(async () => deliver(ok(preview)));
  expect(commands.clearTeamInventoryImportPreview).toHaveBeenCalledWith(preview.previewId);
  expect(commands.prepareTeamInventoryImport).not.toHaveBeenCalled();
});

it("invalidates an unprepared review when refreshed membership no longer contains the team", async () => {
  view();
  await choose();
  commands.teamsPage.mockResolvedValue(ok({ teams: [], nextCursor: null }));
  await userEvent.click(screen.getByRole("button", { name: "Refresh teams" }));
  await waitFor(() => expect(screen.queryByRole("checkbox")).toBeNull());
  expect(commands.clearTeamInventoryImportPreview).toHaveBeenCalledWith(preview.previewId);
});

it("localizes source diagnostics and passes the current native picker language", async () => {
  view("zh-Hans");
  await waitFor(() =>
    expect((screen.getByRole("combobox", { name: "目标团队" }) as HTMLButtonElement).disabled).toBe(false),
  );
  await selectOption(screen.getByRole("combobox", { name: "目标团队" }), "Operations");
  await userEvent.click(await screen.findByRole("button", { name: "选择文件并预览" }));
  await screen.findByRole("checkbox", { name: /Imported production/ });
  expect(commands.chooseTeamInventoryImport).toHaveBeenCalledExactlyOnceWith(team.id, "csv", "zh-Hans");
  expect(screen.queryByText(/unsupported_option/)).toBeNull();
});
