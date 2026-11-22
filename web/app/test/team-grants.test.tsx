// SPDX-License-Identifier: Apache-2.0
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import { TeamGrants } from "../src/team-grants";
import type { TeamGrantPageView } from "../src/ipc/bindings";

const commands = vi.hoisted(() => ({
  teamGrantsPage: vi.fn(),
  withdrawTeamGrant: vi.fn(),
}));
vi.mock("../src/account-profiles", () => ({ useProfileCommands: () => commands }));

const grant = {
  origin: "https://sync.example",
  accountId: "account",
  organizationId: "team",
  id: "0199a653-8392-7355-8b91-70ab85182e3a",
  etag: '"grant-etag"',
  membershipId: "0199a653-8392-7355-8b91-70ab85182e3b",
  hostId: "0199a653-8392-7355-8b91-70ab85182e3c",
  remoteUser: "deploy",
  validFrom: "2026-11-17T10:00:00Z",
  validUntil: "2026-11-17T11:00:00Z",
  status: "active" as const,
};
const page = (items = [grant]): TeamGrantPageView => ({
  origin: grant.origin,
  accountId: grant.accountId,
  organizationId: grant.organizationId,
  items,
  nextCursor: null,
});
const ok = <T,>(data: T) => ({ status: "ok" as const, data });

beforeEach(() => {
  vi.resetAllMocks();
  commands.teamGrantsPage.mockResolvedValue(ok(page()));
  commands.withdrawTeamGrant.mockResolvedValue(ok(null));
});
afterEach(() => cleanup());

function fixture(locale: "en" | "zh-Hans" = "en") {
  const result = render(
    <I18nProvider locale={locale}>
      <TeamGrants organizationId="team" name="Operations" onClose={vi.fn()} />
    </I18nProvider>,
  );
  return result;
}

it("loads current grants and withdraws only after explicit review", async () => {
  fixture();
  const list = await screen.findByRole("list", { name: "Current host grants" });
  expect(within(list).getByText(/deploy · Active/)).toBeTruthy();
  expect(commands.teamGrantsPage).toHaveBeenCalledExactlyOnceWith("team", null);
  await userEvent.click(within(list).getByRole("button", { name: "Withdraw grant" }));
  const confirmation = await screen.findByRole("dialog", { name: "Withdraw this host grant?" });
  expect(confirmation).toBeTruthy();
  expect(commands.withdrawTeamGrant).not.toHaveBeenCalled();
  await userEvent.click(within(confirmation).getByRole("button", { name: "Withdraw grant" }));
  await waitFor(() => expect(commands.withdrawTeamGrant).toHaveBeenCalledExactlyOnceWith("team", grant.id, grant.etag));
  expect(commands.teamGrantsPage).toHaveBeenCalledTimes(2);
});

it("shows an empty state and retains permission errors", async () => {
  commands.teamGrantsPage.mockResolvedValueOnce(ok(page([]))).mockResolvedValueOnce({
    status: "error",
    error: "permissionDenied",
  });
  fixture();
  expect(await screen.findByText("No current host grants are available to this account.")).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: "Refresh grants" }));
  expect((await screen.findByRole("alert")).textContent).toContain(
    "Your current team permission does not allow Grant administration.",
  );
});

it("uses the translated status and labels", async () => {
  fixture("zh-Hans");
  expect(await screen.findByText(/生效中/)).toBeTruthy();
  expect(screen.getByRole("button", { name: "撤回授权" })).toBeTruthy();
});
