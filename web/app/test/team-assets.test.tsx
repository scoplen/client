// SPDX-License-Identifier: Apache-2.0
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import { TeamAssets } from "../src/team-assets";
import { violations } from "../../ui/test/axe";

const commands = vi.hoisted(() => ({ refreshTeamAssets: vi.fn(), teamAssets: vi.fn() }));
vi.mock("../src/account-profiles", () => ({ useProfileCommands: () => commands }));
const team = { id: "0199a653-8392-7355-8b91-70ab85182e30", name: "Operations", roles: ["member"] };
const ready = {
  origin: "https://sync.example",
  accountId: "0199a653-8392-7355-8b91-70ab85182e31",
  organizationId: team.id,
  vaultId: "0199a653-8392-7355-8b91-70ab85182e32",
  revision: "18446744073709551615",
  phase: "ready",
  acknowledged: true,
  assets: [
    { id: "0199a653-8392-7355-8b91-70ab85182e33", kind: "Host", name: "Production host", address: "host.example" },
  ],
};
beforeEach(() => {
  vi.resetAllMocks();
  commands.refreshTeamAssets.mockResolvedValue({ status: "ok", data: ready });
  commands.teamAssets.mockResolvedValue({ status: "ok", data: ready });
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});
function fixture() {
  const close = vi.fn();
  const rendered = render(
    <I18nProvider locale="en">
      <TeamAssets team={team} onClose={close} />
    </I18nProvider>,
  );
  return { ...rendered, close };
}

it("shows the selected team's actual source and permitted assets without a fake connection action", async () => {
  fixture();
  expect(await screen.findByText("Production host")).toBeTruthy();
  expect(commands.refreshTeamAssets).toHaveBeenCalledExactlyOnceWith(team.id);
  expect(screen.getByText("https://sync.example")).toBeTruthy();
  expect(screen.getByText("host.example")).toBeTruthy();
  expect(screen.queryByRole("button", { name: /connect/i })).toBeNull();
  expect(await violations(document.body)).toEqual([]);
});

it("distinguishes a complete empty view from unavailable membership and permits explicit retry", async () => {
  commands.refreshTeamAssets.mockResolvedValueOnce({ status: "error", error: "teamNotFound" });
  fixture();
  expect((await screen.findByRole("alert")).textContent).toContain("no longer available");
  expect(screen.queryByRole("list")).toBeNull();
  commands.refreshTeamAssets.mockResolvedValueOnce({ status: "ok", data: { ...ready, assets: [] } });
  await userEvent.click(screen.getByRole("button", { name: "Refresh assets" }));
  expect(await screen.findByText(/There are no assets you can view/)).toBeTruthy();
  expect(screen.queryByRole("alert")).toBeNull();
});

it("removes previously visible rows when the core invalidates their revision", async () => {
  vi.useFakeTimers();
  fixture();
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0);
  });
  expect(screen.getByText("Production host")).toBeTruthy();
  commands.teamAssets.mockResolvedValue({ status: "ok", data: { ...ready, phase: "stale", assets: [] } });
  await act(async () => {
    await vi.advanceTimersByTimeAsync(2000);
  });
  expect(screen.queryByText("Production host")).toBeNull();
  expect(screen.getByText(/team or your permissions changed/)).toBeTruthy();
});

it("ignores a late response after the captured view closes", async () => {
  let resolve!: (result: unknown) => void;
  commands.refreshTeamAssets.mockImplementationOnce(
    () =>
      new Promise((finish) => {
        resolve = finish;
      }),
  );
  const rendered = fixture();
  await waitFor(() => expect(commands.refreshTeamAssets).toHaveBeenCalledTimes(1));
  rendered.unmount();
  await act(async () => {
    resolve({ status: "ok", data: ready });
  });
  expect(screen.queryByText("Production host")).toBeNull();
});
