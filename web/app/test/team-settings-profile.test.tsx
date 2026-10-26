// SPDX-License-Identifier: Apache-2.0
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { emit } from "@tauri-apps/api/event";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AccountProfilesBoundary } from "../src/account-profiles";
import { I18nProvider } from "../src/i18n";
import { TeamSettings } from "../src/team-settings";

afterEach(() => {
  cleanup();
  clearMocks();
});

it.each(["read", "save"] as const)(
  "suppresses a late team %s after the actual Account generation boundary changes",
  async (phase) => {
    const team = { id: "0199a653-8392-7355-8b91-70ab85182e3a", name: "Operations", roles: ["owner"] };
    const snapshot = { generation: "1", selected: null, accounts: [], retainedProfile: false };
    const calls: string[] = [];
    let finish!: (value: unknown) => void;
    const late = new Promise((resolve) => {
      finish = resolve;
    });
    mockIPC(
      (command) => {
        calls.push(command);
        if (command === "account_profiles_snapshot") return snapshot;
        if (command === "pending_team_creation") return null;
        if (command === "teams_page") return { teams: [team], nextCursor: null };
        if (command === "team_settings") return phase === "read" ? late : { team, etag: '"captured"' };
        if (command === "update_team_name") return late;
        return null;
      },
      { shouldMockEvents: true },
    );
    render(
      <I18nProvider locale="en">
        <AccountProfilesBoundary>
          <TeamSettings authenticated disabled={false} onBusyChange={() => {}} />
        </AccountProfilesBoundary>
      </I18nProvider>,
    );
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Refresh teams" }).hasAttribute("disabled")).toBe(false),
    );
    await userEvent.click(screen.getByRole("button", { name: "Refresh teams" }));
    await userEvent.click(await screen.findByRole("button", { name: "Edit Operations" }));
    if (phase === "save") {
      await screen.findByRole("textbox", { name: "New team name" });
      await userEvent.click(screen.getByRole("button", { name: "Save team name" }));
    }
    await act(async () => {
      await emit("profile-changed", { snapshot: { ...snapshot, generation: "2" } });
    });
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Refresh teams" }).hasAttribute("disabled")).toBe(false),
    );
    await act(async () => finish({ team: { ...team, name: "Late name" }, etag: '"late"' }));
    expect(screen.queryByRole("form", { name: "Team name settings" })).toBeNull();
    expect(screen.queryByText("Team name saved.")).toBeNull();
    expect(screen.queryByText("Late name")).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(calls.filter((command) => command === "pending_team_creation")).toHaveLength(2);
    expect(calls.filter((command) => command === "update_team_name")).toHaveLength(phase === "save" ? 1 : 0);
  },
);
