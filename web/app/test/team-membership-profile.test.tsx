// SPDX-License-Identifier: Apache-2.0
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { emit } from "@tauri-apps/api/event";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AccountProfilesBoundary } from "../src/account-profiles";
import { I18nProvider } from "../src/i18n";
import { TeamMembership } from "../src/team-membership";

afterEach(() => {
  cleanup();
  clearMocks();
});

it.each(["preview", "acceptance", "reveal"] as const)(
  "drops a late %s when the actual Account generation changes",
  async (phase) => {
    const organization = "0199a653-8392-7355-8b91-70ab85182e30";
    const invitation = "0199a653-8392-7355-8b91-70ab85182e31";
    const link = `https://sync.example/join-team#organization=${organization}&invitation=${invitation}`;
    const preview = {
      id: invitation,
      etag: '"preview"',
      organizationId: organization,
      organizationName: "Operations",
      recipientUsername: "teammate",
      roles: ["member"],
      status: "pending",
      expiresAt: "2026-11-02T00:00:00Z",
    };
    const operation = {
      operationId: "0199a653-8392-7355-8b91-70ab85182e33",
      kind: "invitation",
      organizationId: organization,
      invitationId: invitation,
      recipientUsername: "teammate",
      roles: ["member"],
      phase: "confirmed",
      retryUntil: null,
      link,
    };
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
        if (command === "pending_team_operations") return phase === "reveal" ? [operation] : [];
        if (command === "preview_team_invitation") return phase === "preview" ? late : preview;
        if (command === "prepare_team_acceptance") return late;
        if (command === "reveal_team_invitation_password") return late;
        return null;
      },
      { shouldMockEvents: true },
    );
    render(
      <I18nProvider locale="en">
        <AccountProfilesBoundary>
          <TeamMembership
            initialTeamId={null}
            disabled={false}
            onClose={() => {}}
            onBusyChange={() => {}}
            onMembershipChanged={() => {}}
          />
        </AccountProfilesBoundary>
      </I18nProvider>,
    );
    await waitFor(() =>
      expect(screen.getByRole("region", { name: "Join team" }).getAttribute("aria-busy")).toBe("false"),
    );
    let oldField: HTMLInputElement | null = null;
    if (phase === "reveal") {
      oldField = screen.getByLabelText("Separate invitation password") as HTMLInputElement;
      await userEvent.click(screen.getByRole("button", { name: "Reveal password" }));
    } else {
      await userEvent.type(screen.getByRole("textbox", { name: "Public invitation link" }), link);
      await userEvent.click(screen.getByRole("button", { name: "Review invitation" }));
      if (phase === "acceptance") {
        oldField = (await screen.findByLabelText("Separate invitation password")) as HTMLInputElement;
        await userEvent.type(oldField, "01234567");
        await userEvent.click(screen.getByRole("button", { name: "Accept invitation" }));
        expect(oldField.value).toBe("");
      }
    }
    await act(async () => {
      await emit("profile-changed", { snapshot: { ...snapshot, generation: "2" } });
    });
    await act(async () =>
      finish(
        phase === "reveal"
          ? "01234567"
          : phase === "preview"
            ? preview
            : { ...operation, kind: "acceptance", phase: "prepared" },
      ),
    );
    if (oldField) expect(oldField.value).toBe("");
    expect(calls).not.toContain("submit_team_operation");
    expect(screen.queryByText("Operations")).toBeNull();
  },
);
