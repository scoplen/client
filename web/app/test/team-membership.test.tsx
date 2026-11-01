// SPDX-License-Identifier: Apache-2.0
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import { TeamMembership } from "../src/team-membership";
import { violations } from "../../ui/test/axe";

const commands = vi.hoisted(() => ({
  pendingTeamOperations: vi.fn(),
  teamSettings: vi.fn(),
  prepareTeamInvitation: vi.fn(),
  previewTeamInvitation: vi.fn(),
  prepareTeamAcceptance: vi.fn(),
  prepareTeamDissolution: vi.fn(),
  submitTeamOperation: vi.fn(),
  discardTeamOperation: vi.fn(),
  revealTeamInvitationPassword: vi.fn(),
  copyTeamInvitationPassword: vi.fn(),
  copyTeamInvitationLink: vi.fn(),
  teamInvitations: vi.fn(),
  teamMembers: vi.fn(),
  revokeTeamInvitation: vi.fn(),
  updateTeamMember: vi.fn(),
  removeTeamMember: vi.fn(),
  teamsPage: vi.fn(),
}));
vi.mock("../src/account-profiles", () => ({ useProfileCommands: () => commands }));

const org = "0199a653-8392-7355-8b91-70ab85182e30";
const invitation = "0199a653-8392-7355-8b91-70ab85182e31";
const team = {
  team: { id: org, name: "Operations", roles: ["owner"] },
  etag: '"team-captured"',
  membershipId: "0199a653-8392-7355-8b91-70ab85182e32",
};
const link = `https://sync.example/join-team#organization=${org}&invitation=${invitation}`;
const operation = {
  operationId: "0199a653-8392-7355-8b91-70ab85182e33",
  kind: "invitation",
  organizationId: org,
  invitationId: invitation,
  recipientUsername: "teammate",
  roles: ["member"],
  phase: "prepared",
  retryUntil: null,
  link,
};
const preview = {
  id: invitation,
  organizationId: org,
  organizationName: "Operations",
  recipientUsername: "teammate",
  roles: ["member"],
  etag: '"invitation-captured"',
  status: "pending",
  expiresAt: "2026-11-02T00:00:00Z",
};
const member = {
  id: "0199a653-8392-7355-8b91-70ab85182e34",
  organizationId: org,
  etag: '"member-captured"',
  username: "teammate",
  roles: ["member"],
  status: "active",
  isSelf: false,
};
const ok = <T,>(data: T) => ({ status: "ok" as const, data });

beforeEach(() => {
  vi.resetAllMocks();
  commands.pendingTeamOperations.mockResolvedValue(ok([]));
  commands.teamSettings.mockResolvedValue(ok(team));
  commands.prepareTeamInvitation.mockResolvedValue(ok(operation));
  commands.submitTeamOperation.mockResolvedValue(ok({ ...operation, phase: "confirmed" }));
  commands.previewTeamInvitation.mockResolvedValue(ok(preview));
  commands.teamInvitations.mockResolvedValue(ok({ items: [preview], nextCursor: null }));
  commands.teamMembers.mockResolvedValue(ok({ items: [member], nextCursor: null }));
  commands.teamsPage.mockResolvedValue(ok({ teams: [], nextCursor: null }));
  commands.discardTeamOperation.mockResolvedValue(ok(null));
  commands.copyTeamInvitationPassword.mockResolvedValue(ok(null));
  commands.copyTeamInvitationLink.mockResolvedValue(ok(null));
});
afterEach(() => cleanup());

function fixture(teamId: string | null = null) {
  const close = vi.fn();
  const changed = vi.fn();
  const busy = vi.fn();
  return {
    ...render(
      <I18nProvider locale="en">
        <TeamMembership
          initialTeamId={teamId}
          disabled={false}
          onClose={close}
          onMembershipChanged={changed}
          onBusyChange={busy}
        />
      </I18nProvider>,
    ),
    close,
    changed,
    busy,
  };
}
async function ready() {
  await waitFor(() => expect(screen.queryByText("Contacting your server…")).toBeNull());
}
async function teamReady() {
  await ready();
  await userEvent.click(screen.getByRole("button", { name: "Review current team and permissions" }));
  await screen.findByRole("textbox", { name: "Existing account username" });
}

it("opens with local recovery only and renders an accessible join action", async () => {
  const { container } = fixture();
  await ready();
  expect(commands.pendingTeamOperations).toHaveBeenCalledTimes(1);
  expect(commands.previewTeamInvitation).not.toHaveBeenCalled();
  expect(commands.teamSettings).not.toHaveBeenCalled();
  expect(await violations(container)).toEqual([]);
});

it("prepares one named invitation then sends only its original operation identity", async () => {
  fixture(org);
  await teamReady();
  commands.pendingTeamOperations.mockResolvedValue(ok([{ ...operation, phase: "unknown" }]));
  commands.submitTeamOperation.mockResolvedValue({ status: "error", error: "membershipUnknown" });
  await userEvent.type(screen.getByRole("textbox", { name: "Existing account username" }), "teammate");
  await userEvent.click(screen.getByRole("button", { name: "Invite member" }));
  await screen.findByRole("button", { name: "Confirm original request" });
  expect(commands.prepareTeamInvitation).toHaveBeenCalledExactlyOnceWith(org, "teammate", ["member"]);
  expect(commands.submitTeamOperation).toHaveBeenCalledExactlyOnceWith("invitation", operation.operationId);
  await userEvent.click(screen.getByRole("button", { name: "Confirm original request" }));
  expect(commands.submitTeamOperation).toHaveBeenCalledTimes(2);
  expect(commands.prepareTeamInvitation).toHaveBeenCalledTimes(1);
  expect(screen.queryByRole("button", { name: "Dismiss confirmed operation" })).toBeNull();
});

it("clears the uncontrolled separate password immediately on acceptance submission", async () => {
  const { changed } = fixture();
  await ready();
  await userEvent.type(screen.getByRole("textbox", { name: "Public invitation link" }), link);
  await userEvent.click(screen.getByRole("button", { name: "Review invitation" }));
  const field = (await screen.findByLabelText("Separate invitation password")) as HTMLInputElement;
  await userEvent.type(field, "01234567");
  let finish!: (value: unknown) => void;
  commands.prepareTeamAcceptance.mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  await userEvent.click(screen.getByRole("button", { name: "Accept invitation" }));
  expect(field.value).toBe("");
  expect(commands.prepareTeamAcceptance).toHaveBeenCalledExactlyOnceWith(link, preview.etag, "01234567");
  const acceptance = { ...operation, kind: "acceptance", recipientUsername: null, roles: [] };
  commands.submitTeamOperation.mockResolvedValue(ok({ ...acceptance, phase: "confirmed" }));
  commands.pendingTeamOperations.mockResolvedValue(ok([{ ...acceptance, phase: "confirmed" }]));
  await act(async () => finish(ok(acceptance)));
  expect(changed).toHaveBeenCalledTimes(1);
  expect(commands.submitTeamOperation).toHaveBeenCalledExactlyOnceWith("acceptance", operation.operationId);
  expect(commands.teamsPage).toHaveBeenCalledExactlyOnceWith(null);
});

it("shows a password only in its explicit field, clears it on hide, and copies through Rust", async () => {
  commands.pendingTeamOperations.mockResolvedValue(ok([{ ...operation, phase: "confirmed" }]));
  commands.revealTeamInvitationPassword.mockResolvedValue(ok("01234567"));
  const { unmount } = fixture();
  await ready();
  const field = screen.getByLabelText("Separate invitation password") as HTMLInputElement;
  expect(field.value).toBe("");
  expect(commands.revealTeamInvitationPassword).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Reveal password" }));
  expect(field.value).toBe("01234567");
  expect(screen.queryByText("01234567")).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Hide password" }));
  expect(field.value).toBe("");
  await userEvent.click(screen.getByRole("button", { name: "Copy password" }));
  expect(commands.copyTeamInvitationPassword).toHaveBeenCalledExactlyOnceWith(operation.operationId);
  expect(field.value).toBe("");
  await userEvent.click(screen.getByRole("button", { name: "Reveal password" }));
  unmount();
  expect(field.value).toBe("");
});

it("ignores a reveal response after the password control unmounts", async () => {
  commands.pendingTeamOperations.mockResolvedValue(ok([{ ...operation, phase: "confirmed" }]));
  let finish!: (value: unknown) => void;
  commands.revealTeamInvitationPassword.mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const { unmount } = fixture();
  await ready();
  const field = screen.getByLabelText("Separate invitation password") as HTMLInputElement;
  await userEvent.click(screen.getByRole("button", { name: "Reveal password" }));
  unmount();
  await act(async () => finish(ok("01234567")));
  expect(field.value).toBe("");
});

it("requires an explicit current-status review before archiving an expired operation", async () => {
  commands.pendingTeamOperations.mockResolvedValue(ok([{ ...operation, phase: "expired" }]));
  fixture(org);
  await teamReady();
  const archive = screen.getByRole("button", { name: "Archive unresolved operation" });
  expect(archive.hasAttribute("disabled")).toBe(true);
  expect(screen.getByRole("button", { name: "Refresh invitations" }).hasAttribute("disabled")).toBe(false);
  await userEvent.click(screen.getByRole("button", { name: "Review current status" }));
  await waitFor(() => expect(archive.hasAttribute("disabled")).toBe(false));
  expect(commands.teamInvitations).toHaveBeenCalledExactlyOnceWith(org, null);
  commands.pendingTeamOperations.mockResolvedValue(ok([]));
  await userEvent.click(archive);
  expect(commands.discardTeamOperation).toHaveBeenCalledExactlyOnceWith("invitation", operation.operationId);
});

it("keeps the captured member validator and blocks another mutation until explicit review", async () => {
  commands.teamMembers
    .mockResolvedValueOnce(ok({ items: [member], nextCursor: "next-members" }))
    .mockResolvedValueOnce(ok({ items: [], nextCursor: null }));
  fixture(org);
  await teamReady();
  await userEvent.click(screen.getByRole("button", { name: "Refresh members" }));
  await userEvent.click(await screen.findByRole("button", { name: "Edit member" }));
  const form = screen.getByRole("form", { name: "Edit member" });
  await userEvent.click(within(form).getByRole("checkbox", { name: "Suspend team access" }));
  commands.updateTeamMember.mockResolvedValue({ status: "error", error: "membershipConflict" });
  await userEvent.click(within(form).getByRole("button", { name: "Save member roles and access" }));
  await screen.findByRole("alert");
  expect(commands.updateTeamMember).toHaveBeenCalledExactlyOnceWith(
    org,
    member.id,
    member.etag,
    ["member"],
    "suspended",
  );
  expect(screen.getByRole("button", { name: "Edit member" }).hasAttribute("disabled")).toBe(true);
  expect(commands.teamMembers).toHaveBeenCalledTimes(1);
  await userEvent.click(screen.getByRole("button", { name: "Load more members" }));
  expect(commands.teamMembers).toHaveBeenLastCalledWith(org, "next-members");
  expect(screen.getByRole("button", { name: "Edit member" }).hasAttribute("disabled")).toBe(true);
  await userEvent.click(screen.getByRole("button", { name: "Refresh invitations" }));
  expect(screen.getByRole("button", { name: "Edit member" }).hasAttribute("disabled")).toBe(true);
  await userEvent.click(screen.getByRole("button", { name: "Refresh members" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Edit member" }).hasAttribute("disabled")).toBe(false));
  expect(commands.updateTeamMember).toHaveBeenCalledTimes(1);
});

it("keeps stale invitation actions disabled when only another page is appended", async () => {
  commands.teamInvitations
    .mockResolvedValueOnce(ok({ items: [preview], nextCursor: "next-invitations" }))
    .mockResolvedValueOnce(ok({ items: [], nextCursor: null }));
  commands.revokeTeamInvitation.mockResolvedValue({ status: "error", error: "membershipConflict" });
  fixture(org);
  await teamReady();
  await userEvent.click(screen.getByRole("button", { name: "Refresh invitations" }));
  await userEvent.click(await screen.findByRole("button", { name: "Revoke invitation" }));
  await userEvent.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Revoke invitation" }));
  await screen.findByRole("alert");
  expect(commands.revokeTeamInvitation).toHaveBeenCalledExactlyOnceWith(org, invitation, preview.etag);
  expect(screen.getByRole("button", { name: "Revoke invitation" }).hasAttribute("disabled")).toBe(true);
  await userEvent.click(screen.getByRole("button", { name: "Load more invitations" }));
  expect(commands.teamInvitations).toHaveBeenLastCalledWith(org, "next-invitations");
  expect(screen.getByRole("button", { name: "Revoke invitation" }).hasAttribute("disabled")).toBe(true);
  await userEvent.click(screen.getByRole("button", { name: "Refresh invitations" }));
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Revoke invitation" }).hasAttribute("disabled")).toBe(false),
  );
  expect(commands.revokeTeamInvitation).toHaveBeenCalledTimes(1);
});

it("requires destructive confirmation and preserves the reviewed team precondition for dissolution", async () => {
  fixture(org);
  await teamReady();
  await userEvent.click(screen.getByRole("button", { name: "Dissolve team" }));
  const dialog = screen.getByRole("alertdialog");
  expect(within(dialog).getByText(/Personal data and other teams are retained/)).toBeTruthy();
  expect(commands.prepareTeamDissolution).not.toHaveBeenCalled();
  const dissolution = {
    ...operation,
    kind: "dissolution",
    invitationId: null,
    recipientUsername: null,
    roles: [],
    link: null,
  };
  commands.prepareTeamDissolution.mockResolvedValue(ok(dissolution));
  commands.submitTeamOperation.mockResolvedValue(ok({ ...dissolution, phase: "confirmed" }));
  await userEvent.click(within(dialog).getByRole("button", { name: "Dissolve team" }));
  expect(commands.prepareTeamDissolution).toHaveBeenCalledExactlyOnceWith(org, team.etag);
  expect(commands.submitTeamOperation).toHaveBeenCalledExactlyOnceWith("dissolution", operation.operationId);
});

it("requires current team review again after changing its own access", async () => {
  commands.teamMembers.mockResolvedValue(ok({ items: [{ ...member, isSelf: true }], nextCursor: null }));
  commands.updateTeamMember.mockResolvedValue(ok({ ...member, isSelf: true, status: "suspended" }));
  fixture(org);
  await teamReady();
  await userEvent.click(screen.getByRole("button", { name: "Refresh invitations" }));
  await screen.findByRole("button", { name: "Revoke invitation" });
  await userEvent.click(screen.getByRole("button", { name: "Refresh members" }));
  await userEvent.click(await screen.findByRole("button", { name: "Edit member" }));
  const form = screen.getByRole("form", { name: "Edit member" });
  await userEvent.click(within(form).getByRole("checkbox", { name: "Suspend team access" }));
  await userEvent.click(within(form).getByRole("button", { name: "Save member roles and access" }));
  await waitFor(() => expect(screen.queryByRole("button", { name: "Revoke invitation" })).toBeNull());
  expect(screen.queryByRole("button", { name: "Edit member" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Invite member" })).toBeNull();
  expect(screen.getByRole("button", { name: "Review current team and permissions" })).toBeTruthy();
});
