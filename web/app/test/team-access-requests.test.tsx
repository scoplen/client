// SPDX-License-Identifier: Apache-2.0
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { StrictMode } from "react";
import { I18nProvider } from "../src/i18n";
import { TeamAccessRequests } from "../src/team-access-requests";
import { violations } from "../../ui/test/axe";
import type { TeamAccessRequestResourceView, TeamAccessRequestOperationView, SessionTarget } from "../src/ipc/bindings";

const commands = vi.hoisted(() => ({
  pendingTeamAccessRequest: vi.fn(),
  teamAccessRequestPage: vi.fn(),
  reviewTeamAccessRequest: vi.fn(),
  teamAccessRequestLogins: vi.fn(),
  checkTeamAccessRequest: vi.fn(),
  prepareTeamAccessRequest: vi.fn(),
  prepareTeamAccessRequestAction: vi.fn(),
  submitTeamAccessRequest: vi.fn(),
  discardTeamAccessRequest: vi.fn(),
}));
vi.mock("../src/account-profiles", () => ({ useProfileCommands: () => commands }));
const source = { origin: "https://sync.example", accountId: "account", organizationId: "team", deviceId: "device" };
const fields = {
  hostId: "host",
  remoteUser: "Deploy.User",
  durationSeconds: 3600,
  reason: "Review <script>\n  exact text",
};
const resource: TeamAccessRequestResourceView = {
  source,
  id: "request",
  etag: '"original"',
  createdAt: "2026-11-17T10:00:00.123Z",
  updatedAt: "2026-11-17T10:00:00.123Z",
  requesterAccountId: "account",
  requesterMembershipId: "membership",
  fields,
  expiresAt: "2026-11-18T10:00:00.123Z",
  status: "pending",
  deadlinePassed: false,
  canCancel: true,
  canDecide: false,
  canConnect: false,
  decision: null,
  grant: null,
};
const operation: TeamAccessRequestOperationView = {
  source,
  operationId: "original-operation",
  requestId: "request",
  action: "create",
  phase: "prepared",
  retryUntil: null,
  fields,
  result: null,
};
const approved = {
  ...resource,
  status: "approved",
  canCancel: false,
  canConnect: true,
  decision: { outcome: "approve", actorAccountId: "approver", decidedAt: "2026-11-17T10:30:00.456Z" },
  grant: { id: "grant", validFrom: "2026-11-17T10:30:00Z", validUntil: "2026-11-17T11:30:00Z" },
};
const target = {
  kind: "organizationAccessRequest" as const,
  source,
  profileId: "login",
  hostId: "host",
  remoteUser: fields.remoteUser,
};
const ok = <T,>(data: T) => ({ status: "ok" as const, data });
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}
beforeEach(() => {
  vi.resetAllMocks();
  commands.pendingTeamAccessRequest.mockResolvedValue(ok(null));
  commands.teamAccessRequestPage.mockImplementation(async (_id, view) =>
    ok({ source, view, items: [], nextCursor: null }),
  );
  commands.reviewTeamAccessRequest.mockResolvedValue(ok({ intentId: "original-review", resource }));
  commands.checkTeamAccessRequest.mockResolvedValue(ok({ source, fields, allowed: true, checkId: "exact-check" }));
  commands.prepareTeamAccessRequest.mockResolvedValue(ok(operation));
  commands.prepareTeamAccessRequestAction.mockResolvedValue(ok({ ...operation, action: "approve" }));
  commands.submitTeamAccessRequest.mockResolvedValue(ok({ ...operation, phase: "confirmed", result: resource }));
  commands.discardTeamAccessRequest.mockResolvedValue(ok(null));
  commands.teamAccessRequestLogins.mockResolvedValue(ok([{ name: "Deploy", target }]));
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});
function fixture({
  denied = false,
  locale = "en",
  organizationId = "team",
  onConnect = vi.fn(),
}: {
  denied?: boolean;
  locale?: "en" | "zh-Hans";
  organizationId?: string;
  onConnect?: (target: SessionTarget) => void;
} = {}) {
  const props = {
    organizationId,
    name: "Operations",
    onClose: vi.fn(),
    onConnect,
    ...(denied
      ? {
          denial: {
            sessionId: "failed-session",
            target: { source, hostId: fields.hostId, remoteUser: fields.remoteUser },
          },
        }
      : {}),
  };
  const result = render(
    <I18nProvider locale={locale}>
      <TeamAccessRequests {...props} />
    </I18nProvider>,
  );
  return { ...result, props };
}
async function loaded() {
  await waitFor(() =>
    expect((screen.getByRole("button", { name: "Refresh and review" }) as HTMLButtonElement).disabled).toBe(false),
  );
}
async function showRequest(item = resource) {
  commands.teamAccessRequestPage.mockResolvedValue(ok({ source, view: "mine", items: [item], nextCursor: null }));
  commands.reviewTeamAccessRequest.mockResolvedValue(ok({ intentId: "original-review", resource: item }));
  fixture();
  await loaded();
  await userEvent.click(screen.getByRole("button", { name: "Review request" }));
}

it("opens with real read intents only and keeps an empty inbox refreshing", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
  const result = fixture();
  await loaded();
  expect(commands.teamAccessRequestPage).toHaveBeenCalledExactlyOnceWith("team", "mine", null);
  await user.click(screen.getByRole("combobox", { name: "Request view" }));
  await user.click(await screen.findByRole("option", { name: "Approvals" }));
  expect(await screen.findByText(/No pending requests/)).toBeTruthy();
  const calls = commands.teamAccessRequestPage.mock.calls.length;
  await act(async () => {
    await vi.advanceTimersByTimeAsync(60_000);
  });
  expect(commands.teamAccessRequestPage).toHaveBeenCalledTimes(calls + 1);
  expect(commands.teamAccessRequestPage).toHaveBeenLastCalledWith("team", "approvals", null);
  expect(commands.submitTeamAccessRequest).not.toHaveBeenCalled();
  expect(result.container.querySelector("select")).toBeNull();
});

it("checks only the failed session and exact editable text, invalidates edits, and creates only on explicit intent", async () => {
  fixture({ denied: true });
  await loaded();
  expect(screen.queryByRole("button", { name: "Request access" })).toBeNull();
  await userEvent.type(screen.getByRole("textbox", { name: "Reason" }), fields.reason);
  await userEvent.click(screen.getByRole("button", { name: "Check request" }));
  expect(commands.checkTeamAccessRequest).toHaveBeenCalledExactlyOnceWith("failed-session", {
    durationSeconds: 3600,
    reason: fields.reason,
  });
  expect(commands.prepareTeamAccessRequest).not.toHaveBeenCalled();
  await userEvent.type(screen.getByRole("textbox", { name: "Reason" }), "!");
  expect(screen.queryByRole("button", { name: "Request access" })).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Check request" }));
  await userEvent.click(await screen.findByRole("button", { name: "Request access" }));
  await screen.findByText(/The original action is confirmed/);
  expect(commands.prepareTeamAccessRequest).toHaveBeenCalledExactlyOnceWith("exact-check");
  expect(commands.submitTeamAccessRequest).toHaveBeenCalledExactlyOnceWith("team", "original-operation");
  expect(commands.teamAccessRequestLogins).not.toHaveBeenCalled();
  expect(commands.teamAccessRequestPage.mock.calls.length).toBeGreaterThan(1);
});

it("does not offer creation after a denied check or a check failure", async () => {
  commands.checkTeamAccessRequest
    .mockResolvedValueOnce(ok({ source, fields, allowed: false, checkId: null }))
    .mockResolvedValueOnce({ status: "error", error: "permissionDenied" });
  fixture({ denied: true });
  await loaded();
  await userEvent.type(screen.getByRole("textbox", { name: "Reason" }), "Repair service");
  await userEvent.click(screen.getByRole("button", { name: "Check request" }));
  expect(await screen.findByText(/current team policy does not allow this request/)).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Request access" })).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Check request" }));
  await screen.findByRole("alert");
  expect(screen.queryByRole("button", { name: "Request access" })).toBeNull();
  expect(commands.prepareTeamAccessRequest).not.toHaveBeenCalled();
});

it("recovers uncertainty without replay and confirms only the retained original operation", async () => {
  commands.pendingTeamAccessRequest.mockResolvedValue(ok({ ...operation, action: "approve", phase: "unknown" }));
  fixture();
  await loaded();
  expect(commands.submitTeamAccessRequest).not.toHaveBeenCalled();
  expect(screen.queryByRole("button", { name: "Clear retained operation" })).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Confirm original result" }));
  expect(commands.submitTeamAccessRequest).toHaveBeenCalledExactlyOnceWith("team", "original-operation");
  expect(commands.prepareTeamAccessRequestAction).not.toHaveBeenCalled();
});

it("reloads Rust-owned recovery after the submit IPC reply is lost without resending", async () => {
  commands.pendingTeamAccessRequest
    .mockResolvedValueOnce(ok({ ...operation, phase: "prepared" }))
    .mockResolvedValue(ok({ ...operation, phase: "unknown" }));
  commands.submitTeamAccessRequest.mockRejectedValueOnce(new Error("lost invocation reply"));
  fixture();
  await loaded();
  await userEvent.click(screen.getByRole("button", { name: "Send original action" }));
  expect(await screen.findByRole("button", { name: "Confirm original result" })).toBeTruthy();
  expect(commands.pendingTeamAccessRequest).toHaveBeenCalledTimes(2);
  expect(commands.submitTeamAccessRequest).toHaveBeenCalledExactlyOnceWith("team", "original-operation");
  expect(commands.prepareTeamAccessRequest).not.toHaveBeenCalled();
});

it("requires an explicit successful current refresh before archiving an expired result", async () => {
  commands.pendingTeamAccessRequest.mockResolvedValue(ok({ ...operation, phase: "expired" }));
  fixture();
  await loaded();
  const archive = screen.getByRole("button", { name: "Archive uncertain operation" }) as HTMLButtonElement;
  expect(archive.disabled).toBe(true);
  commands.teamAccessRequestPage.mockResolvedValueOnce({ status: "error", error: "network" });
  await userEvent.click(screen.getByRole("button", { name: "Refresh and review" }));
  expect(archive.disabled).toBe(true);
  await userEvent.click(screen.getByRole("button", { name: "Refresh and review" }));
  await waitFor(() => expect(archive.disabled).toBe(false));
  await userEvent.click(archive);
  expect(commands.discardTeamAccessRequest).toHaveBeenCalledExactlyOnceWith("team", "original-operation");
  expect(commands.submitTeamAccessRequest).not.toHaveBeenCalled();
});

it("keeps the confirmed page when an explicitly requested next page fails and can be retried", async () => {
  const second = { ...resource, id: "request-2" };
  commands.teamAccessRequestPage
    .mockResolvedValueOnce(ok({ source, view: "mine", items: [resource], nextCursor: "request" }))
    .mockResolvedValueOnce({ status: "error", error: "network" })
    .mockResolvedValueOnce(ok({ source, view: "mine", items: [second], nextCursor: null }));
  fixture();
  await loaded();
  expect(screen.getByText(resource.id)).toBeTruthy();

  await userEvent.click(screen.getByRole("button", { name: "Load more teams" }));
  expect(await screen.findByRole("alert")).toBeTruthy();
  expect(screen.getByText(resource.id)).toBeTruthy();
  expect(screen.queryByText(second.id)).toBeNull();

  await userEvent.click(screen.getByRole("button", { name: "Load more teams" }));
  expect(await screen.findByText(second.id)).toBeTruthy();
  expect(commands.teamAccessRequestPage.mock.calls).toEqual([
    ["team", "mine", null],
    ["team", "mine", "request"],
    ["team", "mine", "request"],
  ]);
});

it.each(["approve", "deny", "cancel"] as const)(
  "reviews the full native Resource before explicit %s",
  async (action) => {
    const item = { ...resource, canDecide: action !== "cancel", canCancel: action === "cancel" };
    await showRequest(item);
    const details = await screen.findByRole("region", { name: "Request details" });
    expect(within(details).getByText(fields.reason, { normalizer: (value) => value })).toBeTruthy();
    expect(within(details).getByText(resource.requesterMembershipId)).toBeTruthy();
    expect(within(details).getByText(resource.expiresAt)).toBeTruthy();
    expect(commands.prepareTeamAccessRequestAction).not.toHaveBeenCalled();
    await userEvent.click(
      screen.getByRole("button", {
        name: { approve: "Approve request", deny: "Deny request", cancel: "Cancel request" }[action],
      }),
    );
    expect(commands.prepareTeamAccessRequestAction).toHaveBeenCalledExactlyOnceWith("original-review", action);
    expect(commands.submitTeamAccessRequest).toHaveBeenCalledExactlyOnceWith("team", "original-operation");
  },
);

it("clears a stale review without replacing the original ETag or replaying a decision", async () => {
  commands.prepareTeamAccessRequestAction.mockResolvedValue({ status: "error", error: "staleVersion" });
  await showRequest({ ...resource, canDecide: true, canCancel: false });
  await userEvent.click(screen.getByRole("button", { name: "Approve request" }));
  expect(await screen.findByRole("alert")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Approve request" })).toBeNull();
  expect(commands.submitTeamAccessRequest).not.toHaveBeenCalled();
  expect(commands.reviewTeamAccessRequest).toHaveBeenCalledTimes(1);
});

it("keeps approval history separate from a new explicit ordinary Connect", async () => {
  const onConnect = vi.fn();
  commands.teamAccessRequestPage.mockResolvedValue(ok({ source, view: "mine", items: [approved], nextCursor: null }));
  commands.reviewTeamAccessRequest.mockResolvedValue(ok({ intentId: "approved-review", resource: approved }));
  fixture({ onConnect });
  await loaded();
  await userEvent.click(screen.getByRole("button", { name: "Review request" }));
  const connect = await screen.findByRole("button", { name: "Connect" });
  expect(commands.teamAccessRequestLogins).toHaveBeenCalledExactlyOnceWith("approved-review");
  expect(screen.getByText(approved.grant.validUntil)).toBeTruthy();
  expect(screen.getByText(/original approval history/)).toBeTruthy();
  expect(onConnect).not.toHaveBeenCalled();
  await userEvent.click(connect);
  expect(onConnect).toHaveBeenCalledExactlyOnceWith(target);
  expect(commands.submitTeamAccessRequest).not.toHaveBeenCalled();
});

it("explains when approval has no currently visible matching Login without selecting another target", async () => {
  commands.teamAccessRequestLogins.mockResolvedValue(ok([]));
  await showRequest(approved);
  expect(await screen.findByRole("alert")).toHaveProperty(
    "textContent",
    expect.stringContaining("No visible Login matches this exact host"),
  );
  expect(screen.queryByRole("button", { name: "Connect" })).toBeNull();
});

it.each([
  { status: "pending", deadlinePassed: true },
  { status: "denied" },
  { status: "cancelled" },
  { status: "expired" },
  { status: "future_state" },
])("offers no mutation for non-actionable $status", async (patch) => {
  await showRequest({ ...resource, ...patch, canCancel: false, canDecide: false, canConnect: false });
  await screen.findByRole("region", { name: "Request details" });
  expect(screen.queryByRole("button", { name: "Approve request" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Cancel request" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Connect" })).toBeNull();
});

it("fences a late old-team page and re-reads the new team", async () => {
  const old = deferred<ReturnType<typeof ok>>();
  commands.teamAccessRequestPage.mockImplementation(async (id, view) =>
    id === "team" ? old.promise : ok({ source: { ...source, organizationId: id }, view, items: [], nextCursor: null }),
  );
  const rendered = fixture();
  await waitFor(() => expect(commands.teamAccessRequestPage).toHaveBeenCalled());
  rendered.rerender(
    <I18nProvider locale="en">
      <TeamAccessRequests {...rendered.props} organizationId="other-team" />
    </I18nProvider>,
  );
  await loaded();
  await act(async () => {
    old.resolve(ok({ source, view: "mine", items: [resource], nextCursor: null }));
  });
  expect(screen.queryByRole("button", { name: "Review request" })).toBeNull();
  expect(commands.teamAccessRequestPage).toHaveBeenLastCalledWith("other-team", "mine", null);
});

it("survives StrictMode effect replacement and renders localized themed controls accessibly", async () => {
  const rendered = render(
    <StrictMode>
      <I18nProvider locale="zh-Hans">
        <TeamAccessRequests organizationId="team" name="Operations" onClose={vi.fn()} />
      </I18nProvider>
    </StrictMode>,
  );
  await screen.findByText(/暂无申请/);
  expect(screen.getByRole("combobox", { name: "申请列表" })).toBeTruthy();
  expect(rendered.container.querySelector("select")).toBeNull();
  expect(await violations(document.body)).toEqual([]);
});
