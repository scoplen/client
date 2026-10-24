// SPDX-License-Identifier: Apache-2.0
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import type { SessionTransferItem, SessionTransferQueueSnapshot } from "../src/ipc/bindings";
import { SessionTransferQueue } from "../src/session-transfer-queue";

const actions = vi.hoisted(() => ({ cancel: vi.fn(), acknowledge: vi.fn() }));
vi.mock("../src/ipc/bindings", () => ({
  commands: { sessionCancelTransfer: actions.cancel, sessionAcknowledgeTransfer: actions.acknowledge },
}));

function row(changes: Partial<SessionTransferItem> = {}): SessionTransferItem {
  return {
    itemId: "item-1",
    executionId: "execution-1",
    transportId: "transport-1",
    name: "archive.bin",
    direction: "upload",
    state: "queued",
    transferredBytes: "0",
    totalBytes: "4096",
    canCancel: true,
    canAcknowledge: false,
    issue: null,
    stagingMayRemain: false,
    ...changes,
  };
}

function snapshot(items: SessionTransferItem[], recent: SessionTransferItem[] = []): SessionTransferQueueSnapshot {
  return {
    sessionId: "session-1",
    queueId: "queue-1",
    revision: "1",
    capacity: 16,
    outstanding: items.length,
    pickerBusy: false,
    blocksFileOperations: items.length > 0,
    items,
    recent,
  };
}

function view(value: SessionTransferQueueSnapshot | null) {
  return (
    <I18nProvider locale="en">
      <SessionTransferQueue snapshot={value} issue={null} />
    </I18nProvider>
  );
}

beforeEach(() => {
  actions.cancel.mockReset().mockResolvedValue({ status: "ok", data: null });
  actions.acknowledge.mockReset().mockResolvedValue({ status: "ok", data: null });
});

it("cancels only the selected queue item and execution", async () => {
  render(view(snapshot([row()])));
  await userEvent.click(screen.getByRole("button", { name: "Cancel transfer of archive.bin" }));
  expect(actions.cancel).toHaveBeenCalledExactlyOnceWith("session-1", "queue-1", "item-1", "execution-1");
  expect(actions.acknowledge).not.toHaveBeenCalled();
  expect(screen.getByText("Queued")).toBeTruthy();
});

it("keeps 100 percent separate from a saved result and respects the core publication boundary", () => {
  render(view(snapshot([row({ state: "finalizing", transferredBytes: "4096", canCancel: false })])));
  expect(screen.getByText("Verifying and saving")).toBeTruthy();
  expect(screen.queryByText("Saved")).toBeNull();
  expect(screen.getByRole("progressbar", { name: "Transfer progress for archive.bin" }).getAttribute("value")).toBe(
    "100",
  );
  expect(screen.queryByRole("button", { name: /Cancel transfer/ })).toBeNull();
});

it("acknowledges an unknown result without inventing success or replaying it", async () => {
  render(
    view(snapshot([row({ state: "unknown", canCancel: false, canAcknowledge: true, issue: "publicationUnknown" })])),
  );
  expect(screen.getByText("Save result unknown")).toBeTruthy();
  expect(screen.getByText(/Dismiss only clears this reminder/)).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: "Dismiss unknown-result reminder for archive.bin" }));
  expect(actions.acknowledge).toHaveBeenCalledExactlyOnceWith("session-1", "queue-1", "item-1", "execution-1");
  expect(actions.cancel).not.toHaveBeenCalled();
  expect(screen.getByText("Save result unknown")).toBeTruthy();
  expect(screen.queryByText("Saved")).toBeNull();
});

it("shows typed failure feedback without exposing a thrown command message", async () => {
  actions.cancel.mockRejectedValueOnce(new Error("synthetic private native detail"));
  render(view(snapshot([row()])));
  await userEvent.click(screen.getByRole("button", { name: "Cancel transfer of archive.bin" }));
  await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("transfer or status request failed"));
  expect(screen.queryByText(/synthetic private/)).toBeNull();
});

it("drops an uncertain action error when a fresh snapshot proves the item settled", async () => {
  actions.acknowledge.mockRejectedValueOnce(new Error("lost acknowledgement"));
  const rendered = render(view(snapshot([row({ state: "unknown", canCancel: false, canAcknowledge: true })])));
  await userEvent.click(screen.getByRole("button", { name: "Dismiss unknown-result reminder for archive.bin" }));
  await screen.findByRole("alert");
  rendered.rerender(view(snapshot([])));
  expect(screen.queryByRole("alert")).toBeNull();
  expect(actions.acknowledge).toHaveBeenCalledTimes(1);
  expect(actions.cancel).not.toHaveBeenCalled();
});

it("allows a distinct action after a snapshot settles an action whose reply is still pending", async () => {
  actions.acknowledge.mockReturnValueOnce(new Promise(() => {}));
  const first = row({ state: "unknown", canCancel: false, canAcknowledge: true });
  const rendered = render(view(snapshot([first])));
  await userEvent.click(screen.getByRole("button", { name: "Dismiss unknown-result reminder for archive.bin" }));
  rendered.rerender(view(snapshot([row({ itemId: "item-2", executionId: "execution-2", name: "next.bin" })])));
  await userEvent.click(screen.getByRole("button", { name: "Cancel transfer of next.bin" }));
  expect(actions.cancel).toHaveBeenCalledExactlyOnceWith("session-1", "queue-1", "item-2", "execution-2");
  expect(actions.acknowledge).toHaveBeenCalledTimes(1);
});

it("renders empty, interrupted and confirmed recent results without retry actions", () => {
  const rendered = render(view(snapshot([])));
  expect(screen.getByText("Upload a file or choose Download to add a transfer.")).toBeTruthy();
  rendered.rerender(view(snapshot([], [row({ state: "interrupted", canCancel: false })])));
  expect(screen.getByText("Connection ended · Not retried")).toBeTruthy();
  expect(screen.queryByRole("button")).toBeNull();
  expect(actions.cancel).not.toHaveBeenCalled();
});

it("does not turn invalid byte counts into a broken or misleading progress display", () => {
  render(view(snapshot([row({ state: "transferring", transferredBytes: "18446744073709551616" })])));
  expect(screen.getByText("Transferring")).toBeTruthy();
  expect(screen.queryByRole("progressbar")).toBeNull();
  expect(screen.queryByText(/NaN/)).toBeNull();
});
