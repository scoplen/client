// SPDX-License-Identifier: Apache-2.0
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import type { SessionTransferItem, SessionTransferQueueSnapshot } from "../src/ipc/bindings";
import { SessionTransferQueue } from "../src/session-transfer-queue";

const actions = vi.hoisted(() => ({ cancel: vi.fn(), pause: vi.fn(), resume: vi.fn(), acknowledge: vi.fn() }));
vi.mock("../src/ipc/bindings", () => ({
  commands: {
    sessionCancelTransfer: actions.cancel,
    sessionPauseTransfer: actions.pause,
    sessionResumeTransfer: actions.resume,
    sessionAcknowledgeTransfer: actions.acknowledge,
  },
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
    canPause: false,
    canResume: false,
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

function view(value: SessionTransferQueueSnapshot | null, locale: "en" | "zh-Hans" = "en") {
  return (
    <I18nProvider locale={locale}>
      <SessionTransferQueue snapshot={value} issue={null} />
    </I18nProvider>
  );
}

beforeEach(() => {
  actions.cancel.mockReset().mockResolvedValue({ status: "ok", data: null });
  actions.pause.mockReset().mockResolvedValue({ status: "ok", data: null });
  actions.resume.mockReset().mockResolvedValue({ status: "ok", data: null });
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

it("requests Pause for the exact running download without claiming it is already paused", async () => {
  render(view(snapshot([row({ direction: "download", state: "transferring", canPause: true })])));
  await userEvent.click(screen.getByRole("button", { name: "Pause download of archive.bin" }));
  expect(actions.pause).toHaveBeenCalledExactlyOnceWith("session-1", "queue-1", "item-1", "execution-1");
  expect(actions.cancel).not.toHaveBeenCalled();
  expect(actions.resume).not.toHaveBeenCalled();
  expect(screen.getByText("Transferring")).toBeTruthy();
  expect(screen.queryByText("Paused")).toBeNull();
});

it("permits Cancel after a Pausing snapshot even if the Pause reply has been lost", async () => {
  let rejectPause!: (reason: Error) => void;
  actions.pause.mockReturnValueOnce(
    new Promise((_, reject) => {
      rejectPause = reject;
    }),
  );
  const download = row({ direction: "download", state: "transferring", canPause: true });
  const rendered = render(view(snapshot([download])));
  await userEvent.click(screen.getByRole("button", { name: "Pause download of archive.bin" }));
  rendered.rerender(view(snapshot([{ ...download, state: "pausing", canPause: false }])));
  expect(screen.getByText("Finishing the current part before pausing")).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: "Cancel transfer of archive.bin" }));
  expect(actions.cancel).toHaveBeenCalledExactlyOnceWith("session-1", "queue-1", "item-1", "execution-1");
  rejectPause(new Error("synthetic old pause error"));
  await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
  expect(screen.queryByText("Paused")).toBeNull();
});

it("allows Cancel to supersede a pending Pause before another snapshot arrives", async () => {
  actions.pause.mockReturnValueOnce(new Promise(() => {}));
  render(view(snapshot([row({ direction: "download", state: "transferring", canPause: true })])));
  await userEvent.click(screen.getByRole("button", { name: "Pause download of archive.bin" }));
  await userEvent.click(screen.getByRole("button", { name: "Cancel transfer of archive.bin" }));
  expect(actions.cancel).toHaveBeenCalledExactlyOnceWith("session-1", "queue-1", "item-1", "execution-1");
  expect(actions.pause).toHaveBeenCalledTimes(1);
});

it("allows Cancel to supersede a pending Resume and ignores its late failure", async () => {
  let rejectResume!: (reason: Error) => void;
  actions.resume.mockReturnValueOnce(
    new Promise((_, reject) => {
      rejectResume = reject;
    }),
  );
  render(view(snapshot([row({ direction: "download", state: "paused", canResume: true })])));
  await userEvent.click(screen.getByRole("button", { name: "Resume download of archive.bin" }));
  const cancel = screen.getByRole("button", { name: "Cancel transfer of archive.bin" });
  expect(cancel.hasAttribute("disabled")).toBe(false);
  await userEvent.click(cancel);
  expect(actions.cancel).toHaveBeenCalledExactlyOnceWith("session-1", "queue-1", "item-1", "execution-1");
  await act(async () => rejectResume(new Error("synthetic old resume failure")));
  expect(screen.queryByRole("alert")).toBeNull();
  expect(screen.getByText("Paused")).toBeTruthy();
});

it("does not let a late Resume success clear a newer Cancel failure", async () => {
  let finishResume!: (value: { status: "ok"; data: null }) => void;
  actions.resume.mockReturnValueOnce(
    new Promise((resolve) => {
      finishResume = resolve;
    }),
  );
  actions.cancel.mockResolvedValueOnce({ status: "error", error: "localIo" });
  render(view(snapshot([row({ direction: "download", state: "paused", canResume: true })])));
  await userEvent.click(screen.getByRole("button", { name: "Resume download of archive.bin" }));
  await userEvent.click(screen.getByRole("button", { name: "Cancel transfer of archive.bin" }));
  expect((await screen.findByRole("alert")).textContent).toContain("The local file could not be read or saved");
  await act(async () => finishResume({ status: "ok", data: null }));
  expect(screen.getByRole("alert").textContent).toContain("The local file could not be read or saved");
  expect(actions.cancel).toHaveBeenCalledExactlyOnceWith("session-1", "queue-1", "item-1", "execution-1");
});

it("resumes a retained download by keyboard using its existing item and execution", async () => {
  const user = userEvent.setup();
  render(view(snapshot([row({ direction: "download", state: "paused", canResume: true, transferredBytes: "1024" })])));
  expect(screen.getByText(/Resume joins the end of the queue/)).toBeTruthy();
  await user.tab();
  expect(document.activeElement).toBe(screen.getByRole("button", { name: "Resume download of archive.bin" }));
  await user.keyboard("{Enter}");
  expect(actions.resume).toHaveBeenCalledExactlyOnceWith("session-1", "queue-1", "item-1", "execution-1");
  expect(actions.pause).not.toHaveBeenCalled();
  expect(screen.getByText("Paused")).toBeTruthy();
  expect(screen.getByRole("progressbar").getAttribute("value")).toBe("25");
});

it("releases a lost Resume reply on the new execution and ignores its late failure", async () => {
  let rejectResume!: (reason: Error) => void;
  actions.resume.mockReturnValueOnce(
    new Promise((_, reject) => {
      rejectResume = reject;
    }),
  );
  const download = row({ direction: "download", state: "paused", canResume: true, transferredBytes: "1024" });
  const rendered = render(view(snapshot([download])));
  await userEvent.click(screen.getByRole("button", { name: "Resume download of archive.bin" }));
  rendered.rerender(
    view(snapshot([{ ...download, executionId: "execution-2", state: "validating", canResume: false }])),
  );
  expect(screen.getByText("Checking downloaded bytes")).toBeTruthy();
  expect(screen.getByRole("progressbar").getAttribute("value")).toBe("25");
  await userEvent.click(screen.getByRole("button", { name: "Cancel transfer of archive.bin" }));
  expect(actions.cancel).toHaveBeenCalledExactlyOnceWith("session-1", "queue-1", "item-1", "execution-2");
  rejectResume(new Error("synthetic old resume error"));
  await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
  expect(actions.resume).toHaveBeenCalledTimes(1);
});

it("retains absolute progress while a resumed download waits at the queue tail", () => {
  render(view(snapshot([row({ direction: "download", state: "queued", transferredBytes: "1024" })])));
  expect(screen.getByText("Queued")).toBeTruthy();
  expect(screen.getByRole("progressbar").getAttribute("value")).toBe("25");
  expect(screen.queryByRole("button", { name: /Resume download/ })).toBeNull();
});

it.each(["upload", "unknown", "interrupted", "finalizing"] as const)(
  "does not expose pause or resume for %s even with inconsistent action flags",
  (kind) => {
    render(
      view(
        snapshot([
          row({
            direction: kind === "upload" ? "upload" : "download",
            state: kind === "upload" ? "transferring" : kind,
            canPause: true,
            canResume: true,
            canCancel: false,
          }),
        ]),
      ),
    );
    expect(screen.queryByRole("button", { name: /Pause download|Resume download/ })).toBeNull();
    expect(actions.pause).not.toHaveBeenCalled();
    expect(actions.resume).not.toHaveBeenCalled();
  },
);

it("localizes paused-download controls and failures without including native error text", async () => {
  actions.resume.mockRejectedValueOnce(new Error("synthetic private checkpoint path"));
  render(view(snapshot([row({ direction: "download", state: "paused", canResume: true })]), "zh-Hans"));
  expect(screen.getByText("已暂停")).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: "继续下载 archive.bin" }));
  expect(actions.resume).toHaveBeenCalledTimes(1);
  await screen.findByRole("alert");
  expect(screen.queryByText(/synthetic private/)).toBeNull();
});
