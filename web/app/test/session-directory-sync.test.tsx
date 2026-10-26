// SPDX-License-Identifier: Apache-2.0
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { I18nProvider } from "../src/i18n";
import type { SessionDirectorySyncPlan, SessionTransferQueueSnapshot } from "../src/ipc/bindings";
import { SessionFiles } from "../src/session-files";

const api = vi.hoisted(() => ({
  list: vi.fn(),
  snapshot: vi.fn(),
  prepare: vi.fn(),
  apply: vi.fn(),
  discard: vi.fn(),
  cancel: vi.fn(),
}));

vi.mock("../src/ipc/bindings", () => ({
  commands: {
    sessionListFiles: api.list,
    sessionEditorSnapshot: api.snapshot,
    sessionPrepareDirectorySync: api.prepare,
    sessionApplyDirectorySync: api.apply,
    sessionDiscardDirectorySync: api.discard,
    sessionCancelFileOperation: api.cancel,
  },
}));

const queue: SessionTransferQueueSnapshot = {
  sessionId: "session-1",
  queueId: "queue-1",
  revision: "1",
  capacity: 16,
  outstanding: 0,
  pickerBusy: false,
  blocksFileOperations: false,
  items: [],
  recent: [],
};

function plan(changes: Partial<SessionDirectorySyncPlan> = {}): SessionDirectorySyncPlan {
  return {
    planId: "plan-1",
    sessionId: "session-1",
    transportId: "transport-1",
    direction: "upload",
    remoteName: "./config",
    localName: "config",
    excludedDirectories: 2,
    entries: [
      { name: "new.conf", change: "create", sourceSizeBytes: "4", targetSizeBytes: null },
      { name: "changed.conf", change: "changed", sourceSizeBytes: "8", targetSizeBytes: "8" },
      { name: "same.conf", change: "same", sourceSizeBytes: "0", targetSizeBytes: "0" },
    ],
    ...changes,
  };
}

function view({
  transportId = "transport-1" as string | null,
  active = true,
  locale = "en" as "en" | "zh-Hans",
  transfers = queue,
} = {}) {
  return (
    <I18nProvider locale={locale}>
      <SessionFiles
        sessionId="session-1"
        transportId={transportId}
        connectionLabel="operator@example"
        active={active}
        queue={transfers}
        queueIssue={null}
        onClose={vi.fn()}
        onFileOutcome={vi.fn()}
        onEnqueueFeedback={vi.fn()}
      />
    </I18nProvider>
  );
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}

beforeEach(() => {
  mockIPC(() => undefined);
  api.list.mockReset().mockResolvedValue({ status: "ok", data: { entries: [] } });
  api.snapshot.mockReset().mockResolvedValue({ status: "ok", data: null });
  api.prepare.mockReset().mockImplementation(async (...args: unknown[]) => ({
    status: "ok",
    data: { kind: "prepared", plan: plan({ direction: args[4] as "upload" | "download" }) },
  }));
  api.apply.mockReset().mockResolvedValue({
    status: "ok",
    data: {
      kind: "queued",
      queueId: "queue-1",
      items: [
        { itemId: "item-1", executionId: "execution-1" },
        { itemId: "item-2", executionId: "execution-2" },
      ],
    },
  });
  api.discard.mockReset().mockResolvedValue({ status: "ok", data: null });
  api.cancel.mockReset().mockResolvedValue({ status: "ok", data: null });
});

afterEach(() => clearMocks());

async function open() {
  const button = await screen.findByRole("button", { name: "Compare folder files" });
  await waitFor(() => expect(button).toHaveProperty("disabled", false));
  await userEvent.click(button);
  return screen.findByRole("dialog", { name: "Compare folder files" });
}

async function compare(direction: "upload" | "download" = "upload") {
  const dialog = await open();
  await userEvent.click(
    within(dialog).getByRole("button", {
      name: direction === "upload" ? "Compare for upload" : "Compare for download",
    }),
  );
  await screen.findByRole("list", { name: "Compared files" });
  return dialog;
}

it("discloses the current-layer scope and selects a direction before native comparison", async () => {
  render(view());
  const dialog = await open();
  expect(within(dialog).getByText(/up to 16 ordinary source files/)).toBeTruthy();
  expect(within(dialog).getByText(/outside Scoplen's encrypted storage/)).toBeTruthy();
  expect(api.prepare).not.toHaveBeenCalled();
  expect(api.apply).not.toHaveBeenCalled();
  await userEvent.click(within(dialog).getByRole("button", { name: "Compare for download" }));
  await screen.findByRole("list", { name: "Compared files" });
  expect(api.prepare).toHaveBeenCalledExactlyOnceWith(
    "session-1",
    "transport-1",
    expect.any(String),
    [46],
    "download",
    "en",
  );
  expect(screen.getByText("Download: remote folder → local folder")).toBeTruthy();
  expect(api.apply).not.toHaveBeenCalled();
});

it("shows Create, Changed and Same without writing and explicitly queues only the retained plan", async () => {
  render(view());
  await compare();
  expect(screen.getByText("Create")).toBeTruthy();
  expect(screen.getByText("Changed")).toBeTruthy();
  expect(screen.getByText("Same — skip")).toBeTruthy();
  expect(screen.getByText("2 subfolders are excluded.")).toBeTruthy();
  expect(api.apply).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Apply 2 changes" }));
  expect(api.apply).toHaveBeenCalledExactlyOnceWith("session-1", "transport-1", "plan-1", "en");
  await screen.findByText("2 files were added to the transfer queue.");
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(api.discard).not.toHaveBeenCalled();
});

it.each(["same", "empty"])("%s input cannot request zero-slot admission", async (kind) => {
  api.prepare.mockResolvedValueOnce({
    status: "ok",
    data: {
      kind: "prepared",
      plan: plan({
        entries: kind === "empty" ? [] : [plan().entries[2]!],
      }),
    },
  });
  render(view());
  const dialog = await open();
  await userEvent.click(within(dialog).getByRole("button", { name: "Compare for upload" }));
  await screen.findByText(
    kind === "empty" ? /No ordinary files in this source folder/ : /All source files have matching contents/,
  );
  expect(screen.getByRole("button", { name: "Apply 0 changes" })).toHaveProperty("disabled", true);
  expect(api.apply).not.toHaveBeenCalled();
});

it("waits for capacity for the complete batch without automatically retrying", async () => {
  const rendered = render(view({ transfers: { ...queue, outstanding: 15 } }));
  await compare();
  expect(screen.getByText("This batch needs 2 free transfer slots. Available: 1.")).toBeTruthy();
  expect(screen.getByRole("button", { name: "Apply 2 changes" })).toHaveProperty("disabled", true);
  rendered.rerender(view());
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Apply 2 changes" })).toHaveProperty("disabled", false),
  );
  expect(api.apply).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Apply 2 changes" }));
  expect(api.apply).toHaveBeenCalledTimes(1);
});

it("a full-queue rejection keeps explicit retry available without a second invocation", async () => {
  api.apply.mockResolvedValueOnce({ status: "error", error: "queueFull" });
  render(view());
  await compare();
  await userEvent.click(screen.getByRole("button", { name: "Apply 2 changes" }));
  await screen.findByText(/No files were queued. The complete batch needs/);
  expect(api.apply).toHaveBeenCalledTimes(1);
  expect(screen.getByRole("button", { name: "Apply 2 changes" })).toHaveProperty("disabled", false);
});

it("changed metadata requires a new comparison and cannot reuse its plan", async () => {
  api.apply.mockResolvedValueOnce({ status: "error", error: "fileChanged" });
  render(view());
  await compare();
  await userEvent.click(screen.getByRole("button", { name: "Apply 2 changes" }));
  await screen.findByText(/The folder contents or a reviewed file changed/);
  expect(api.discard).toHaveBeenCalledExactlyOnceWith("session-1", "plan-1");
  expect(screen.queryByRole("button", { name: "Apply 2 changes" })).toBeNull();
  expect(api.prepare).toHaveBeenCalledTimes(1);
  expect(api.apply).toHaveBeenCalledTimes(1);
});

it("closing an unapplied preview discards it and restores keyboard focus", async () => {
  render(view());
  await compare();
  await userEvent.keyboard("{Escape}");
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(api.discard).toHaveBeenCalledExactlyOnceWith("session-1", "plan-1");
  await waitFor(() =>
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Compare folder files" })),
  );
  expect(api.apply).not.toHaveBeenCalled();
});

it("closing during comparison cancels it and discards a late prepared result", async () => {
  const pending = deferred<{ status: "ok"; data: { kind: "prepared"; plan: SessionDirectorySyncPlan } }>();
  api.prepare.mockReturnValueOnce(pending.promise);
  render(view());
  const dialog = await open();
  await userEvent.click(within(dialog).getByRole("button", { name: "Compare for upload" }));
  await userEvent.click(screen.getByRole("button", { name: "Cancel comparison" }));
  expect(api.cancel).toHaveBeenCalledExactlyOnceWith("session-1", "transport-1", api.prepare.mock.calls[0]![2]);
  await act(async () => pending.resolve({ status: "ok", data: { kind: "prepared", plan: plan() } }));
  await waitFor(() => expect(api.discard).toHaveBeenCalledExactlyOnceWith("session-1", "plan-1"));
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(api.apply).not.toHaveBeenCalled();
});

it.each(["inactive", "transport"])("%s context ends unapplied authority", async (kind) => {
  const rendered = render(view());
  await compare();
  rendered.rerender(kind === "inactive" ? view({ active: false }) : view({ transportId: "transport-2" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(api.discard).toHaveBeenCalledExactlyOnceWith("session-1", "plan-1");
  expect(api.apply).not.toHaveBeenCalled();
});

it("a mismatched plan is discarded without enabling Apply", async () => {
  api.prepare.mockResolvedValueOnce({
    status: "ok",
    data: { kind: "prepared", plan: plan({ sessionId: "other-session" }) },
  });
  render(view());
  const dialog = await open();
  await userEvent.click(within(dialog).getByRole("button", { name: "Compare for upload" }));
  await screen.findByText(/This connection is unavailable/);
  expect(api.discard).toHaveBeenCalledExactlyOnceWith("session-1", "plan-1");
  expect(screen.queryByRole("list", { name: "Compared files" })).toBeNull();
});

it("one pending Apply prevents duplicate batch admission", async () => {
  const pending = deferred<{ status: "ok"; data: { kind: "unchanged" } }>();
  api.apply.mockReturnValueOnce(pending.promise);
  render(view());
  await compare();
  await userEvent.dblClick(screen.getByRole("button", { name: "Apply 2 changes" }));
  expect(api.apply).toHaveBeenCalledTimes(1);
  await act(async () => pending.resolve({ status: "ok", data: { kind: "unchanged" } }));
});

it("an uncertain Apply requires queue review without automatic comparison or replay", async () => {
  api.apply.mockRejectedValueOnce(new Error("sensitive native path"));
  render(view());
  await compare();
  await userEvent.click(screen.getByRole("button", { name: "Apply 2 changes" }));
  await screen.findByText(/The queueing result could not be confirmed/);
  expect(screen.queryByRole("button", { name: /Apply/ })).toBeNull();
  expect(screen.queryByRole("button", { name: "Compare again" })).toBeNull();
  expect(screen.queryByText(/sensitive native path/)).toBeNull();
  expect(api.prepare).toHaveBeenCalledTimes(1);
  expect(api.apply).toHaveBeenCalledTimes(1);
});

it("native cancellation permits another explicit selection without queueing", async () => {
  api.prepare.mockResolvedValueOnce({ status: "ok", data: { kind: "cancelled" } });
  render(view());
  const dialog = await open();
  await userEvent.click(within(dialog).getByRole("button", { name: "Compare for upload" }));
  await screen.findByText("Comparison was cancelled. No files were queued.");
  expect(screen.getByRole("button", { name: "Compare for download" })).toBeTruthy();
  expect(api.apply).not.toHaveBeenCalled();
});

it("shows fixed comparison failures without native exception details", async () => {
  api.prepare.mockRejectedValueOnce(new Error("sensitive native path"));
  render(view());
  const dialog = await open();
  await userEvent.click(within(dialog).getByRole("button", { name: "Compare for upload" }));
  await screen.findByText(/Folder synchronization could not be completed/);
  expect(screen.queryByText(/sensitive native path/)).toBeNull();
  expect(api.prepare).toHaveBeenCalledTimes(1);
  expect(api.apply).not.toHaveBeenCalled();
});

it("keeps Chinese direction, scope and change labels consistent", async () => {
  render(view({ locale: "zh-Hans" }));
  const button = await screen.findByRole("button", { name: "比较文件夹内文件" });
  await waitFor(() => expect(button).toHaveProperty("disabled", false));
  await userEvent.click(button);
  await userEvent.click(screen.getByRole("button", { name: "比较要下载的文件" }));
  expect(await screen.findByText("下载：远端文件夹 → 本地文件夹")).toBeTruthy();
  expect(screen.getByText("相同，跳过")).toBeTruthy();
  expect(screen.getByText("已排除 2 个子文件夹。")).toBeTruthy();
  expect(screen.getByRole("button", { name: "应用 2 项变化" })).toBeTruthy();
  expect(api.prepare.mock.calls[0]![5]).toBe("zh-Hans");
  expect(api.apply).not.toHaveBeenCalled();
});
