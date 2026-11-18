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
    summary: {
      filesCreate: 1,
      filesChanged: 1,
      filesSame: 1,
      directoriesCreate: 0,
      directoriesExisting: 2,
      transferSizeBytes: "12",
    },
    entries: [
      { kind: "directory", name: ".", change: "existing" },
      { kind: "directory", name: "config", change: "existing" },
      { kind: "file", name: "config/new.conf", change: "create", sourceSizeBytes: "4", targetSizeBytes: null },
      { kind: "file", name: "changed.conf", change: "changed", sourceSizeBytes: "8", targetSizeBytes: "8" },
      { kind: "file", name: "same.conf", change: "same", sourceSizeBytes: "0", targetSizeBytes: "0" },
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
      itemId: "item-1",
      executionId: "execution-1",
    },
  });
  api.discard.mockReset().mockResolvedValue({ status: "ok", data: null });
  api.cancel.mockReset().mockResolvedValue({ status: "ok", data: null });
});

afterEach(() => clearMocks());

async function open() {
  const button = await screen.findByRole("button", { name: "Compare folders" });
  await waitFor(() => expect(button).toHaveProperty("disabled", false));
  await userEvent.click(button);
  return screen.findByRole("dialog", { name: "Compare folders" });
}

async function compare(direction: "upload" | "download" = "upload") {
  const dialog = await open();
  await userEvent.click(
    within(dialog).getByRole("button", {
      name: direction === "upload" ? "Compare for upload" : "Compare for download",
    }),
  );
  await screen.findByRole("list", { name: "Compared folder contents" });
  return dialog;
}

it("discloses recursive scope and selects a direction before native comparison", async () => {
  render(view());
  const dialog = await open();
  expect(within(dialog).getByText(/Includes all subfolders and empty folders/)).toBeTruthy();
  expect(within(dialog).getByText(/outside Scoplen's encrypted storage/)).toBeTruthy();
  expect(api.prepare).not.toHaveBeenCalled();
  expect(api.apply).not.toHaveBeenCalled();
  await userEvent.click(within(dialog).getByRole("button", { name: "Compare for download" }));
  await screen.findByRole("list", { name: "Compared folder contents" });
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
  expect(screen.getByText("config/new.conf")).toBeTruthy();
  expect(
    screen.getByText(/Files to create: 1 · Files to update: 1 · Same files: 1 · Folders to create: 0/),
  ).toBeTruthy();
  expect(screen.getAllByText("Already exists")).toHaveLength(2);
  expect(api.apply).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Apply 2 changes" }));
  expect(api.apply).toHaveBeenCalledExactlyOnceWith("session-1", "transport-1", "plan-1", "en");
  await screen.findByText("Folder synchronization was added to the transfer queue.");
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(api.discard).not.toHaveBeenCalled();
});

it.each(["same", "empty"])("%s input cannot request zero-slot admission", async (kind) => {
  api.prepare.mockResolvedValueOnce({
    status: "ok",
    data: {
      kind: "prepared",
      plan: plan({
        entries: kind === "empty" ? [plan().entries[0]!] : [plan().entries[0]!, plan().entries[4]!],
        summary: {
          filesCreate: 0,
          filesChanged: 0,
          filesSame: kind === "empty" ? 0 : 1,
          directoriesCreate: 0,
          directoriesExisting: 1,
          transferSizeBytes: "0",
        },
      }),
    },
  });
  render(view());
  const dialog = await open();
  await userEvent.click(within(dialog).getByRole("button", { name: "Compare for upload" }));
  await screen.findByText(/All files match and all folders already exist/);
  expect(screen.getByRole("button", { name: "Apply 0 changes" })).toHaveProperty("disabled", true);
  expect(api.apply).not.toHaveBeenCalled();
});

it("queues a missing empty folder even when no file needs transferring", async () => {
  api.prepare.mockResolvedValueOnce({
    status: "ok",
    data: {
      kind: "prepared",
      plan: plan({
        entries: [plan().entries[0]!, { kind: "directory", name: "nested/empty", change: "create" }],
        summary: {
          filesCreate: 0,
          filesChanged: 0,
          filesSame: 0,
          directoriesCreate: 1,
          directoriesExisting: 1,
          transferSizeBytes: "0",
        },
      }),
    },
  });
  render(view({ transfers: { ...queue, outstanding: 15 } }));
  await compare();
  expect(screen.getByText("nested/empty")).toBeTruthy();
  expect(screen.queryByText(/All files match/)).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Apply 1 change" }));
  expect(api.apply).toHaveBeenCalledExactlyOnceWith("session-1", "transport-1", "plan-1", "en");
  await screen.findByText("Folder synchronization was added to the transfer queue.");
});

it("shows every row of a larger recursive plan while requiring only one queue slot", async () => {
  api.prepare.mockResolvedValueOnce({
    status: "ok",
    data: {
      kind: "prepared",
      plan: plan({
        entries: [
          plan().entries[0]!,
          { kind: "directory", name: "nested", change: "create" },
          ...Array.from({ length: 25 }, (_, index) => ({
            kind: "file" as const,
            name: `nested/file-${index}.bin`,
            change: "create" as const,
            sourceSizeBytes: "4",
            targetSizeBytes: null,
          })),
        ],
        summary: {
          filesCreate: 25,
          filesChanged: 0,
          filesSame: 0,
          directoriesCreate: 1,
          directoriesExisting: 1,
          transferSizeBytes: "100",
        },
      }),
    },
  });
  render(view({ transfers: { ...queue, outstanding: 15 } }));
  await compare();
  expect(within(screen.getByRole("list", { name: "Compared folder contents" })).getAllByRole("listitem")).toHaveLength(
    27,
  );
  expect(screen.getByRole("button", { name: "Apply 26 changes" })).toHaveProperty("disabled", false);
  expect(api.apply).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Apply 26 changes" }));
  expect(api.apply).toHaveBeenCalledTimes(1);
  await screen.findByText("Folder synchronization was added to the transfer queue.");
});

it("requires one slot for the whole tree without automatically retrying", async () => {
  const rendered = render(view({ transfers: { ...queue, outstanding: 16 } }));
  await compare();
  expect(screen.getByText(/Folder synchronization needs one free transfer slot/)).toBeTruthy();
  expect(screen.getByRole("button", { name: "Apply 2 changes" })).toHaveProperty("disabled", true);
  rendered.rerender(view({ transfers: { ...queue, outstanding: 15 } }));
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
  await screen.findByText(/Nothing was queued. Folder synchronization needs one free transfer slot/);
  expect(api.apply).toHaveBeenCalledTimes(1);
  expect(screen.getByRole("button", { name: "Apply 2 changes" })).toHaveProperty("disabled", false);
});

it("changed metadata requires a new comparison and cannot reuse its plan", async () => {
  api.apply.mockResolvedValueOnce({ status: "error", error: "fileChanged" });
  render(view());
  await compare();
  await userEvent.click(screen.getByRole("button", { name: "Apply 2 changes" }));
  await screen.findByText(/The reviewed source or destination changed/);
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
  await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: "Compare folders" })));
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
  expect(screen.queryByRole("list", { name: "Compared folder contents" })).toBeNull();
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
  await screen.findByText("The operation was cancelled. Check the queue for any completed changes.");
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
  const button = await screen.findByRole("button", { name: "比较文件夹" });
  await waitFor(() => expect(button).toHaveProperty("disabled", false));
  await userEvent.click(button);
  await userEvent.click(screen.getByRole("button", { name: "比较要下载的文件" }));
  expect(await screen.findByText("下载：远端文件夹 → 本地文件夹")).toBeTruthy();
  expect(screen.getByText("相同，跳过")).toBeTruthy();
  expect(screen.getByText(/待新建文件：1 · 待更新文件：1 · 相同文件：1 · 待创建文件夹：0/)).toBeTruthy();
  expect(screen.getByRole("button", { name: "应用 2 项变化" })).toBeTruthy();
  expect(api.prepare.mock.calls[0]![5]).toBe("zh-Hans");
  expect(api.apply).not.toHaveBeenCalled();
});
