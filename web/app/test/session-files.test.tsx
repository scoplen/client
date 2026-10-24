// SPDX-License-Identifier: Apache-2.0
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { StrictMode } from "react";
import { I18nProvider } from "../src/i18n";
import type { SessionTransferItem, SessionTransferQueueSnapshot } from "../src/ipc/bindings";
import { SessionFiles } from "../src/session-files";

const fileCommands = vi.hoisted(() => ({
  list: vi.fn(),
  preview: vi.fn(),
  download: vi.fn(),
  upload: vi.fn(),
  create: vi.fn(),
  rename: vi.fn(),
  delete: vi.fn(),
  cancel: vi.fn(),
}));

vi.mock("../src/ipc/bindings", () => ({
  commands: {
    sessionListFiles: fileCommands.list,
    sessionPreviewFile: fileCommands.preview,
    sessionEnqueueDownload: fileCommands.download,
    sessionEnqueueUpload: fileCommands.upload,
    sessionCreateRemoteDirectory: fileCommands.create,
    sessionRenameRemoteEntry: fileCommands.rename,
    sessionDeleteRemoteEntry: fileCommands.delete,
    sessionCancelFileOperation: fileCommands.cancel,
  },
}));

type Entry = { name: string; path: number[]; kind: "file" | "directory" | "other"; sizeBytes: string | null };
type Listed = { status: "ok"; data: { entries: Entry[] } } | { status: "error"; error: string };
function queue(changes: Partial<SessionTransferQueueSnapshot> = {}): SessionTransferQueueSnapshot {
  return {
    sessionId: "session-1",
    queueId: "queue-1",
    revision: "1",
    capacity: 16,
    outstanding: 0,
    pickerBusy: false,
    blocksFileOperations: false,
    items: [],
    recent: [],
    ...changes,
  };
}

const queuedItem: SessionTransferItem = {
  itemId: "item-1",
  executionId: "execution-1",
  transportId: "transport-1",
  name: "existing.bin",
  direction: "upload",
  state: "transferring",
  transferredBytes: "0",
  totalBytes: "4",
  canCancel: false,
  canPause: false,
  canResume: false,
  canAcknowledge: false,
  issue: null,
  stagingMayRemain: false,
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}

function view(
  transportId: string | null = "transport-1",
  onClose = vi.fn(),
  onUploadOutcome = vi.fn(),
  locale: "en" | "zh-Hans" = "en",
  transfers = queue(),
  active = true,
) {
  return (
    <I18nProvider locale={locale}>
      <SessionFiles
        sessionId="session-1"
        transportId={transportId}
        connectionLabel="fixture@example"
        active={active}
        onClose={onClose}
        onFileOutcome={onUploadOutcome}
        queue={transfers}
        queueIssue={null}
        onEnqueueFeedback={vi.fn()}
      />
    </I18nProvider>
  );
}

const directory: Entry = { name: "logs", path: [46, 47, 108, 111, 103, 115], kind: "directory", sizeBytes: null };
const file: Entry = { name: "raw.bin", path: [46, 47, 255, 46, 98, 105, 110], kind: "file", sizeBytes: "4" };
const other: Entry = { name: "socket", path: [46, 47, 115, 111, 99, 107, 101, 116], kind: "other", sizeBytes: null };

beforeEach(() => {
  mockIPC(() => undefined);
  fileCommands.list.mockReset().mockResolvedValue({ status: "ok", data: { entries: [] } });
  fileCommands.preview.mockReset().mockResolvedValue({ status: "ok", data: { text: "sample", sizeBytes: 6 } });
  const added = {
    status: "ok",
    data: { status: "queued", queueId: "queue-1", itemId: "item-1", executionId: "execution-1" },
  };
  fileCommands.download.mockReset().mockResolvedValue(added);
  fileCommands.upload.mockReset().mockResolvedValue(added);
  fileCommands.create.mockReset().mockResolvedValue({ status: "ok", data: { status: "saved", message: null } });
  fileCommands.rename.mockReset().mockResolvedValue({ status: "ok", data: { status: "saved", message: null } });
  fileCommands.delete.mockReset().mockResolvedValue({ status: "ok", data: { status: "saved", message: null } });
  fileCommands.cancel.mockReset().mockResolvedValue({ status: "ok", data: null });
});

afterEach(() => clearMocks());

it("previews only an explicit ordinary file and renders markup as literal text", async () => {
  const literal = '<img src="https://invalid.example/image">\r\n中文\t<a href="https://invalid.example">link</a>';
  fileCommands.list.mockResolvedValue({ status: "ok", data: { entries: [directory, file, other] } });
  fileCommands.preview.mockResolvedValueOnce({ status: "ok", data: { text: literal, sizeBytes: 96 } });
  render(view());
  const preview = await screen.findByRole("button", { name: "Preview raw.bin" });
  expect(fileCommands.preview).not.toHaveBeenCalled();
  expect(screen.queryByRole("button", { name: "Preview socket" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Preview logs" })).toBeNull();
  await userEvent.click(preview);
  expect(fileCommands.preview).toHaveBeenCalledExactlyOnceWith(
    "session-1",
    "transport-1",
    expect.any(String),
    file.path,
  );
  const content = await screen.findByLabelText("Remote file text");
  expect(content.textContent).toBe(literal);
  expect(content.querySelector("img, a, script, iframe")).toBeNull();
  expect(screen.getByText(/Read-only text from fixture@example/)).toBeTruthy();
  expect(fileCommands.download).not.toHaveBeenCalled();
  expect(fileCommands.upload).not.toHaveBeenCalled();
  expect(fileCommands.create).not.toHaveBeenCalled();
});

it("shows an empty complete preview in Chinese", async () => {
  fileCommands.list.mockResolvedValue({ status: "ok", data: { entries: [file] } });
  fileCommands.preview.mockResolvedValueOnce({ status: "ok", data: { text: "", sizeBytes: 0 } });
  render(view("transport-1", vi.fn(), vi.fn(), "zh-Hans"));
  await userEvent.click(await screen.findByRole("button", { name: "预览 raw.bin" }));
  expect(await screen.findByText("此文本文件为空。")).toBeTruthy();
  expect(screen.getByText("0 字节 · UTF-8")).toBeTruthy();
  expect(screen.queryByLabelText("远程文件文本")).toBeNull();
});

it.each([
  ["tooLarge", "256 KiB"],
  ["notText", "not supported UTF-8 text"],
  ["fileChanged", "changed while reading"],
  ["notRegularFile", "Only ordinary remote files"],
  ["missingMetadata", "file metadata needed"],
  ["remoteDenied", "server refused the preview"],
  ["timeout", "timed out"],
  ["unavailable", "file access is unavailable"],
] as const)("localizes a %s refusal and retries only after explicit intent", async (issue, message) => {
  fileCommands.list.mockResolvedValue({ status: "ok", data: { entries: [file] } });
  fileCommands.preview.mockResolvedValueOnce({ status: "error", error: issue });
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Preview raw.bin" }));
  expect((await screen.findByRole("alert")).textContent).toContain(message);
  expect(screen.getByText(/Close this preview to download/)).toBeTruthy();
  expect(fileCommands.preview).toHaveBeenCalledTimes(1);
  await userEvent.click(screen.getByRole("button", { name: "Try again" }));
  expect(await screen.findByLabelText("Remote file text")).toBeTruthy();
  expect(fileCommands.preview).toHaveBeenCalledTimes(2);
});

it("does not reveal bridge exception contents in a preview", async () => {
  fileCommands.list.mockResolvedValue({ status: "ok", data: { entries: [file] } });
  fileCommands.preview.mockRejectedValueOnce(new Error("private remote file contents"));
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Preview raw.bin" }));
  expect((await screen.findByRole("alert")).textContent).toContain("could not be previewed safely");
  expect(screen.queryByText(/private remote/)).toBeNull();
});

it("cancels closing preview and discards its late text", async () => {
  const pending = deferred<{ status: "ok"; data: { text: string; sizeBytes: number } }>();
  fileCommands.list.mockResolvedValue({ status: "ok", data: { entries: [file] } });
  fileCommands.preview.mockReturnValueOnce(pending.promise);
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Preview raw.bin" }));
  expect(await screen.findByText("Reading remote text…")).toBeTruthy();
  const operation = fileCommands.preview.mock.calls[0]?.[2];
  await userEvent.keyboard("{Escape}");
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(fileCommands.cancel).toHaveBeenCalledWith("session-1", "transport-1", operation);
  await act(async () => pending.resolve({ status: "ok", data: { text: "late private text", sizeBytes: 17 } }));
  expect(screen.queryByText("late private text")).toBeNull();
});

it("a late close acknowledgement cannot close a newer preview of the same file", async () => {
  const oldRead = deferred<{ status: "ok"; data: { text: string; sizeBytes: number } }>();
  const oldCancel = deferred<{ status: "ok"; data: null }>();
  fileCommands.list.mockResolvedValue({ status: "ok", data: { entries: [file] } });
  fileCommands.preview.mockReturnValueOnce(oldRead.promise);
  fileCommands.cancel.mockReturnValueOnce(oldCancel.promise);
  const rendered = render(view("old-transport"));
  await userEvent.click(await screen.findByRole("button", { name: "Preview raw.bin" }));
  await screen.findByText("Reading remote text…");
  await userEvent.keyboard("{Escape}");
  rendered.rerender(view("new-transport"));
  await userEvent.click(await screen.findByRole("button", { name: "Preview raw.bin" }));
  await screen.findByLabelText("Remote file text");
  await act(async () => oldCancel.resolve({ status: "ok", data: null }));
  expect(screen.getByRole("dialog")).toBeTruthy();
  expect(screen.getByLabelText("Remote file text").textContent).toBe("sample");
  await act(async () => oldRead.resolve({ status: "ok", data: { text: "stale", sizeBytes: 5 } }));
  expect(screen.queryByText("stale")).toBeNull();
});

it("discards the preview when its tab becomes inactive without reopening it on return", async () => {
  fileCommands.list.mockResolvedValue({ status: "ok", data: { entries: [file] } });
  const rendered = render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Preview raw.bin" }));
  await screen.findByLabelText("Remote file text");
  rendered.rerender(view("transport-1", vi.fn(), vi.fn(), "en", queue(), false));
  expect(screen.queryByRole("dialog")).toBeNull();
  rendered.rerender(view());
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Preview raw.bin" }).hasAttribute("disabled")).toBe(false),
  );
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(fileCommands.preview).toHaveBeenCalledTimes(1);
});

it("opens and closes preview by keyboard and returns focus to its action", async () => {
  fileCommands.list.mockResolvedValue({ status: "ok", data: { entries: [file] } });
  render(view());
  const action = await screen.findByRole("button", { name: "Preview raw.bin" });
  action.focus();
  await userEvent.keyboard("{Enter}");
  await screen.findByLabelText("Remote file text");
  expect(screen.getByRole("dialog").contains(document.activeElement)).toBe(true);
  await userEvent.keyboard("{Escape}");
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  await waitFor(() => expect(document.activeElement).toBe(action));
});

it("restores preview focus to the rebuilt action after a delayed directory response", async () => {
  const reloaded = deferred<Listed>();
  fileCommands.list
    .mockResolvedValueOnce({ status: "ok", data: { entries: [file] } })
    .mockReturnValueOnce(reloaded.promise);
  render(view());
  const oldAction = await screen.findByRole("button", { name: "Preview raw.bin" });
  oldAction.focus();
  await userEvent.keyboard("{Enter}");
  await screen.findByLabelText("Remote file text");
  await userEvent.keyboard("{Escape}");
  await waitFor(() => expect(fileCommands.list).toHaveBeenCalledTimes(2));
  expect(oldAction.isConnected).toBe(false);
  await act(async () => reloaded.resolve({ status: "ok", data: { entries: [file] } }));
  const newAction = await screen.findByRole("button", { name: "Preview raw.bin" });
  expect(newAction).not.toBe(oldAction);
  await waitFor(() => expect(document.activeElement).toBe(newAction));
});

it("blocks preview behind runnable queue work but allows it with only paused or unknown items", async () => {
  fileCommands.list.mockResolvedValue({ status: "ok", data: { entries: [file] } });
  const rendered = render(view());
  await screen.findByRole("button", { name: "Preview raw.bin" });
  rendered.rerender(
    view(
      "transport-1",
      vi.fn(),
      vi.fn(),
      "en",
      queue({ blocksFileOperations: true, outstanding: 1, items: [queuedItem] }),
    ),
  );
  expect(screen.getByRole("button", { name: "Preview raw.bin" }).hasAttribute("disabled")).toBe(true);
  expect(fileCommands.preview).not.toHaveBeenCalled();
  rendered.rerender(
    view("transport-1", vi.fn(), vi.fn(), "en", queue({ blocksFileOperations: false, outstanding: 16 })),
  );
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Preview raw.bin" }).hasAttribute("disabled")).toBe(false),
  );
  await userEvent.click(screen.getByRole("button", { name: "Preview raw.bin" }));
  expect(await screen.findByLabelText("Remote file text")).toBeTruthy();
});

it("adds native-selected uploads to the queue with the current raw directory", async () => {
  fileCommands.list.mockResolvedValueOnce({ status: "ok", data: { entries: [directory] } });
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "logs" }));
  await waitFor(() => expect(fileCommands.list).toHaveBeenCalledTimes(2));
  await userEvent.click(screen.getByRole("button", { name: "Upload file" }));
  expect(fileCommands.upload).toHaveBeenCalledExactlyOnceWith("session-1", "transport-1", directory.path, "en");
  expect(screen.queryByText("Saved")).toBeNull();
  expect(fileCommands.list).toHaveBeenCalledTimes(2);
});

it("passes the current Chinese language to native selection", async () => {
  render(view("transport-1", vi.fn(), vi.fn(), "zh-Hans"));
  await screen.findByText("此目录为空。");
  await userEvent.click(screen.getByRole("button", { name: "上传文件" }));
  expect(fileCommands.upload).toHaveBeenCalledExactlyOnceWith("session-1", "transport-1", [46], "zh-Hans");
});

it("keeps the listing available for enqueueing while transfers block browsing and mutations", async () => {
  fileCommands.list.mockResolvedValueOnce({ status: "ok", data: { entries: [directory, file] } });
  const rendered = render(view());
  await screen.findByRole("button", { name: "logs" });
  rendered.rerender(
    view(
      "transport-1",
      vi.fn(),
      vi.fn(),
      "en",
      queue({ outstanding: 1, blocksFileOperations: true, items: [queuedItem] }),
    ),
  );
  expect(screen.getByRole("button", { name: "logs" }).hasAttribute("disabled")).toBe(true);
  expect(screen.getByRole("button", { name: "Refresh files" }).hasAttribute("disabled")).toBe(true);
  expect(screen.getByRole("button", { name: "Delete raw.bin" }).hasAttribute("disabled")).toBe(true);
  await userEvent.click(screen.getByRole("button", { name: "Download raw.bin" }));
  expect(fileCommands.download).toHaveBeenCalledExactlyOnceWith("session-1", "transport-1", file.path, "en");
  expect(fileCommands.list).toHaveBeenCalledTimes(1);
});

it("does not cancel or replay an enqueue when Files closes", async () => {
  const pending = deferred<{ status: "ok"; data: { status: "cancelled" } }>();
  fileCommands.upload.mockReturnValueOnce(pending.promise);
  const rendered = render(view());
  await screen.findByText("This directory is empty.");
  await userEvent.click(screen.getByRole("button", { name: "Upload file" }));
  rendered.unmount();
  expect(fileCommands.cancel).not.toHaveBeenCalled();
  await act(async () => pending.resolve({ status: "ok", data: { status: "cancelled" } }));
  expect(fileCommands.upload).toHaveBeenCalledTimes(1);
});

it("keeps one native selection pending and renders fixed enqueue failures", async () => {
  const pending = deferred<{ status: "error"; error: "nativeDialogBusy" }>();
  fileCommands.upload.mockReturnValueOnce(pending.promise);
  render(view());
  await screen.findByText("This directory is empty.");
  const upload = screen.getByRole("button", { name: "Upload file" });
  await userEvent.dblClick(upload);
  expect(fileCommands.upload).toHaveBeenCalledTimes(1);
  expect(upload.hasAttribute("disabled")).toBe(true);
  await act(async () => pending.resolve({ status: "error", error: "nativeDialogBusy" }));
  expect(screen.getByRole("alert").textContent).toContain("Finish the current file selection");
});

it("does not expose or replay a rejected native enqueue", async () => {
  fileCommands.upload.mockRejectedValueOnce(new Error("synthetic private path"));
  render(view());
  await screen.findByText("This directory is empty.");
  await userEvent.click(screen.getByRole("button", { name: "Upload file" }));
  expect(screen.getByRole("alert").textContent).toContain("transfer or status request failed");
  expect(screen.queryByText(/synthetic private/)).toBeNull();
  expect(fileCommands.upload).toHaveBeenCalledTimes(1);
});

it("reserves full capacity for unknown results while allowing directory inspection", async () => {
  render(view("transport-1", vi.fn(), vi.fn(), "en", queue({ outstanding: 16 })));
  await screen.findByText("This directory is empty.");
  expect(screen.getByRole("button", { name: "Upload file" }).hasAttribute("disabled")).toBe(true);
  await userEvent.click(screen.getByRole("button", { name: "Refresh files" }));
  await waitFor(() => expect(fileCommands.list).toHaveBeenCalledTimes(2));
  expect(fileCommands.upload).not.toHaveBeenCalled();
});

it("shows retained transfer results without issuing file requests after disconnect", async () => {
  render(view(null, vi.fn(), vi.fn(), "en", queue({ recent: [{ ...queuedItem, state: "interrupted" }] })));
  expect(screen.getByText("Connection ended · Not retried")).toBeTruthy();
  expect(screen.getByRole("button", { name: "Upload file" }).hasAttribute("disabled")).toBe(true);
  await act(async () => {});
  expect(fileCommands.list).not.toHaveBeenCalled();
});

it("opens one directory request in StrictMode and reports an empty directory", async () => {
  render(<StrictMode>{view()}</StrictMode>);
  await waitFor(() => expect(screen.getByText("This directory is empty.")).toBeTruthy());
  expect(fileCommands.list).toHaveBeenCalledTimes(1);
  expect(fileCommands.list.mock.calls[0]).toMatchObject(["session-1", "transport-1", expect.any(String), [46]]);
});

it("navigates with raw path bytes and downloads only regular files", async () => {
  fileCommands.list
    .mockResolvedValueOnce({ status: "ok", data: { entries: [directory, file, other] } })
    .mockResolvedValueOnce({ status: "ok", data: { entries: [file] } })
    .mockResolvedValueOnce({ status: "ok", data: { entries: [directory, file, other] } });
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "logs" }));
  await waitFor(() => expect(fileCommands.list).toHaveBeenCalledTimes(2));
  expect(fileCommands.list.mock.calls[1]?.[3]).toEqual(directory.path);
  await userEvent.click(screen.getByRole("button", { name: "Home" }));
  await waitFor(() => expect(fileCommands.list).toHaveBeenCalledTimes(3));
  expect(screen.queryByRole("button", { name: "Download socket" })).toBeNull();
  await userEvent.click(await screen.findByRole("button", { name: "Download raw.bin" }));
  expect(fileCommands.download).toHaveBeenCalledWith("session-1", "transport-1", file.path, "en");
  expect(screen.queryByText("Saved")).toBeNull();
});

it("cancels the old transport and ignores its late directory response", async () => {
  const old = deferred<Listed>();
  fileCommands.list
    .mockReturnValueOnce(old.promise)
    .mockResolvedValueOnce({ status: "ok", data: { entries: [directory] } });
  const rendered = render(view("old-transport"));
  await waitFor(() => expect(fileCommands.list).toHaveBeenCalledTimes(1));
  const oldOperation = fileCommands.list.mock.calls[0]?.[2];
  rendered.rerender(view("new-transport"));
  await waitFor(() => expect(fileCommands.cancel).toHaveBeenCalledWith("session-1", "old-transport", oldOperation));
  await waitFor(() => expect(fileCommands.list).toHaveBeenCalledTimes(2));
  await act(async () => old.resolve({ status: "ok", data: { entries: [file] } }));
  expect(screen.getByRole("button", { name: "logs" })).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Download raw.bin" })).toBeNull();
});

it("keeps directory navigation available when Rust reports only paused downloads", async () => {
  const paused = { ...queuedItem, direction: "download" as const, state: "paused" as const, canResume: true };
  fileCommands.list
    .mockResolvedValueOnce({ status: "ok", data: { entries: [directory] } })
    .mockResolvedValueOnce({ status: "ok", data: { entries: [] } });
  render(
    view(
      "transport-1",
      vi.fn(),
      vi.fn(),
      "en",
      queue({
        items: [paused],
        outstanding: 1,
        blocksFileOperations: false,
      }),
    ),
  );
  await userEvent.click(await screen.findByRole("button", { name: "logs" }));
  await screen.findByText("This directory is empty.");
  expect(fileCommands.list).toHaveBeenLastCalledWith("session-1", "transport-1", expect.any(String), directory.path);
  expect(screen.getByText("Paused")).toBeTruthy();
  expect(screen.getByRole("button", { name: "New folder" }).hasAttribute("disabled")).toBe(false);
  expect(fileCommands.upload).not.toHaveBeenCalled();
  expect(fileCommands.download).not.toHaveBeenCalled();
});

it("creates one folder in the current opaque directory and refreshes after success", async () => {
  fileCommands.list
    .mockResolvedValueOnce({ status: "ok", data: { entries: [directory] } })
    .mockResolvedValueOnce({ status: "ok", data: { entries: [] } })
    .mockResolvedValueOnce({ status: "ok", data: { entries: [{ ...directory, name: "snapshots" }] } });
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "logs" }));
  await screen.findByText("This directory is empty.");
  await userEvent.click(screen.getByRole("button", { name: "New folder" }));
  const submit = screen.getByRole("button", { name: "Create folder" });
  expect(submit.hasAttribute("disabled")).toBe(true);
  await userEvent.type(screen.getByRole("textbox", { name: "Name" }), "snapshots");
  await userEvent.click(submit);
  expect(fileCommands.create).toHaveBeenCalledWith(
    "session-1",
    "transport-1",
    expect.any(String),
    directory.path,
    "snapshots",
    "en",
  );
  expect(await screen.findByText("Folder created in this directory.")).toBeTruthy();
  await waitFor(() => expect(fileCommands.list).toHaveBeenCalledTimes(3));
});

it("passes the Chinese locale to folder creation and keeps directory paths as bytes", async () => {
  render(view("transport-1", vi.fn(), vi.fn(), "zh-Hans"));
  await screen.findByText("此目录为空。");
  await userEvent.click(screen.getByRole("button", { name: "新建文件夹" }));
  await userEvent.type(screen.getByRole("textbox", { name: "名称" }), "归档");
  await userEvent.click(screen.getByRole("button", { name: "创建文件夹" }));
  expect(fileCommands.create).toHaveBeenCalledWith(
    "session-1",
    "transport-1",
    expect.any(String),
    [46],
    "归档",
    "zh-Hans",
  );
});

it.each([file, directory])("renames only listed regular items using their opaque source path", async (entry) => {
  fileCommands.list.mockResolvedValueOnce({ status: "ok", data: { entries: [entry, other] } });
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: `Rename ${entry.name}` }));
  expect(screen.getByText(/a simultaneous remote change may be replaced on some servers/i)).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Rename socket" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Delete socket" })).toBeNull();
  const field = screen.getByRole("textbox", { name: "Name" });
  expect((field as HTMLInputElement).value).toBe("");
  await userEvent.type(field, "new-name");
  await userEvent.click(screen.getByRole("button", { name: "Rename" }));
  expect(fileCommands.rename).toHaveBeenCalledWith(
    "session-1",
    "transport-1",
    expect.any(String),
    [46],
    entry.path,
    "new-name",
    "en",
  );
  expect(await screen.findByText("Remote item renamed.")).toBeTruthy();
  await waitFor(() => expect(fileCommands.list).toHaveBeenCalledTimes(2));
});

it("sends deletion directly to Rust for native confirmation and keeps a cancelled listing", async () => {
  fileCommands.list.mockResolvedValueOnce({ status: "ok", data: { entries: [file, directory] } });
  fileCommands.delete.mockResolvedValueOnce({ status: "ok", data: { status: "cancelled", message: null } });
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Delete raw.bin" }));
  expect(fileCommands.delete).toHaveBeenCalledWith(
    "session-1",
    "transport-1",
    expect.any(String),
    [46],
    file.path,
    "en",
  );
  expect(await screen.findByText("Remote operation cancelled.")).toBeTruthy();
  expect(fileCommands.list).toHaveBeenCalledTimes(1);
  await userEvent.click(screen.getByRole("button", { name: "Delete logs" }));
  expect(fileCommands.delete).toHaveBeenCalledWith(
    "session-1",
    "transport-1",
    expect.any(String),
    [46],
    directory.path,
    "en",
  );
  expect(fileCommands.delete).toHaveBeenCalledTimes(2);
});

it("deletes a nested file with the current directory and entry paths kept separate", async () => {
  const nested = { ...file, path: [...directory.path, 47, 255, 46, 98, 105, 110] };
  fileCommands.list
    .mockResolvedValueOnce({ status: "ok", data: { entries: [directory] } })
    .mockResolvedValueOnce({ status: "ok", data: { entries: [nested] } });
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "logs" }));
  await userEvent.click(await screen.findByRole("button", { name: "Delete raw.bin" }));
  expect(fileCommands.delete).toHaveBeenCalledWith(
    "session-1",
    "transport-1",
    expect.any(String),
    directory.path,
    nested.path,
    "en",
  );
});

it("keeps a mutation inside the single-operation fence until Rust returns", async () => {
  const pending = deferred<{ status: "ok"; data: { status: "cancelled"; message: null } }>();
  fileCommands.list.mockResolvedValueOnce({ status: "ok", data: { entries: [file] } });
  fileCommands.delete.mockReturnValueOnce(pending.promise);
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Delete raw.bin" }));
  expect(screen.getByRole("button", { name: "Upload file" }).hasAttribute("disabled")).toBe(true);
  expect(screen.getByRole("button", { name: "New folder" }).hasAttribute("disabled")).toBe(true);
  expect(screen.getByRole("button", { name: "Rename raw.bin" }).hasAttribute("disabled")).toBe(true);
  const operationId = fileCommands.delete.mock.calls[0]?.[2];
  await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(fileCommands.cancel).toHaveBeenCalledWith("session-1", "transport-1", operationId);
  await act(async () => pending.resolve({ status: "ok", data: { status: "cancelled", message: null } }));
  expect(await screen.findByText("Remote operation cancelled.")).toBeTruthy();
  expect(fileCommands.delete).toHaveBeenCalledTimes(1);
});

it.each([
  ["conflict", "The remote item changed or the target name already exists. Refresh the directory before trying again."],
  ["unsupported", "This type of remote directory or item cannot be changed here. Refresh to check it."],
  ["failed", "Could not complete the remote operation. Refresh the directory and check before trying again."],
])("shows a %s mutation without refreshing or retrying", async (status, copy) => {
  fileCommands.list.mockResolvedValueOnce({ status: "ok", data: { entries: [file] } });
  fileCommands.delete.mockResolvedValueOnce({ status: "ok", data: { status, message: "untrusted detail" } });
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Delete raw.bin" }));
  expect(await screen.findByText(copy)).toBeTruthy();
  expect(screen.queryByText("untrusted detail")).toBeNull();
  expect(fileCommands.list).toHaveBeenCalledTimes(1);
  expect(fileCommands.delete).toHaveBeenCalledTimes(1);
});

it("keeps an uncertain old-transport mutation in the session outcome channel", async () => {
  const pending = deferred<{ status: "ok"; data: { status: "unknown"; message: null } }>();
  fileCommands.rename.mockReturnValueOnce(pending.promise);
  fileCommands.list
    .mockResolvedValueOnce({ status: "ok", data: { entries: [file] } })
    .mockResolvedValueOnce({ status: "ok", data: { entries: [directory] } });
  const onFileOutcome = vi.fn();
  const rendered = render(view("old-transport", vi.fn(), onFileOutcome));
  await userEvent.click(await screen.findByRole("button", { name: "Rename raw.bin" }));
  await userEvent.type(screen.getByRole("textbox", { name: "Name" }), "new.bin");
  await userEvent.click(screen.getByRole("button", { name: "Rename" }));
  const oldOperation = fileCommands.rename.mock.calls[0]?.[2];
  rendered.rerender(view("new-transport", vi.fn(), onFileOutcome));
  await waitFor(() => expect(fileCommands.cancel).toHaveBeenCalledWith("session-1", "old-transport", oldOperation));
  await screen.findByRole("button", { name: "logs" });
  await act(async () => pending.resolve({ status: "ok", data: { status: "unknown", message: null } }));
  expect(onFileOutcome).toHaveBeenCalledWith({
    transportId: "old-transport",
    operationId: oldOperation,
    status: "unknown",
    stagingMayRemain: false,
  });
  expect(fileCommands.rename).toHaveBeenCalledTimes(1);
  expect(fileCommands.list).toHaveBeenCalledTimes(2);
  expect(screen.getByRole("button", { name: "logs" })).toBeTruthy();
});

it("treats a rejected mutation IPC promise as unknown without an automatic retry", async () => {
  fileCommands.list.mockResolvedValueOnce({ status: "ok", data: { entries: [file] } });
  fileCommands.delete.mockRejectedValueOnce(new Error("untrusted bridge detail"));
  const onFileOutcome = vi.fn();
  render(view("transport-1", vi.fn(), onFileOutcome));
  await userEvent.click(await screen.findByRole("button", { name: "Delete raw.bin" }));
  await waitFor(() => expect(onFileOutcome).toHaveBeenCalledTimes(1));
  expect(onFileOutcome.mock.calls[0]?.[0]).toMatchObject({ status: "unknown", stagingMayRemain: false });
  expect(screen.queryByText("untrusted bridge detail")).toBeNull();
  expect(fileCommands.list).toHaveBeenCalledTimes(1);
  expect(fileCommands.delete).toHaveBeenCalledTimes(1);
});
