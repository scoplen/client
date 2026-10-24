// SPDX-License-Identifier: Apache-2.0
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Channel } from "@tauri-apps/api/core";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { StrictMode } from "react";
import { I18nProvider } from "../src/i18n";
import type { SessionFileTransferProgress } from "../src/ipc/bindings";
import { SessionFiles } from "../src/session-files";

const fileCommands = vi.hoisted(() => ({
  list: vi.fn(),
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
    sessionDownloadFile: fileCommands.download,
    sessionUploadFile: fileCommands.upload,
    sessionCreateRemoteDirectory: fileCommands.create,
    sessionRenameRemoteEntry: fileCommands.rename,
    sessionDeleteRemoteEntry: fileCommands.delete,
    sessionCancelFileOperation: fileCommands.cancel,
  },
}));

type Entry = { name: string; path: number[]; kind: "file" | "directory" | "other"; sizeBytes: string | null };
type Listed = { status: "ok"; data: { entries: Entry[] } } | { status: "error"; error: string };
type Downloaded =
  | { status: "ok"; data: { status: "saved" | "cancelled" | "unknown" | "failed"; message: string | null } }
  | { status: "error"; error: string };
function progressEvent(
  operationId: string,
  changes: Partial<SessionFileTransferProgress> = {},
): SessionFileTransferProgress {
  return {
    sessionId: "session-1",
    transportId: "transport-1",
    operationId,
    transferredBytes: "1024",
    totalBytes: "4096",
    phase: "transferring",
    ...changes,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}

function view(
  transportId = "transport-1",
  onClose = vi.fn(),
  onUploadOutcome = vi.fn(),
  locale: "en" | "zh-Hans" = "en",
) {
  return (
    <I18nProvider locale={locale}>
      <SessionFiles sessionId="session-1" transportId={transportId} onClose={onClose} onFileOutcome={onUploadOutcome} />
    </I18nProvider>
  );
}

const directory: Entry = { name: "logs", path: [46, 47, 108, 111, 103, 115], kind: "directory", sizeBytes: null };
const file: Entry = { name: "raw.bin", path: [46, 47, 255, 46, 98, 105, 110], kind: "file", sizeBytes: "4" };
const other: Entry = { name: "socket", path: [46, 47, 115, 111, 99, 107, 101, 116], kind: "other", sizeBytes: null };

beforeEach(() => {
  mockIPC(() => undefined);
  fileCommands.list.mockReset().mockResolvedValue({ status: "ok", data: { entries: [] } });
  fileCommands.download.mockReset().mockResolvedValue({ status: "ok", data: { status: "saved", message: null } });
  fileCommands.upload.mockReset().mockResolvedValue({
    status: "ok",
    data: { status: "saved", message: null, stagingMayRemain: false },
  });
  fileCommands.create.mockReset().mockResolvedValue({ status: "ok", data: { status: "saved", message: null } });
  fileCommands.rename.mockReset().mockResolvedValue({ status: "ok", data: { status: "saved", message: null } });
  fileCommands.delete.mockReset().mockResolvedValue({ status: "ok", data: { status: "saved", message: null } });
  fileCommands.cancel.mockReset().mockResolvedValue({ status: "ok", data: null });
});

afterEach(() => clearMocks());

it("uploads one native-selected file into the current raw directory and refreshes after success", async () => {
  fileCommands.list
    .mockResolvedValueOnce({ status: "ok", data: { entries: [directory] } })
    .mockResolvedValueOnce({ status: "ok", data: { entries: [] } })
    .mockResolvedValueOnce({ status: "ok", data: { entries: [file] } });
  const onUploadOutcome = vi.fn();
  render(view("transport-1", vi.fn(), onUploadOutcome));
  await userEvent.click(await screen.findByRole("button", { name: "logs" }));
  await waitFor(() => expect(fileCommands.list).toHaveBeenCalledTimes(2));
  await userEvent.click(screen.getByRole("button", { name: "Upload file" }));
  expect(fileCommands.upload).toHaveBeenCalledWith(
    "session-1",
    "transport-1",
    expect.any(String),
    directory.path,
    "en",
    expect.any(Channel),
  );
  expect(await screen.findByText("File uploaded to this directory.")).toBeTruthy();
  await waitFor(() => expect(fileCommands.list).toHaveBeenCalledTimes(3));
  expect(screen.getByRole("button", { name: "Download raw.bin" })).toBeTruthy();
  expect(onUploadOutcome).not.toHaveBeenCalled();
});

it("passes the current Chinese interface language to the native upload command", async () => {
  render(view("transport-1", vi.fn(), vi.fn(), "zh-Hans"));
  await screen.findByText("此目录为空。");
  await userEvent.click(screen.getByRole("button", { name: "上传文件" }));
  expect(fileCommands.upload).toHaveBeenCalledWith(
    "session-1",
    "transport-1",
    expect.any(String),
    [46],
    "zh-Hans",
    expect.any(Channel),
  );
});

it("shows an upload with unknown total in Chinese and clears progress for an unknown result", async () => {
  const pending = deferred<{ status: "ok"; data: { status: "unknown"; message: null; stagingMayRemain: true } }>();
  fileCommands.upload.mockReturnValueOnce(pending.promise);
  const onFileOutcome = vi.fn();
  render(view("transport-1", vi.fn(), onFileOutcome, "zh-Hans"));
  await screen.findByText("此目录为空。");
  await userEvent.click(screen.getByRole("button", { name: "上传文件" }));
  const operationId = fileCommands.upload.mock.calls[0]?.[2] as string;
  const channel = fileCommands.upload.mock.calls[0]?.[5] as Channel<SessionFileTransferProgress>;
  await act(() =>
    channel.onmessage(progressEvent(operationId, { transferredBytes: "18446744073709551615", totalBytes: null })),
  );
  expect(screen.getByText("已传输 18,446,744,073,709,551,615 字节")).toBeTruthy();
  expect(screen.getByRole("progressbar", { name: "文件传输进度" }).getAttribute("value")).toBeNull();
  expect(screen.queryByText("文件已上传到此目录。")).toBeNull();
  await act(async () =>
    pending.resolve({ status: "ok", data: { status: "unknown", message: null, stagingMayRemain: true } }),
  );
  expect(screen.queryByRole("progressbar")).toBeNull();
  expect(onFileOutcome).toHaveBeenCalledWith({
    transportId: "transport-1",
    operationId,
    status: "unknown",
    stagingMayRemain: true,
  });
});

it.each([
  ["cancelled", "No file was uploaded."],
  ["unsupported", "This server cannot safely publish the upload here. The remote destination was left unchanged."],
  ["conflict", "The remote destination changed. It was not replaced. Refresh the directory before trying again."],
  ["failed", "Upload failed before completion. Check the connection before trying again."],
])("shows the %s upload result without an automatic retry", async (status, text) => {
  fileCommands.upload.mockResolvedValueOnce({ status: "ok", data: { status, message: null, stagingMayRemain: true } });
  render(view());
  await screen.findByText("This directory is empty.");
  await userEvent.click(screen.getByRole("button", { name: "Upload file" }));
  expect(await screen.findByText(text)).toBeTruthy();
  expect(screen.getByText("A temporary .scoplen-upload-*.part file may remain in the remote directory.")).toBeTruthy();
  expect(fileCommands.upload).toHaveBeenCalledTimes(1);
  expect(fileCommands.list).toHaveBeenCalledTimes(1);
});

it("keeps a rejected cancellation pending and reports an uncertain upload before stale guards", async () => {
  const pending = deferred<{ status: "ok"; data: { status: "unknown"; message: null; stagingMayRemain: true } }>();
  fileCommands.upload.mockReturnValueOnce(pending.promise);
  fileCommands.cancel.mockResolvedValueOnce({ status: "error", error: "publication started" });
  const onUploadOutcome = vi.fn();
  render(view("transport-1", vi.fn(), onUploadOutcome));
  await screen.findByText("This directory is empty.");
  await userEvent.click(screen.getByRole("button", { name: "Upload file" }));
  const operationId = fileCommands.upload.mock.calls[0]?.[2];
  await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(fileCommands.cancel).toHaveBeenCalledWith("session-1", "transport-1", operationId);
  expect(await screen.findByText("Waiting for the file operation result…")).toBeTruthy();
  await act(async () =>
    pending.resolve({ status: "ok", data: { status: "unknown", message: null, stagingMayRemain: true } }),
  );
  expect(onUploadOutcome).toHaveBeenCalledWith({
    transportId: "transport-1",
    operationId,
    status: "unknown",
    stagingMayRemain: true,
  });
  expect(screen.queryByText("File operation cancelled.")).toBeNull();
  expect(fileCommands.upload).toHaveBeenCalledTimes(1);
  expect(fileCommands.list).toHaveBeenCalledTimes(1);
});

it("ignores late transfer progress after cancellation is requested while awaiting an unknown upload", async () => {
  const pending = deferred<{ status: "ok"; data: { status: "unknown"; message: null; stagingMayRemain: true } }>();
  fileCommands.upload.mockReturnValueOnce(pending.promise);
  fileCommands.cancel.mockResolvedValueOnce({ status: "error", error: "publication started" });
  const onFileOutcome = vi.fn();
  render(view("transport-1", vi.fn(), onFileOutcome));
  await screen.findByText("This directory is empty.");
  await userEvent.click(screen.getByRole("button", { name: "Upload file" }));
  const operationId = fileCommands.upload.mock.calls[0]?.[2] as string;
  const channel = fileCommands.upload.mock.calls[0]?.[5] as Channel<SessionFileTransferProgress>;
  await act(() => channel.onmessage(progressEvent(operationId)));
  expect(screen.getByText("1,024 / 4,096 bytes · 25%")).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(screen.queryByRole("progressbar")).toBeNull();
  expect(await screen.findByText("Waiting for the file operation result…")).toBeTruthy();
  await act(() => channel.onmessage(progressEvent(operationId, { transferredBytes: "4096", phase: "finalizing" })));
  expect(screen.queryByRole("progressbar")).toBeNull();
  expect(screen.queryByText("Transfer complete. Waiting for save confirmation.")).toBeNull();
  await act(async () =>
    pending.resolve({ status: "ok", data: { status: "unknown", message: null, stagingMayRemain: true } }),
  );
  expect(onFileOutcome).toHaveBeenCalledWith({
    transportId: "transport-1",
    operationId,
    status: "unknown",
    stagingMayRemain: true,
  });
  expect(fileCommands.upload).toHaveBeenCalledTimes(1);
});

it("reports an old transport's uncertain result without changing the new directory", async () => {
  const old = deferred<{ status: "ok"; data: { status: "unknown"; message: null; stagingMayRemain: false } }>();
  fileCommands.upload.mockReturnValueOnce(old.promise);
  fileCommands.list
    .mockResolvedValueOnce({ status: "ok", data: { entries: [] } })
    .mockResolvedValueOnce({ status: "ok", data: { entries: [directory] } });
  const onUploadOutcome = vi.fn();
  const rendered = render(view("old-transport", vi.fn(), onUploadOutcome));
  await screen.findByText("This directory is empty.");
  await userEvent.click(screen.getByRole("button", { name: "Upload file" }));
  const oldOperation = fileCommands.upload.mock.calls[0]?.[2];
  rendered.rerender(view("new-transport", vi.fn(), onUploadOutcome));
  await waitFor(() => expect(fileCommands.cancel).toHaveBeenCalledWith("session-1", "old-transport", oldOperation));
  await screen.findByRole("button", { name: "logs" });
  await act(async () =>
    old.resolve({ status: "ok", data: { status: "unknown", message: null, stagingMayRemain: false } }),
  );
  expect(onUploadOutcome).toHaveBeenCalledWith({
    transportId: "old-transport",
    operationId: oldOperation,
    status: "unknown",
    stagingMayRemain: false,
  });
  expect(screen.getByRole("button", { name: "logs" })).toBeTruthy();
  expect(fileCommands.upload).toHaveBeenCalledTimes(1);
});

it("refreshes the directory after an unknown result without retrying the upload", async () => {
  fileCommands.upload.mockResolvedValueOnce({
    status: "ok",
    data: { status: "unknown", message: "untrusted server detail", stagingMayRemain: false },
  });
  const onUploadOutcome = vi.fn();
  render(view("transport-1", vi.fn(), onUploadOutcome));
  await screen.findByText("This directory is empty.");
  await userEvent.click(screen.getByRole("button", { name: "Upload file" }));
  await waitFor(() => expect(onUploadOutcome).toHaveBeenCalledTimes(1));
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Refresh files" }).hasAttribute("disabled")).toBe(false),
  );
  await userEvent.click(screen.getByRole("button", { name: "Refresh files" }));
  await waitFor(() => expect(fileCommands.list).toHaveBeenCalledTimes(2));
  expect(fileCommands.upload).toHaveBeenCalledTimes(1);
  expect(screen.queryByText("untrusted server detail")).toBeNull();
});

it("shows a preflight IPC error as failed without a residual-file warning", async () => {
  fileCommands.upload.mockResolvedValueOnce({ status: "error", error: "untrusted preflight detail" });
  const onUploadOutcome = vi.fn();
  render(view("transport-1", vi.fn(), onUploadOutcome));
  await screen.findByText("This directory is empty.");
  await userEvent.click(screen.getByRole("button", { name: "Upload file" }));
  expect(
    await screen.findByText("Upload failed before completion. Check the connection before trying again."),
  ).toBeTruthy();
  expect(screen.queryByText("untrusted preflight detail")).toBeNull();
  expect(screen.queryByText("A temporary .scoplen-upload-*.part file may remain in the remote directory.")).toBeNull();
  expect(onUploadOutcome).not.toHaveBeenCalled();
});

it("treats a rejected IPC promise as an unknown upload outcome", async () => {
  fileCommands.upload.mockRejectedValueOnce(new Error("untrusted bridge detail"));
  const onUploadOutcome = vi.fn();
  render(view("transport-1", vi.fn(), onUploadOutcome));
  await screen.findByText("This directory is empty.");
  await userEvent.click(screen.getByRole("button", { name: "Upload file" }));
  await waitFor(() => expect(onUploadOutcome).toHaveBeenCalledTimes(1));
  expect(onUploadOutcome.mock.calls[0]?.[0]).toMatchObject({
    status: "unknown",
    stagingMayRemain: true,
  });
  expect(screen.queryByText("untrusted bridge detail")).toBeNull();
});

it("reports a possible staging file after the Files view closes", async () => {
  const pending = deferred<{ status: "ok"; data: { status: "failed"; message: string; stagingMayRemain: true } }>();
  fileCommands.upload.mockReturnValueOnce(pending.promise);
  const onUploadOutcome = vi.fn();
  const rendered = render(view("old-transport", vi.fn(), onUploadOutcome));
  await screen.findByText("This directory is empty.");
  await userEvent.click(screen.getByRole("button", { name: "Upload file" }));
  const operationId = fileCommands.upload.mock.calls[0]?.[2];
  rendered.unmount();
  await act(async () =>
    pending.resolve({
      status: "ok",
      data: { status: "failed", message: "untrusted server detail", stagingMayRemain: true },
    }),
  );
  expect(onUploadOutcome).toHaveBeenCalledWith({
    transportId: "old-transport",
    operationId,
    status: "failed",
    stagingMayRemain: true,
  });
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
  expect(fileCommands.download).toHaveBeenCalledWith(
    "session-1",
    "transport-1",
    expect.any(String),
    file.path,
    expect.any(Channel),
  );
  expect(await screen.findByText("Download saved to the selected location.")).toBeTruthy();
});

it("shows download bytes and finalizing while native save is still pending", async () => {
  fileCommands.list.mockResolvedValueOnce({ status: "ok", data: { entries: [file] } });
  const pending = deferred<Downloaded>();
  fileCommands.download.mockReturnValueOnce(pending.promise);
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Download raw.bin" }));
  const operationId = fileCommands.download.mock.calls[0]?.[2] as string;
  const channel = fileCommands.download.mock.calls[0]?.[4] as Channel<SessionFileTransferProgress>;
  await act(() => channel.onmessage(progressEvent(operationId)));
  expect(screen.getByText("1,024 / 4,096 bytes · 25%")).toBeTruthy();
  expect(screen.getByRole("progressbar", { name: "File transfer progress" }).getAttribute("value")).toBe("25");
  await act(() => channel.onmessage(progressEvent(operationId, { transferredBytes: "4096", phase: "finalizing" })));
  expect(screen.getByText("4,096 / 4,096 bytes · 100%")).toBeTruthy();
  expect(screen.getByText("Transfer complete. Waiting for save confirmation.")).toBeTruthy();
  expect(screen.queryByText("Download saved to the selected location.")).toBeNull();
  await act(async () => pending.resolve({ status: "ok", data: { status: "saved", message: null } }));
  expect(screen.queryByRole("progressbar")).toBeNull();
  expect(screen.getByText("Download saved to the selected location.")).toBeTruthy();
  await act(() => channel.onmessage(progressEvent(operationId, { transferredBytes: "4096", phase: "finalizing" })));
  expect(screen.queryByRole("progressbar")).toBeNull();
});

it("ignores progress for another operation and invalid byte counts", async () => {
  fileCommands.list.mockResolvedValueOnce({ status: "ok", data: { entries: [file] } });
  const pending = deferred<Downloaded>();
  fileCommands.download.mockReturnValueOnce(pending.promise);
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Download raw.bin" }));
  const operationId = fileCommands.download.mock.calls[0]?.[2] as string;
  const channel = fileCommands.download.mock.calls[0]?.[4] as Channel<SessionFileTransferProgress>;
  await act(() => {
    channel.onmessage(progressEvent(operationId, { sessionId: "other-session" }));
    channel.onmessage(progressEvent(operationId, { transportId: "other-transport" }));
    channel.onmessage(progressEvent(operationId, { operationId: "other-operation" }));
    channel.onmessage(progressEvent(operationId, { transferredBytes: "4097" }));
    channel.onmessage(progressEvent(operationId, { transferredBytes: "18446744073709551616", totalBytes: null }));
  });
  expect(screen.queryByRole("progressbar")).toBeNull();
  await act(() => channel.onmessage(progressEvent(operationId)));
  expect(screen.getByText("1,024 / 4,096 bytes · 25%")).toBeTruthy();
  await act(() => channel.onmessage(progressEvent(operationId, { transferredBytes: "512" })));
  expect(screen.getByText("1,024 / 4,096 bytes · 25%")).toBeTruthy();
  await act(async () => pending.resolve({ status: "error", error: "Remote file changed" }));
  expect(screen.queryByRole("progressbar")).toBeNull();
  expect((screen.getByRole("alert") as HTMLElement).textContent).toContain("Remote file changed");
});

it("retries a listing error and keeps download errors alongside the file", async () => {
  fileCommands.list
    .mockResolvedValueOnce({ status: "error", error: "SFTP unavailable" })
    .mockResolvedValueOnce({ status: "ok", data: { entries: [file] } });
  fileCommands.download
    .mockResolvedValueOnce({ status: "ok", data: { status: "failed", message: "Remote file changed" } })
    .mockResolvedValueOnce({ status: "ok", data: { status: "cancelled", message: null } });
  render(view());
  expect((await screen.findByRole("alert")).textContent).toContain("SFTP unavailable");
  expect(screen.queryByText("This directory is empty.")).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Try again" }));
  await userEvent.click(await screen.findByRole("button", { name: "Download raw.bin" }));
  expect((await screen.findByRole("alert")).textContent).toContain("Remote file changed");
  expect(screen.queryByRole("button", { name: "Try again" })).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Download raw.bin" }));
  expect(await screen.findByText("No file was saved.")).toBeTruthy();
  expect(fileCommands.list).toHaveBeenCalledTimes(2);
});

it("cancels a pending download without disabling the terminal's file panel", async () => {
  fileCommands.list.mockResolvedValueOnce({ status: "ok", data: { entries: [file] } });
  const pending = deferred<Downloaded>();
  fileCommands.download.mockReturnValueOnce(pending.promise);
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Download raw.bin" }));
  const operationId = fileCommands.download.mock.calls[0]?.[2];
  const channel = fileCommands.download.mock.calls[0]?.[4] as Channel<SessionFileTransferProgress>;
  await act(() => channel.onmessage(progressEvent(operationId)));
  await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(fileCommands.cancel).toHaveBeenCalledWith("session-1", "transport-1", operationId);
  await act(async () => pending.resolve({ status: "ok", data: { status: "cancelled", message: null } }));
  expect(await screen.findByText("No file was saved.")).toBeTruthy();
  expect(screen.queryByRole("progressbar")).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Download raw.bin" }));
  expect(fileCommands.download).toHaveBeenCalledTimes(2);
  expect(fileCommands.download.mock.calls[1]?.[2]).not.toBe(operationId);
});

it("uses the confirmed saved result after a late cancellation is refused", async () => {
  fileCommands.list.mockResolvedValueOnce({ status: "ok", data: { entries: [file] } });
  const pending = deferred<Downloaded>();
  fileCommands.download.mockReturnValueOnce(pending.promise);
  fileCommands.cancel.mockResolvedValueOnce({ status: "error", error: "the final save has started" });
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Download raw.bin" }));
  await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(screen.getByText("Waiting for the file operation result…")).toBeTruthy();
  await act(async () => pending.resolve({ status: "ok", data: { status: "saved", message: null } }));
  expect(screen.getByText("Download saved to the selected location.")).toBeTruthy();
  expect(screen.queryByText("No file was saved.")).toBeNull();
});

it("keeps an unknown local result visible after Files closes", async () => {
  fileCommands.list.mockResolvedValueOnce({ status: "ok", data: { entries: [file] } });
  const pending = deferred<Downloaded>();
  fileCommands.download.mockReturnValueOnce(pending.promise);
  const onFileOutcome = vi.fn();
  const rendered = render(view("transport-1", vi.fn(), onFileOutcome));
  await userEvent.click(await screen.findByRole("button", { name: "Download raw.bin" }));
  const operationId = fileCommands.download.mock.calls[0]?.[2];
  rendered.unmount();
  await act(async () => pending.resolve({ status: "ok", data: { status: "unknown", message: null } }));
  expect(onFileOutcome).toHaveBeenCalledWith({
    kind: "download",
    transportId: "transport-1",
    operationId,
    status: "unknown",
  });
  expect(fileCommands.download).toHaveBeenCalledTimes(1);
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

it("ignores a late download result after the transport changes", async () => {
  fileCommands.list
    .mockResolvedValueOnce({ status: "ok", data: { entries: [file] } })
    .mockResolvedValueOnce({ status: "ok", data: { entries: [directory] } });
  const old = deferred<Downloaded>();
  fileCommands.download.mockReturnValueOnce(old.promise);
  const rendered = render(view("old-transport"));
  await userEvent.click(await screen.findByRole("button", { name: "Download raw.bin" }));
  const oldOperation = fileCommands.download.mock.calls[0]?.[2];
  const oldChannel = fileCommands.download.mock.calls[0]?.[4] as Channel<SessionFileTransferProgress>;
  await act(() => oldChannel.onmessage(progressEvent(oldOperation, { transportId: "old-transport" })));
  expect(screen.getByRole("progressbar", { name: "File transfer progress" })).toBeTruthy();
  rendered.rerender(view("new-transport"));
  await waitFor(() => expect(fileCommands.cancel).toHaveBeenCalledWith("session-1", "old-transport", oldOperation));
  await waitFor(() => expect(fileCommands.list).toHaveBeenCalledTimes(2));
  expect(screen.queryByRole("progressbar")).toBeNull();
  await act(() =>
    oldChannel.onmessage(progressEvent(oldOperation, { transportId: "old-transport", transferredBytes: "2048" })),
  );
  expect(screen.queryByRole("progressbar")).toBeNull();
  await act(async () => old.resolve({ status: "ok", data: { status: "saved", message: null } }));
  expect(screen.getByRole("button", { name: "logs" })).toBeTruthy();
  expect(screen.queryByText("Download saved to the selected location.")).toBeNull();
});

it("cancels a pending picker when the panel closes and does not restore late results", async () => {
  fileCommands.list.mockResolvedValueOnce({ status: "ok", data: { entries: [file] } });
  const pending = deferred<Downloaded>();
  fileCommands.download.mockReturnValueOnce(pending.promise);
  const onClose = vi.fn();
  const rendered = render(view("transport-1", onClose));
  await userEvent.click(await screen.findByRole("button", { name: "Download raw.bin" }));
  const operationId = fileCommands.download.mock.calls[0]?.[2];
  await userEvent.click(screen.getByRole("button", { name: "Close files" }));
  expect(onClose).toHaveBeenCalledOnce();
  rendered.unmount();
  expect(fileCommands.cancel).toHaveBeenCalledWith("session-1", "transport-1", operationId);
  await act(async () => pending.resolve({ status: "ok", data: { status: "saved", message: null } }));
  expect(screen.queryByText("Download saved to the selected location.")).toBeNull();
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
