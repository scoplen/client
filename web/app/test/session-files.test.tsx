// SPDX-License-Identifier: Apache-2.0
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { StrictMode } from "react";
import { I18nProvider } from "../src/i18n";
import { SessionFiles } from "../src/session-files";

const fileCommands = vi.hoisted(() => ({
  list: vi.fn(),
  download: vi.fn(),
  cancel: vi.fn(),
}));

vi.mock("../src/ipc/bindings", () => ({
  commands: {
    sessionListFiles: fileCommands.list,
    sessionDownloadFile: fileCommands.download,
    sessionCancelFileOperation: fileCommands.cancel,
  },
}));

type Entry = { name: string; path: number[]; kind: "file" | "directory" | "other"; sizeBytes: string | null };
type Listed = { status: "ok"; data: { entries: Entry[] } } | { status: "error"; error: string };
type Downloaded = { status: "ok"; data: boolean } | { status: "error"; error: string };

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}

function view(transportId = "transport-1", onClose = vi.fn()) {
  return (
    <I18nProvider locale="en">
      <SessionFiles sessionId="session-1" transportId={transportId} onClose={onClose} />
    </I18nProvider>
  );
}

const directory: Entry = { name: "logs", path: [46, 47, 108, 111, 103, 115], kind: "directory", sizeBytes: null };
const file: Entry = { name: "raw.bin", path: [46, 47, 255, 46, 98, 105, 110], kind: "file", sizeBytes: "4" };
const other: Entry = { name: "socket", path: [46, 47, 115, 111, 99, 107, 101, 116], kind: "other", sizeBytes: null };

beforeEach(() => {
  fileCommands.list.mockReset().mockResolvedValue({ status: "ok", data: { entries: [] } });
  fileCommands.download.mockReset().mockResolvedValue({ status: "ok", data: true });
  fileCommands.cancel.mockReset().mockResolvedValue({ status: "ok", data: null });
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
  expect(fileCommands.download).toHaveBeenCalledWith("session-1", "transport-1", expect.any(String), file.path);
  expect(await screen.findByText("Download saved to the selected location.")).toBeTruthy();
});

it("retries a listing error and keeps download errors alongside the file", async () => {
  fileCommands.list
    .mockResolvedValueOnce({ status: "error", error: "SFTP unavailable" })
    .mockResolvedValueOnce({ status: "ok", data: { entries: [file] } });
  fileCommands.download
    .mockResolvedValueOnce({ status: "error", error: "Remote file changed" })
    .mockResolvedValueOnce({ status: "ok", data: false });
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
  await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(fileCommands.cancel).toHaveBeenCalledWith("session-1", "transport-1", operationId);
  await act(async () => pending.resolve({ status: "error", error: "file operation was cancelled" }));
  expect(await screen.findByText("File operation cancelled.")).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: "Download raw.bin" }));
  expect(fileCommands.download).toHaveBeenCalledTimes(2);
  expect(fileCommands.download.mock.calls[1]?.[2]).not.toBe(operationId);
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
  rendered.rerender(view("new-transport"));
  await waitFor(() => expect(fileCommands.cancel).toHaveBeenCalledWith("session-1", "old-transport", oldOperation));
  await waitFor(() => expect(fileCommands.list).toHaveBeenCalledTimes(2));
  await act(async () => old.resolve({ status: "ok", data: true }));
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
  await act(async () => pending.resolve({ status: "ok", data: true }));
  expect(screen.queryByText("Download saved to the selected location.")).toBeNull();
});
