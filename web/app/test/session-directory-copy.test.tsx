// SPDX-License-Identifier: Apache-2.0
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { StrictMode } from "react";
import { violations } from "../../ui/test/axe";
import { I18nProvider } from "../src/i18n";
import type { SessionDirectoryCopySelection, SessionTransferQueueSnapshot } from "../src/ipc/bindings";
import { SessionFiles } from "../src/session-files";

const api = vi.hoisted(() => {
  const commands = {
    sessionListFiles: vi.fn(),
    sessionEditorSnapshot: vi.fn(),
    sessionPrepareDirectoryCopy: vi.fn(),
    sessionEnqueueDirectoryCopy: vi.fn(),
    sessionDiscardDirectoryCopy: vi.fn(),
    sessionCancelFileOperation: vi.fn(),
  };
  return { commands, owner: commands };
});
vi.mock("../src/account-profiles", () => ({ useProfileCommands: () => api.owner }));

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
function selection(changes: Partial<SessionDirectoryCopySelection> = {}): SessionDirectoryCopySelection {
  return {
    selectionId: "selection-1",
    sessionId: "session-1",
    transportId: "transport-1",
    direction: "upload",
    sourceName: "config",
    destinationParentName: "remote-home",
    defaultRootName: "config",
    ...changes,
  };
}
function view({
  transportId = "transport-1",
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
  api.owner = api.commands;
  api.commands.sessionListFiles.mockReset().mockResolvedValue({
    status: "ok",
    data: {
      entries: [
        { name: "logs", path: [46, 47, 108, 111, 103, 115], kind: "directory", sizeBytes: null },
        { name: "link", path: [46, 47, 108], kind: "other", sizeBytes: null },
      ],
    },
  });
  api.commands.sessionEditorSnapshot.mockReset().mockResolvedValue({ status: "ok", data: null });
  api.commands.sessionPrepareDirectoryCopy.mockReset().mockImplementation(async (...args: unknown[]) => ({
    status: "ok",
    data: { kind: "prepared", selection: selection({ direction: args[3] as "upload" | "download" }) },
  }));
  api.commands.sessionEnqueueDirectoryCopy.mockReset().mockResolvedValue({
    status: "ok",
    data: { status: "queued", queueId: "queue-1", itemId: "item-1", executionId: "execution-1" },
  });
  api.commands.sessionDiscardDirectoryCopy.mockReset().mockResolvedValue({ status: "ok", data: null });
  api.commands.sessionCancelFileOperation.mockReset().mockResolvedValue({ status: "ok", data: null });
});
afterEach(() => clearMocks());

async function open(direction: "upload" | "download" = "upload") {
  const button = await screen.findByRole("button", {
    name: direction === "upload" ? "Upload folder" : "Download folder logs",
  });
  await waitFor(() => expect(button).toHaveProperty("disabled", false));
  await userEvent.click(button);
  await screen.findByRole("textbox", { name: "New folder name" });
  return screen.getByRole("dialog");
}

it("reviews captured source, direction, destination and editable name before one-slot enqueue", async () => {
  render(view());
  const dialog = await open();
  expect(api.commands.sessionPrepareDirectoryCopy).toHaveBeenCalledExactlyOnceWith(
    "session-1",
    "transport-1",
    [46],
    "upload",
    "en",
  );
  expect(within(dialog).getByText("Upload: local folder → remote folder")).toBeTruthy();
  expect(within(dialog).getByText("config")).toBeTruthy();
  expect(within(dialog).getByText("remote-home")).toBeTruthy();
  expect(within(dialog).getByText(/Existing folders are never merged or replaced/)).toBeTruthy();
  expect(within(dialog).getByText(/completed files and created folders remain/)).toBeTruthy();
  expect(api.commands.sessionEnqueueDirectoryCopy).not.toHaveBeenCalled();
  expect(await violations(dialog)).toEqual([]);
  const name = screen.getByRole("textbox", { name: "New folder name" });
  await userEvent.clear(name);
  await userEvent.type(name, "config-copy");
  await userEvent.click(screen.getByRole("button", { name: "Queue folder copy" }));
  expect(api.commands.sessionEnqueueDirectoryCopy).toHaveBeenCalledExactlyOnceWith(
    "session-1",
    "transport-1",
    "selection-1",
    "config-copy",
  );
  expect(await screen.findByText("The folder was added to the transfer queue.")).toBeTruthy();
  expect(api.commands.sessionDiscardDirectoryCopy).not.toHaveBeenCalled();
});

it("downloads only a directory row using its opaque path and requires a name when no default exists", async () => {
  api.commands.sessionPrepareDirectoryCopy.mockResolvedValueOnce({
    status: "ok",
    data: {
      kind: "prepared",
      selection: selection({ direction: "download", sourceName: "logs", defaultRootName: null }),
    },
  });
  render(view());
  await open("download");
  expect(api.commands.sessionPrepareDirectoryCopy).toHaveBeenCalledExactlyOnceWith(
    "session-1",
    "transport-1",
    [46, 47, 108, 111, 103, 115],
    "download",
    "en",
  );
  expect(screen.getByText("Download: remote folder → local folder")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Download folder link" })).toBeNull();
  expect(screen.getByRole("button", { name: "Queue folder copy" })).toHaveProperty("disabled", true);
  await userEvent.type(screen.getByRole("textbox"), "logs-copy{Enter}");
  expect(api.commands.sessionEnqueueDirectoryCopy).toHaveBeenCalledExactlyOnceWith(
    "session-1",
    "transport-1",
    "selection-1",
    "logs-copy",
  );
});

it("passes an upload basename containing a backslash unchanged to Rust", async () => {
  const name = "config\\backup";
  api.commands.sessionPrepareDirectoryCopy.mockResolvedValueOnce({
    status: "ok",
    data: { kind: "prepared", selection: selection({ sourceName: name, defaultRootName: name }) },
  });
  render(view());
  await open();
  expect(screen.getByRole("textbox", { name: "New folder name" })).toHaveProperty("value", name);
  expect(screen.getByRole("button", { name: "Queue folder copy" })).toHaveProperty("disabled", false);
  await userEvent.click(screen.getByRole("button", { name: "Queue folder copy" }));
  expect(api.commands.sessionEnqueueDirectoryCopy).toHaveBeenCalledExactlyOnceWith(
    "session-1",
    "transport-1",
    "selection-1",
    name,
  );
});

it.each(["", ".", "..", "nested/name"])(
  "refuses obvious non-basename input %j without consuming selection",
  async (name) => {
    render(view());
    await open();
    const field = screen.getByRole("textbox");
    await userEvent.clear(field);
    if (name) await userEvent.type(field, name);
    expect(screen.getByRole("button", { name: "Queue folder copy" })).toHaveProperty("disabled", true);
    expect(api.commands.sessionEnqueueDirectoryCopy).not.toHaveBeenCalled();
  },
);

it.each(["upload", "download"] as const)(
  "retains the %s review after native name validation and requires explicit corrected enqueue",
  async (direction) => {
    api.commands.sessionEnqueueDirectoryCopy.mockResolvedValueOnce({ status: "error", error: "unsupportedName" });
    render(view());
    await open(direction);
    await userEvent.click(screen.getByRole("button", { name: "Queue folder copy" }));
    expect(await screen.findByRole("alert")).toHaveProperty(
      "textContent",
      expect.stringContaining("A name cannot be used unchanged"),
    );
    expect(api.commands.sessionPrepareDirectoryCopy).toHaveBeenCalledTimes(1);
    expect(api.commands.sessionDiscardDirectoryCopy).not.toHaveBeenCalled();
    await userEvent.type(screen.getByRole("textbox"), "-copy");
    await userEvent.click(screen.getByRole("button", { name: "Queue folder copy" }));
    expect(api.commands.sessionEnqueueDirectoryCopy).toHaveBeenLastCalledWith(
      "session-1",
      "transport-1",
      "selection-1",
      "config-copy",
    );
  },
);

it("discards closing review and restores keyboard focus", async () => {
  render(view());
  await open();
  await userEvent.keyboard("{Escape}");
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(api.commands.sessionDiscardDirectoryCopy).toHaveBeenCalledExactlyOnceWith("session-1", "selection-1");
  await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: "Upload folder" })));
});

it.each(["inactive", "transport", "account"])(
  "discards %s context selection through the original owner",
  async (kind) => {
    const rendered = render(view());
    await open();
    const replacementDiscard = vi.fn();
    if (kind === "account") api.owner = { ...api.commands, sessionDiscardDirectoryCopy: replacementDiscard };
    rendered.rerender(
      view({ active: kind !== "inactive", transportId: kind === "transport" ? "transport-2" : "transport-1" }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(api.commands.sessionDiscardDirectoryCopy).toHaveBeenCalledExactlyOnceWith("session-1", "selection-1");
    expect(replacementDiscard).not.toHaveBeenCalled();
    expect(api.commands.sessionEnqueueDirectoryCopy).not.toHaveBeenCalled();
  },
);

it("discards a late native selection after the dialog closes", async () => {
  const pending = deferred<{ status: "ok"; data: { kind: "prepared"; selection: SessionDirectoryCopySelection } }>();
  api.commands.sessionPrepareDirectoryCopy.mockReturnValueOnce(pending.promise);
  render(view());
  const action = await screen.findByRole("button", { name: "Upload folder" });
  await waitFor(() => expect(action).toHaveProperty("disabled", false));
  await userEvent.click(action);
  await screen.findByText(/Choose a local folder in the system dialog/);
  await userEvent.keyboard("{Escape}");
  await act(async () => pending.resolve({ status: "ok", data: { kind: "prepared", selection: selection() } }));
  await waitFor(() =>
    expect(api.commands.sessionDiscardDirectoryCopy).toHaveBeenCalledExactlyOnceWith("session-1", "selection-1"),
  );
  expect(screen.queryByRole("dialog")).toBeNull();
});

it("discards mismatched prepared authority instead of enabling enqueue", async () => {
  api.commands.sessionPrepareDirectoryCopy.mockResolvedValueOnce({
    status: "ok",
    data: { kind: "prepared", selection: selection({ transportId: "obsolete" }) },
  });
  render(view());
  const action = await screen.findByRole("button", { name: "Upload folder" });
  await waitFor(() => expect(action).toHaveProperty("disabled", false));
  await userEvent.click(action);
  expect(await screen.findByRole("alert")).toHaveProperty(
    "textContent",
    expect.stringContaining("This connection is unavailable"),
  );
  expect(api.commands.sessionDiscardDirectoryCopy).toHaveBeenCalledExactlyOnceWith("session-1", "selection-1");
  expect(screen.queryByRole("textbox")).toBeNull();
});

it("does not retry uncertain enqueue or reveal exception details", async () => {
  api.commands.sessionEnqueueDirectoryCopy.mockRejectedValueOnce(new Error("private native detail"));
  render(view());
  await open();
  await userEvent.click(screen.getByRole("button", { name: "Queue folder copy" }));
  expect(await screen.findByRole("alert")).toHaveProperty(
    "textContent",
    expect.stringContaining("check the transfer queue"),
  );
  expect(screen.queryByRole("button", { name: "Queue folder copy" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Choose again" })).toBeNull();
  expect(screen.queryByText(/private native detail/)).toBeNull();
  expect(api.commands.sessionPrepareDirectoryCopy).toHaveBeenCalledTimes(1);
  expect(api.commands.sessionEnqueueDirectoryCopy).toHaveBeenCalledTimes(1);
});

it("blocks duplicate enqueue while one admission is pending", async () => {
  const pending = deferred<unknown>();
  api.commands.sessionEnqueueDirectoryCopy.mockReturnValueOnce(pending.promise);
  render(view());
  await open();
  await userEvent.dblClick(screen.getByRole("button", { name: "Queue folder copy" }));
  expect(api.commands.sessionEnqueueDirectoryCopy).toHaveBeenCalledTimes(1);
  await act(async () => pending.resolve({ status: "ok", data: { status: "queued" } }));
});

it("reports native selection cancellation without queueing or retrying", async () => {
  api.commands.sessionPrepareDirectoryCopy.mockResolvedValueOnce({ status: "ok", data: { kind: "cancelled" } });
  render(view());
  const action = await screen.findByRole("button", { name: "Upload folder" });
  await waitFor(() => expect(action).toHaveProperty("disabled", false));
  await userEvent.click(action);
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", "The folder selection or copy was cancelled.");
  expect(screen.queryByRole("textbox")).toBeNull();
  expect(api.commands.sessionPrepareDirectoryCopy).toHaveBeenCalledTimes(1);
  expect(api.commands.sessionEnqueueDirectoryCopy).not.toHaveBeenCalled();
});

it("requires fresh selection after expiry without replaying enqueue", async () => {
  api.commands.sessionEnqueueDirectoryCopy.mockResolvedValueOnce({ status: "error", error: "selectionExpired" });
  render(view());
  await open();
  await userEvent.click(screen.getByRole("button", { name: "Queue folder copy" }));
  expect(await screen.findByRole("alert")).toHaveProperty(
    "textContent",
    "This folder selection expired. Choose the folder again.",
  );
  expect(screen.queryByRole("textbox")).toBeNull();
  expect(api.commands.sessionEnqueueDirectoryCopy).toHaveBeenCalledTimes(1);
  expect(api.commands.sessionPrepareDirectoryCopy).toHaveBeenCalledTimes(1);
  await userEvent.click(screen.getByRole("button", { name: "Choose again" }));
  await screen.findByRole("textbox");
  expect(api.commands.sessionPrepareDirectoryCopy).toHaveBeenCalledTimes(2);
  expect(api.commands.sessionEnqueueDirectoryCopy).toHaveBeenCalledTimes(1);
});

it("starts exactly one picker in StrictMode and disables entry when queue capacity is full", async () => {
  const rendered = render(<StrictMode>{view({ transfers: { ...queue, outstanding: 16 } })}</StrictMode>);
  const action = await screen.findByRole("button", { name: "Upload folder" });
  expect(action).toHaveProperty("disabled", true);
  rendered.rerender(<StrictMode>{view()}</StrictMode>);
  await waitFor(() => expect(action).toHaveProperty("disabled", false));
  await userEvent.click(action);
  await screen.findByRole("textbox");
  expect(api.commands.sessionPrepareDirectoryCopy).toHaveBeenCalledTimes(1);
});

it("localizes the complete review and fixed preparation error", async () => {
  api.commands.sessionPrepareDirectoryCopy.mockResolvedValueOnce({ status: "error", error: "nativeDialogBusy" });
  render(view({ locale: "zh-Hans" }));
  const action = await screen.findByRole("button", { name: "上传文件夹" });
  await waitFor(() => expect(action).toHaveProperty("disabled", false));
  await userEvent.click(action);
  expect(await screen.findByRole("alert")).toHaveProperty(
    "textContent",
    "另一个文件对话框已打开，请完成后重新选择文件夹。",
  );
  await userEvent.click(screen.getByRole("button", { name: "重新选择" }));
  expect(await screen.findByRole("textbox", { name: "新文件夹名称" })).toBeTruthy();
  expect(screen.getByText("上传：本地文件夹 → 远端文件夹")).toBeTruthy();
  expect(api.commands.sessionPrepareDirectoryCopy).toHaveBeenLastCalledWith(
    "session-1",
    "transport-1",
    [46],
    "upload",
    "zh-Hans",
  );
});
