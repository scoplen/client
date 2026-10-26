// SPDX-License-Identifier: Apache-2.0
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { I18nProvider } from "../src/i18n";
import type { SessionEditorSnapshot, SessionTransferQueueSnapshot } from "../src/ipc/bindings";
import { SessionFiles } from "../src/session-files";

const api = vi.hoisted(() => ({
  list: vi.fn(),
  cancel: vi.fn(),
  snapshot: vi.fn(),
  start: vi.fn(),
  open: vi.fn(),
  upload: vi.fn(),
  stop: vi.fn(),
}));

vi.mock("../src/ipc/bindings", () => ({
  commands: {
    sessionListFiles: api.list,
    sessionCancelFileOperation: api.cancel,
    sessionEditorSnapshot: api.snapshot,
    sessionEditFile: api.start,
    sessionEditorOpen: api.open,
    sessionEditorUpload: api.upload,
    sessionEditorStop: api.stop,
  },
}));

const file = { name: "service.conf", path: [46, 47, 255, 47, 115], kind: "file", sizeBytes: "8" };
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

function copy(changes: Partial<SessionEditorSnapshot> = {}): SessionEditorSnapshot {
  return {
    sessionId: "session-1",
    editorId: "editor-1",
    transportId: "transport-1",
    remoteName: "./config/service.conf",
    localName: "working.txt",
    state: "watching",
    issue: null,
    canOpen: true,
    transfer: null,
    ...changes,
  };
}

let current: SessionEditorSnapshot | null;

function view({
  active = true,
  transportId = "transport-1" as string | null,
  locale = "en" as "en" | "zh-Hans",
  transfers = queue,
} = {}) {
  return (
    <I18nProvider locale={locale}>
      <SessionFiles
        key="files"
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
  current = null;
  api.list.mockReset().mockResolvedValue({ status: "ok", data: { entries: [file] } });
  api.cancel.mockReset().mockResolvedValue({ status: "ok", data: null });
  api.snapshot.mockReset().mockImplementation(async () => ({ status: "ok", data: current }));
  api.start.mockReset().mockImplementation(async () => {
    current = copy({ state: "preparing", localName: null });
    return { status: "ok", data: { kind: "started", editorId: "editor-1" } };
  });
  api.open.mockReset().mockResolvedValue({ status: "ok", data: null });
  api.upload.mockReset().mockImplementation(async () => {
    current = copy({
      state: "queued",
      transfer: { queueId: "queue-1", itemId: "upload-1", executionId: "execution-1" },
    });
    return {
      status: "ok",
      data: { status: "queued", queueId: "queue-1", itemId: "upload-1", executionId: "execution-1" },
    };
  });
  api.stop.mockReset().mockImplementation(async () => {
    current = null;
    return { status: "ok", data: null };
  });
});

afterEach(() => clearMocks());

async function confirmStart() {
  const edit = await screen.findByRole("button", { name: "Edit service.conf locally" });
  await waitFor(() => expect(edit).toHaveProperty("disabled", false));
  await userEvent.click(edit);
  return screen.findByRole("dialog", { name: "Edit locally: service.conf" });
}

it("explains the ordinary local copy and requires explicit intent before native selection", async () => {
  render(view());
  const dialog = await confirmStart();
  expect(within(dialog).getByText(/outside Scoplen's encrypted storage/)).toBeTruthy();
  expect(within(dialog).getByText(/Saving in the editor does not upload/)).toBeTruthy();
  expect(api.start).not.toHaveBeenCalled();
  await userEvent.click(within(dialog).getByRole("button", { name: "Choose copy and open editor" }));
  expect(api.start).toHaveBeenCalledExactlyOnceWith("session-1", "transport-1", file.path, "en");
  expect(await screen.findByText("Preparing the local working copy…")).toBeTruthy();
  expect(api.upload).not.toHaveBeenCalled();
});

it("closing the confirmation does not select, download, or open an editor", async () => {
  render(view());
  await confirmStart();
  await userEvent.keyboard("{Escape}");
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(api.start).not.toHaveBeenCalled();
  expect(api.open).not.toHaveBeenCalled();
});

it("saved-change detection never uploads and an explicit upload names only the retained editor", async () => {
  current = copy();
  render(view());
  const panel = await screen.findByRole("region", { name: "Local editing" });
  expect(within(panel).getByText("Remote target: ./config/service.conf")).toBeTruthy();
  expect(within(panel).getByText("Local copy: working.txt")).toBeTruthy();
  current = copy({ state: "changesDetected" });
  await screen.findByText("Saved local changes are ready to upload.");
  expect(api.upload).not.toHaveBeenCalled();
  await userEvent.click(within(panel).getByRole("button", { name: "Upload changes" }));
  expect(api.upload).toHaveBeenCalledExactlyOnceWith("session-1", "transport-1", "editor-1", "en");
  await screen.findByText("Changes are queued for upload. See the transfer queue below.");
  expect(within(panel).getByRole("button", { name: "Upload changes" })).toHaveProperty("disabled", true);
});

it("one pending upload prevents a second request", async () => {
  current = copy({ state: "changesDetected" });
  const pending = deferred<{ status: "ok"; data: { status: "cancelled" } }>();
  api.upload.mockReturnValueOnce(pending.promise);
  render(view());
  const button = await screen.findByRole("button", { name: "Upload changes" });
  await waitFor(() => expect(button).toHaveProperty("disabled", false));
  await userEvent.dblClick(button);
  expect(api.upload).toHaveBeenCalledTimes(1);
  expect(button).toHaveProperty("disabled", true);
  await act(async () => pending.resolve({ status: "ok", data: { status: "cancelled" } }));
});

it("open and stop are explicit and stopping leaves the saved copy under user control", async () => {
  current = copy();
  render(view());
  const button = await screen.findByRole("button", { name: "Open editor" });
  expect(api.open).not.toHaveBeenCalled();
  await waitFor(() => expect(button).toHaveProperty("disabled", false));
  await userEvent.click(button);
  expect(api.open).toHaveBeenCalledExactlyOnceWith("session-1", "editor-1");
  const stop = screen.getByRole("button", { name: "Stop editing" });
  await waitFor(() => expect(stop).toHaveProperty("disabled", false));
  expect(screen.getByText("Stopping keeps your local copy and leaves the external editor open.")).toBeTruthy();
  await userEvent.click(stop);
  expect(api.stop).toHaveBeenCalledExactlyOnceWith("session-1", "editor-1");
  await waitFor(() => expect(screen.queryByRole("region", { name: "Local editing" })).toBeNull());
});

it("hiding and remounting Files discovers the same Rust-owned working copy without starting another", async () => {
  current = copy({ state: "changesDetected" });
  const first = render(view());
  await screen.findByText("Saved local changes are ready to upload.");
  first.unmount();
  expect(api.stop).not.toHaveBeenCalled();
  render(view());
  await screen.findByText("Saved local changes are ready to upload.");
  expect(api.start).not.toHaveBeenCalled();
  expect(api.upload).not.toHaveBeenCalled();
});

it("an old transport cannot upload through its replacement", async () => {
  current = copy({ state: "unavailable" });
  render(view({ transportId: "new-transport" }));
  await screen.findByText("This editing connection is unavailable. Your local copy is retained.");
  expect(screen.getByRole("button", { name: "Upload changes" })).toHaveProperty("disabled", true);
  expect(screen.getByRole("button", { name: "Edit service.conf locally" })).toHaveProperty("disabled", true);
  expect(api.upload).not.toHaveBeenCalled();
});

it("inactive panes cannot start or mutate editing", async () => {
  current = copy({ state: "changesDetected" });
  const rendered = render(view());
  await screen.findByText("Saved local changes are ready to upload.");
  rendered.rerender(view({ active: false }));
  expect(screen.getByRole("button", { name: "Upload changes" })).toHaveProperty("disabled", true);
  expect(screen.getByRole("button", { name: "Open editor" })).toHaveProperty("disabled", true);
  expect(screen.getByRole("button", { name: "Stop editing" })).toHaveProperty("disabled", true);
  expect(api.upload).not.toHaveBeenCalled();
});

it("becoming inactive dismisses an unconfirmed Edit dialog", async () => {
  const rendered = render(view());
  await confirmStart();
  rendered.rerender(view({ active: false }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(api.start).not.toHaveBeenCalled();
});

it.each(["preparing", "opening", "queued", "uploading", "unavailable", "unknown"] as const)(
  "refuses upload in %s",
  async (state) => {
    current = copy({ state });
    render(view());
    expect(await screen.findByRole("button", { name: "Upload changes" })).toHaveProperty("disabled", true);
    expect(api.upload).not.toHaveBeenCalled();
  },
);

it("a full transfer queue disables upload without stopping local observation", async () => {
  current = copy({ state: "changesDetected" });
  render(view({ transfers: { ...queue, outstanding: 16 } }));
  await screen.findByText("Saved local changes are ready to upload.");
  expect(screen.getByRole("button", { name: "Upload changes" })).toHaveProperty("disabled", true);
  expect(api.stop).not.toHaveBeenCalled();
});

it("shows fixed errors without bridge details and does not retry an upload after polling", async () => {
  current = copy({ state: "changesDetected" });
  api.upload.mockRejectedValueOnce(new Error("private local path and contents"));
  render(view());
  const upload = await screen.findByRole("button", { name: "Upload changes" });
  await waitFor(() => expect(upload).toHaveProperty("disabled", false));
  await userEvent.click(upload);
  expect(
    await screen.findByText(
      "Local editing could not be completed. Check the connection and local copy before trying again.",
    ),
  ).toBeTruthy();
  await waitFor(() => expect(api.snapshot.mock.calls.length).toBeGreaterThanOrEqual(3));
  expect(api.upload).toHaveBeenCalledTimes(1);
  expect(screen.queryByText(/private local path/)).toBeNull();
  expect(screen.getByRole("alert").textContent).toContain("Local editing could not be completed");
});

it("shows launch failure with an explicit retry and keeps the working-copy name visible", async () => {
  current = copy({ issue: "editorLaunchFailed" });
  render(view());
  expect(await screen.findByText(/The text editor could not open/)).toBeTruthy();
  expect(screen.getByText("Local copy: working.txt")).toBeTruthy();
  expect(api.open).not.toHaveBeenCalled();
});

it("localizes editing and its upload warning in Chinese", async () => {
  current = copy({ state: "unknown", issue: "publicationUnknown" });
  render(view({ locale: "zh-Hans" }));
  expect(await screen.findByRole("region", { name: "本地编辑" })).toBeTruthy();
  expect(screen.getByText(/上传可能已完成/)).toBeTruthy();
  expect(screen.getByRole("button", { name: "上传更改" })).toHaveProperty("disabled", true);
  expect(screen.getByRole("button", { name: "打开编辑器" })).toBeTruthy();
});

it("a closed Files view discards a late snapshot reply", async () => {
  const pending = deferred<{ status: "ok"; data: SessionEditorSnapshot }>();
  api.snapshot.mockReturnValueOnce(pending.promise);
  const rendered = render(view());
  await waitFor(() => expect(api.snapshot).toHaveBeenCalledTimes(1));
  rendered.unmount();
  await act(async () => pending.resolve({ status: "ok", data: copy({ remoteName: "stale remote name" }) }));
  expect(screen.queryByText(/stale remote name/)).toBeNull();
  expect(api.stop).not.toHaveBeenCalled();
});

it("disconnecting during an upload request releases UI busy state and ignores its late reply", async () => {
  current = copy({ state: "changesDetected" });
  const pending = deferred<{ status: "error"; error: "transferFailed" }>();
  api.upload.mockReturnValueOnce(pending.promise);
  const rendered = render(view());
  const upload = await screen.findByRole("button", { name: "Upload changes" });
  await waitFor(() => expect(upload).toHaveProperty("disabled", false));
  await userEvent.click(upload);
  expect(upload).toHaveProperty("disabled", true);
  current = copy({ state: "unavailable", canOpen: true });
  rendered.rerender(view({ transportId: null }));
  await screen.findByText("This editing connection is unavailable. Your local copy is retained.");
  const stop = screen.getByRole("button", { name: "Stop editing" });
  await waitFor(() => expect(stop).toHaveProperty("disabled", false));
  expect(screen.getByRole("button", { name: "Open editor" })).toHaveProperty("disabled", false);
  await userEvent.click(stop);
  expect(api.stop).toHaveBeenCalledExactlyOnceWith("session-1", "editor-1");
  await act(async () => pending.resolve({ status: "error", error: "transferFailed" }));
  await waitFor(() => expect(screen.queryByRole("region", { name: "Local editing" })).toBeNull());
  expect(api.upload).toHaveBeenCalledTimes(1);
  expect(screen.queryByText(/Local editing could not be completed/)).toBeNull();
});

it.each(["opening", "queued", "uploading", "unknown", "unavailable"] as const)(
  "respects the native Open capability in %s",
  async (state) => {
    current = copy({ state, canOpen: false });
    render(view());
    expect(await screen.findByRole("button", { name: "Open editor" })).toHaveProperty("disabled", true);
    expect(api.open).not.toHaveBeenCalled();
  },
);
