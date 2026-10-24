// SPDX-License-Identifier: Apache-2.0
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { StrictMode } from "react";
import { I18nProvider } from "../src/i18n";
import type { SessionFileDrag, SessionTransferQueueSnapshot } from "../src/ipc/bindings";
import { SessionFiles, type EnqueueFeedback } from "../src/session-files";

const native = vi.hoisted(() => ({
  arm: vi.fn(),
  revoke: vi.fn(),
  consume: vi.fn(),
  cancelDrop: vi.fn(),
  listen: vi.fn(),
  list: vi.fn(),
  upload: vi.fn(),
  cancel: vi.fn(),
}));

vi.mock("../src/ipc/bindings", () => ({
  commands: {
    sessionArmFileDrop: native.arm,
    sessionRevokeFileDrop: native.revoke,
    sessionConsumeFileDrop: native.consume,
    sessionCancelFileDrop: native.cancelDrop,
    sessionListFiles: native.list,
    sessionEnqueueUpload: native.upload,
    sessionCancelFileOperation: native.cancel,
  },
  events: { sessionFileDrag: { listen: native.listen } },
}));

type Listener = (event: { payload: SessionFileDrag }) => void;
const listeners = new Set<Listener>();
const resized = new Set<() => void>();
const scales = new Set<() => void>();
let bounds: DOMRect;
let occluded: Element | null;
let point: ReturnType<typeof vi.fn>;

function rectangle(left = 600, top = 100, width = 320, height = 500): DOMRect {
  return { x: left, y: top, left, top, width, height, right: left + width, bottom: top + height, toJSON: () => ({}) };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}

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

function view({
  active = true,
  transport = "transport-1",
  locale = "en",
  transfers = queue(),
  feedback = vi.fn(),
}: {
  active?: boolean;
  transport?: string | null;
  locale?: "en" | "zh-Hans";
  transfers?: SessionTransferQueueSnapshot;
  feedback?: (feedback: EnqueueFeedback) => void;
} = {}) {
  return (
    <I18nProvider locale={locale}>
      <SessionFiles
        sessionId="session-1"
        transportId={transport}
        connectionLabel="fixture.example"
        active={active}
        queue={transfers}
        queueIssue={null}
        onClose={vi.fn()}
        onFileOutcome={vi.fn()}
        onEnqueueFeedback={feedback}
      />
    </I18nProvider>
  );
}

function context(): string {
  return native.arm.mock.calls.at(-1)![4] as string;
}

function drag(changes: Partial<SessionFileDrag> = {}): SessionFileDrag {
  return { contextId: context(), phase: "drop", ticketId: "ticket-1", count: 2, x: 0.8, y: 0.3, ...changes };
}

async function emit(event: SessionFileDrag) {
  await act(async () => {
    for (const listener of [...listeners]) listener({ payload: event });
  });
}

async function ready() {
  await waitFor(() => expect(native.arm).toHaveBeenCalled());
}

beforeEach(() => {
  bounds = rectangle();
  occluded = null;
  listeners.clear();
  resized.clear();
  scales.clear();
  vi.stubGlobal("innerWidth", 1000);
  vi.stubGlobal("innerHeight", 800);
  vi.stubGlobal("devicePixelRatio", 2);
  vi.stubGlobal(
    "ResizeObserver",
    class {
      callback: () => void;
      constructor(callback: () => void) {
        this.callback = callback;
        resized.add(callback);
      }
      observe() {}
      disconnect() {
        resized.delete(this.callback);
      }
    },
  );
  vi.stubGlobal("matchMedia", () => ({
    addEventListener: (_name: string, callback: () => void) => scales.add(callback),
    removeEventListener: (_name: string, callback: () => void) => scales.delete(callback),
  }));
  vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(function (this: HTMLElement) {
    return this.getAttribute("role") === "region" ? bounds : rectangle(0, 0, 1000, 800);
  });
  point = vi.fn(() => occluded ?? document.querySelector('[role="region"]'));
  Object.defineProperty(document, "elementFromPoint", { configurable: true, value: point });
  native.arm.mockReset().mockResolvedValue({ status: "ok", data: null });
  native.revoke.mockReset().mockResolvedValue({ status: "ok", data: null });
  native.cancelDrop.mockReset().mockResolvedValue({ status: "ok", data: null });
  native.consume.mockReset().mockResolvedValue({ status: "ok", data: { accepted: 2 } });
  native.list.mockReset().mockResolvedValue({ status: "ok", data: { entries: [] } });
  native.upload.mockReset().mockResolvedValue({ status: "ok", data: { status: "cancelled" } });
  native.cancel.mockReset().mockResolvedValue({ status: "ok", data: null });
  native.listen.mockReset().mockImplementation(async (listener: Listener) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  });
});

afterEach(async () => {
  cleanup();
  await act(async () => {
    await Promise.resolve();
  });
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  delete (document as unknown as { elementFromPoint?: unknown }).elementFromPoint;
});

it("arms a loaded empty directory and returns only its ticket after normalized hit testing", async () => {
  const feedback = vi.fn();
  render(view({ feedback }));
  await ready();
  expect(native.arm).toHaveBeenLastCalledWith("session-1", "transport-1", "queue-1", [46], expect.any(String));
  expect(screen.getByRole("region", { name: "Remote directory files" })).toBeTruthy();
  expect(screen.getByText("This directory is empty.")).toBeTruthy();
  await emit(drag({ phase: "over", ticketId: null }));
  expect(screen.getByText("Drop 2 files to upload here")).toBeTruthy();
  await emit(drag());
  expect(point).toHaveBeenCalledWith(800, 240);
  expect(native.consume).toHaveBeenCalledExactlyOnceWith(context(), "ticket-1", "en");
  expect(screen.getByText("2 files added to the upload queue.")).toBeTruthy();
  expect(feedback).toHaveBeenCalledWith({ requestId: "ticket-1", phase: "settled", issue: null });
  expect(native.upload).not.toHaveBeenCalled();
});

it.each([1, 16])("uses bounded accepted counts for %i files", async (selected) => {
  native.consume.mockResolvedValue({ status: "ok", data: { accepted: selected } });
  render(view());
  await ready();
  await emit(drag({ count: selected }));
  expect(screen.getByText(`${selected} ${selected === 1 ? "file" : "files"} added to the upload queue.`)).toBeTruthy();
});

it("shows path-free hover feedback when the native Over event has no file count", async () => {
  render(view());
  await ready();
  await emit(drag({ phase: "over", ticketId: null, count: 0 }));
  expect(screen.getByText("Drop files to upload to this directory.")).toBeTruthy();
  expect(screen.queryByText(/No files were added/)).toBeNull();
  expect(native.consume).not.toHaveBeenCalled();
  await emit(drag({ phase: "leave", ticketId: null, count: 0 }));
  expect(screen.queryByText("Drop files to upload to this directory.")).toBeNull();
});

it("keeps the upload button available by keyboard and localizes drop feedback", async () => {
  render(view({ locale: "zh-Hans" }));
  await ready();
  const button = screen.getByRole("button", { name: "上传文件" });
  button.focus();
  await userEvent.keyboard("{Enter}");
  expect(native.upload).toHaveBeenCalledWith("session-1", "transport-1", [46], "zh-Hans");
  await waitFor(() => expect(native.arm.mock.calls.length).toBeGreaterThan(1));
  await emit(drag());
  expect(native.consume).toHaveBeenLastCalledWith(context(), "ticket-1", "zh-Hans");
  expect(screen.getByText("已将 2 个文件加入上传队列。")).toBeTruthy();
});

it.each([
  ["outside the remote list", { x: 0.2, y: 0.3 }],
  ["outside the viewport", { x: 1, y: 0.3 }],
  ["a negative position", { x: -0.1, y: 0.3 }],
  ["a nonfinite position", { x: Number.NaN, y: 0.3 }],
  ["missing geometry", { x: null, y: null }],
  ["zero files", { count: 0 }],
  ["more than sixteen files", { count: 17 }],
] as const)("refuses %s without consuming the native selection", async (_name, changes) => {
  render(view());
  await ready();
  await emit(drag(changes));
  expect(native.consume).not.toHaveBeenCalled();
  expect(native.cancelDrop).toHaveBeenCalledWith(context(), "ticket-1");
});

it("refuses an occluded list even when the coordinates fall within its rectangle", async () => {
  render(view());
  await ready();
  occluded = screen.getByRole("button", { name: "Upload file" });
  await emit(drag());
  expect(native.consume).not.toHaveBeenCalled();
  expect(native.cancelDrop).toHaveBeenCalledOnce();
});

it.each(["inactive", "disconnected", "queue missing", "picker open", "listing failure"])(
  "does not arm while %s",
  async (state) => {
    if (state === "listing failure") native.list.mockResolvedValue({ status: "error", error: "listing refused" });
    render(
      view({
        active: state !== "inactive",
        transport: state === "disconnected" ? null : "transport-1",
        transfers:
          state === "queue missing"
            ? queue({ sessionId: "another-session" })
            : queue({ pickerBusy: state === "picker open" }),
      }),
    );
    await act(async () => {
      await Promise.resolve();
    });
    expect(native.arm).not.toHaveBeenCalled();
  },
);

it("does not arm before its directory listing succeeds", async () => {
  const listing = deferred<{ status: "ok"; data: { entries: [] } }>();
  native.list.mockReturnValueOnce(listing.promise);
  render(view());
  await screen.findByText("Loading remote files…");
  expect(native.arm).not.toHaveBeenCalled();
  await act(async () => listing.resolve({ status: "ok", data: { entries: [] } }));
  await ready();
});

it("does not revoke its own pending batch when the reservation fills the queue", async () => {
  const admission = deferred<{ status: "ok"; data: { accepted: number } }>();
  native.consume.mockReturnValueOnce(admission.promise);
  vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(function (this: HTMLElement) {
    if (this.getAttribute("role") !== "region") return rectangle(0, 0, 1000, 800);
    const nativeDialogMessage = [...document.querySelectorAll("p")].some(
      (paragraph) => paragraph.textContent === "Finish the open file selection or replacement confirmation.",
    );
    const blockedBeforeList = this.previousElementSibling?.textContent?.includes(
      "Directory navigation and file changes are paused",
    );
    return rectangle(600, blockedBeforeList ? 132 : 100, 320, nativeDialogMessage ? 468 : 500);
  });
  const rendered = render(view());
  await ready();
  const original = context();
  await emit(drag({ count: 16 }));
  rendered.rerender(view({ transfers: queue({ pickerBusy: true, outstanding: 16, blocksFileOperations: true }) }));
  await act(async () => {
    await Promise.resolve();
  });
  expect(native.revoke).not.toHaveBeenCalledWith(original);
  expect(screen.queryByText("Finish the open file selection or replacement confirmation.")).toBeNull();
  await act(async () => admission.resolve({ status: "ok", data: { accepted: 16 } }));
  expect(screen.getByText("16 files added to the upload queue.")).toBeTruthy();
});

it("does not mistake a hidden view's old admission for a current native selection", async () => {
  const admission = deferred<{ status: "error"; error: "staleItem" }>();
  native.consume.mockReturnValueOnce(admission.promise);
  const rendered = render(view());
  await ready();
  await emit(drag());
  rendered.rerender(view({ active: false }));
  rendered.rerender(view({ transfers: queue({ pickerBusy: true, blocksFileOperations: true }) }));
  await act(async () => {
    await Promise.resolve();
  });
  expect(native.arm).toHaveBeenCalledOnce();
  await act(async () => admission.resolve({ status: "error", error: "staleItem" }));
  rendered.rerender(view());
  await waitFor(() => expect(native.arm).toHaveBeenCalledTimes(2));
});

it("does not treat the automatic Leave after Drop as cancellation or replay the ticket", async () => {
  const admission = deferred<{ status: "ok"; data: { accepted: number } }>();
  native.consume.mockReturnValueOnce(admission.promise);
  render(view());
  await ready();
  await emit(drag());
  await emit(drag({ phase: "over", ticketId: null }));
  await emit(drag({ phase: "leave", ticketId: null }));
  await emit(drag());
  expect(screen.getByText("Checking 2 dropped files…")).toBeTruthy();
  expect(native.consume).toHaveBeenCalledOnce();
  expect(native.cancelDrop).not.toHaveBeenCalled();
  await act(async () => admission.resolve({ status: "ok", data: { accepted: 2 } }));
  expect(screen.getByText("2 files added to the upload queue.")).toBeTruthy();
});

it("waits for arm acknowledgement before consumption and fences a drop received during a late arm", async () => {
  const arming = deferred<{ status: "ok"; data: null }>();
  native.arm.mockReturnValueOnce(arming.promise);
  const rendered = render(view());
  await ready();
  await emit(drag());
  expect(native.consume).not.toHaveBeenCalled();
  rendered.rerender(view({ active: false }));
  await act(async () => arming.resolve({ status: "ok", data: null }));
  expect(native.consume).not.toHaveBeenCalled();
  expect(native.cancelDrop).toHaveBeenCalledWith(context(), "ticket-1");
});

it("does not let a refused later drop reveal an older admission reply", async () => {
  const admission = deferred<{ status: "ok"; data: { accepted: number } }>();
  native.consume.mockReturnValueOnce(admission.promise);
  render(view());
  await ready();
  await emit(drag());
  await emit(drag({ phase: "refused", ticketId: null, count: 17 }));
  await act(async () => admission.resolve({ status: "ok", data: { accepted: 2 } }));
  expect(screen.queryByText("2 files added to the upload queue.")).toBeNull();
  expect(screen.getByText(/No files were added/)).toBeTruthy();
});

it("shows a safe localized failure without exposing bridge exception contents", async () => {
  native.consume.mockRejectedValueOnce(new Error("/private/fixture/selected.bin"));
  render(view());
  await ready();
  await emit(drag());
  expect(screen.getByText("2 dropped files were not added. Try again or choose Upload file.")).toBeTruthy();
  expect(screen.queryByText(/private\/fixture/)).toBeNull();
  expect(screen.getByRole("alert").textContent).toContain("transfer or status request failed");
});

it("hit tests the actual component at a narrow Chinese viewport without applying DPR twice", async () => {
  vi.stubGlobal("innerWidth", 480);
  bounds = rectangle(0, 100, 480, 500);
  render(view({ locale: "zh-Hans" }));
  await ready();
  await emit(drag({ x: 0.75, y: 0.5 }));
  expect(point).toHaveBeenCalledWith(360, 400);
  expect(screen.getByRole("button", { name: "上传文件" })).toBeTruthy();
  expect(screen.getByText("已将 2 个文件加入上传队列。")).toBeTruthy();
});

it("fences visual viewport changes while an admission is pending", async () => {
  const viewport = new EventTarget();
  Object.assign(viewport, { width: 1000, height: 800, offsetLeft: 0, offsetTop: 0, scale: 1 });
  vi.stubGlobal("visualViewport", viewport);
  const admission = deferred<{ status: "ok"; data: { accepted: number } }>();
  native.consume.mockReturnValueOnce(admission.promise);
  render(view());
  await ready();
  const oldContext = context();
  await emit(drag());
  await act(async () => viewport.dispatchEvent(new Event("resize")));
  await waitFor(() => expect(native.revoke).toHaveBeenCalledWith(oldContext));
  await act(async () => admission.resolve({ status: "ok", data: { accepted: 2 } }));
  expect(screen.queryByText("2 files added to the upload queue.")).toBeNull();
});

it("does not let a superseded ticket's late reply replace current feedback", async () => {
  const first = deferred<{ status: "ok"; data: { accepted: number } }>();
  const second = deferred<{ status: "ok"; data: { accepted: number } }>();
  native.consume.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
  render(view());
  await ready();
  await emit(drag({ count: 1, ticketId: "old-ticket" }));
  await emit(drag({ count: 16, ticketId: "new-ticket" }));
  await act(async () => first.resolve({ status: "ok", data: { accepted: 1 } }));
  expect(screen.getByText("Checking 16 dropped files…")).toBeTruthy();
  expect(screen.queryByText("1 file added to the upload queue.")).toBeNull();
  await act(async () => second.resolve({ status: "ok", data: { accepted: 16 } }));
  expect(screen.getByText("16 files added to the upload queue.")).toBeTruthy();
});

it.each(["resize", "scale", "layout", "visibility"])("fences a pending ticket after %s changes", async (change) => {
  const admission = deferred<{ status: "ok"; data: { accepted: number } }>();
  native.consume.mockReturnValueOnce(admission.promise);
  render(view());
  await ready();
  const previous = context();
  await emit(drag());
  await act(async () => {
    if (change === "resize") window.dispatchEvent(new Event("resize"));
    if (change === "scale") for (const callback of [...scales]) callback();
    if (change === "layout") {
      bounds = rectangle(550);
      for (const callback of [...resized]) callback();
    }
    if (change === "visibility") document.dispatchEvent(new Event("visibilitychange"));
  });
  await waitFor(() => expect(native.revoke).toHaveBeenCalledWith(previous));
  await act(async () => admission.resolve({ status: "ok", data: { accepted: 2 } }));
  expect(screen.queryByText("2 files added to the upload queue.")).toBeNull();
});

it("fences an old directory and rejects native drops while a name dialog is open", async () => {
  native.list.mockResolvedValueOnce({
    status: "ok",
    data: { entries: [{ name: "logs", path: [46, 47, 108], kind: "directory", sizeBytes: null }] },
  });
  render(view());
  await ready();
  const oldEvent = drag();
  await userEvent.click(screen.getByRole("button", { name: "logs" }));
  await waitFor(() =>
    expect(native.arm).toHaveBeenLastCalledWith(
      "session-1",
      "transport-1",
      "queue-1",
      [46, 47, 108],
      expect.any(String),
    ),
  );
  await emit(oldEvent);
  expect(native.consume).not.toHaveBeenCalled();
  const beforeDialog = drag();
  await userEvent.click(screen.getByRole("button", { name: "New folder" }));
  await screen.findByRole("dialog");
  await emit(beforeDialog);
  expect(native.consume).not.toHaveBeenCalled();
});

it("revokes when an external blocking dialog appears and rearms only after it closes", async () => {
  render(view());
  await ready();
  const previous = context();
  const modal = document.createElement("div");
  modal.setAttribute("role", "dialog");
  await act(async () => document.body.append(modal));
  await waitFor(() => expect(native.revoke).toHaveBeenCalledWith(previous));
  const armedBefore = native.arm.mock.calls.length;
  await emit(drag({ contextId: previous }));
  expect(native.consume).not.toHaveBeenCalled();
  await act(async () => modal.remove());
  await waitFor(() => expect(native.arm.mock.calls.length).toBeGreaterThan(armedBefore));
});

it("ignores old transport events and late admission replies after Files becomes inactive", async () => {
  const admission = deferred<{ status: "ok"; data: { accepted: number } }>();
  native.consume.mockReturnValueOnce(admission.promise);
  const rendered = render(view());
  await ready();
  const old = drag();
  await emit(old);
  rendered.rerender(view({ active: false }));
  await emit(old);
  await act(async () => admission.resolve({ status: "ok", data: { accepted: 2 } }));
  expect(screen.queryByText("2 files added to the upload queue.")).toBeNull();
  rendered.rerender(view({ transport: "transport-2" }));
  await waitFor(() =>
    expect(native.arm).toHaveBeenLastCalledWith("session-1", "transport-2", "queue-1", [46], expect.any(String)),
  );
  await emit(old);
  expect(native.consume).toHaveBeenCalledOnce();
});

it("serializes late arm and obsolete cleanup ahead of a newer context", async () => {
  const oldArm = deferred<{ status: "ok"; data: null }>();
  native.arm.mockReturnValueOnce(oldArm.promise);
  const rendered = render(view());
  await ready();
  const previous = context();
  rendered.rerender(view({ transport: "transport-2" }));
  await act(async () => {
    await Promise.resolve();
  });
  expect(native.arm).toHaveBeenCalledOnce();
  await act(async () => oldArm.resolve({ status: "ok", data: null }));
  await waitFor(() => expect(native.arm).toHaveBeenCalledTimes(2));
  expect(native.revoke).toHaveBeenCalledWith(previous);
  expect(native.revoke).not.toHaveBeenCalledWith(context());
  expect(native.revoke.mock.invocationCallOrder[0]).toBeLessThan(native.arm.mock.invocationCallOrder[1]!);
});

it("removes a listener that registers after unmount without arming a stale context", async () => {
  const registration = deferred<() => void>();
  const stop = vi.fn();
  native.listen.mockReturnValueOnce(registration.promise);
  const rendered = render(view());
  await waitFor(() => expect(native.listen).toHaveBeenCalled());
  rendered.unmount();
  await act(async () => registration.resolve(stop));
  expect(stop).toHaveBeenCalledOnce();
  expect(native.arm).not.toHaveBeenCalled();
});

it("uses only the owned event under StrictMode and localizes queue rejection", async () => {
  native.consume.mockResolvedValue({ status: "error", error: "queueFull" });
  render(<StrictMode>{view({ locale: "zh-Hans" })}</StrictMode>);
  await ready();
  await emit(drag());
  expect(screen.getByText("拖入的 2 个文件未加入队列。请重试，或选择上传文件。")).toBeTruthy();
  expect(screen.getByText(/传输队列已满/)).toBeTruthy();
  expect(native.consume).toHaveBeenCalledOnce();
  expect(listeners.size).toBe(1);
});
