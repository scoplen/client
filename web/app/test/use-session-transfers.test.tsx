// SPDX-License-Identifier: Apache-2.0
import { act, renderHook } from "@testing-library/react";
import { StrictMode } from "react";
import type { SessionTransferQueueSnapshot } from "../src/ipc/bindings";
import { useSessionTransfers } from "../src/use-session-transfers";

const queue = vi.hoisted(() => vi.fn());
vi.mock("../src/ipc/bindings", () => ({ commands: { sessionTransferQueue: queue } }));

function snapshot(changes: Partial<SessionTransferQueueSnapshot> = {}): SessionTransferQueueSnapshot {
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

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}

async function tick() {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(250);
  });
}

beforeEach(() => {
  vi.useFakeTimers();
  queue.mockReset().mockResolvedValue({ status: "ok", data: snapshot() });
});

afterEach(() => {
  vi.useRealTimers();
});

it("reads current Rust state when Files opens and stops observing when hidden", async () => {
  const view = renderHook(({ visible }) => useSessionTransfers("session-1", visible), {
    initialProps: { visible: false },
  });
  expect(queue).not.toHaveBeenCalled();
  await act(async () => view.rerender({ visible: true }));
  expect(view.result.current.snapshot).toEqual(snapshot());
  expect(queue).toHaveBeenCalledTimes(1);
  await tick();
  expect(queue).toHaveBeenCalledTimes(2);
  view.rerender({ visible: false });
  await tick();
  expect(queue).toHaveBeenCalledTimes(2);
  expect(view.result.current.snapshot).toEqual(snapshot());
});

it("keeps one request in flight across Strict Mode and hiding/reopening Files", async () => {
  const pending = deferred<{ status: "ok"; data: SessionTransferQueueSnapshot }>();
  queue.mockReturnValueOnce(pending.promise);
  const view = renderHook(({ visible }) => useSessionTransfers("session-1", visible), {
    initialProps: { visible: true },
    wrapper: StrictMode,
  });
  await tick();
  expect(queue).toHaveBeenCalledTimes(1);
  view.rerender({ visible: false });
  view.rerender({ visible: true });
  await tick();
  expect(queue).toHaveBeenCalledTimes(1);
  await act(async () => pending.resolve({ status: "ok", data: snapshot({ revision: "2" }) }));
  expect(view.result.current.snapshot).toBeNull();
  queue.mockResolvedValue({ status: "ok", data: snapshot({ revision: "3" }) });
  await tick();
  expect(queue).toHaveBeenCalledTimes(2);
  expect(view.result.current.snapshot?.revision).toBe("3");
});

it("does not replace a newer snapshot with an older revision", async () => {
  queue
    .mockResolvedValueOnce({ status: "ok", data: snapshot({ revision: "9007199254740993" }) })
    .mockResolvedValueOnce({ status: "ok", data: snapshot({ revision: "9007199254740992" }) });
  const view = renderHook(() => useSessionTransfers("session-1", true));
  await act(async () => {});
  await tick();
  expect(view.result.current.snapshot?.revision).toBe("9007199254740993");
});

it.each(["-1", "01", "1.5", "18446744073709551616"])("refuses invalid revision %s", async (value) => {
  queue.mockResolvedValue({ status: "ok", data: snapshot({ revision: value }) });
  const view = renderHook(() => useSessionTransfers("session-1", true));
  await act(async () => {});
  expect(view.result.current.snapshot).toBeNull();
});

it("ignores a late result from a replaced logical session", async () => {
  const pending = deferred<{ status: "ok"; data: SessionTransferQueueSnapshot }>();
  queue.mockReturnValueOnce(pending.promise);
  const view = renderHook(({ sessionId }) => useSessionTransfers(sessionId, true), {
    initialProps: { sessionId: "session-1" },
  });
  view.rerender({ sessionId: "session-2" });
  expect(view.result.current.snapshot).toBeNull();
  await act(async () => pending.resolve({ status: "ok", data: snapshot() }));
  expect(view.result.current.snapshot).toBeNull();
  queue.mockResolvedValue({ status: "ok", data: snapshot({ sessionId: "session-2", queueId: "queue-2" }) });
  await tick();
  expect(view.result.current.snapshot?.queueId).toBe("queue-2");
  expect(queue).toHaveBeenLastCalledWith("session-2");
});

it("preserves known state on an observation failure without replaying an intent", async () => {
  queue
    .mockResolvedValueOnce({ status: "ok", data: snapshot() })
    .mockRejectedValueOnce(new Error("synthetic private failure"))
    .mockResolvedValueOnce({ status: "ok", data: snapshot({ revision: "2" }) });
  const view = renderHook(() => useSessionTransfers("session-1", true));
  await act(async () => {});
  await tick();
  expect(view.result.current.snapshot?.revision).toBe("1");
  expect(view.result.current.issue).toBe("transferFailed");
  await tick();
  expect(view.result.current.snapshot?.revision).toBe("2");
  expect(view.result.current.issue).toBeNull();
});

it("shows a typed observation error and refuses another session's snapshot", async () => {
  queue
    .mockResolvedValueOnce({ status: "error", error: "sessionUnavailable" })
    .mockResolvedValueOnce({ status: "ok", data: snapshot({ sessionId: "another-session" }) });
  const view = renderHook(() => useSessionTransfers("session-1", true));
  await act(async () => {});
  expect(view.result.current.issue).toBe("sessionUnavailable");
  await tick();
  expect(view.result.current.snapshot).toBeNull();
});

it("stops requesting snapshots after the logical view unmounts", async () => {
  const view = renderHook(() => useSessionTransfers("session-1", true));
  await act(async () => {});
  view.unmount();
  await tick();
  expect(queue).toHaveBeenCalledTimes(1);
});
