// SPDX-License-Identifier: Apache-2.0
import { emit } from "@tauri-apps/api/event";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { render, waitFor } from "@testing-library/react";
import type { StoreChanged } from "../src/ipc/bindings";
import { useStoreChanges } from "../src/ipc/store-events";
import { createInventoryApi } from "../src/inventory/core-api";

afterEach(() => clearMocks());

function Listener({ onChange }: { onChange: (change: StoreChanged) => void }) {
  useStoreChanges(["host", "accessProfile"], onChange);
  return null;
}

describe("useStoreChanges", () => {
  it("refreshes inventory consumers after a saved Forward changes", async () => {
    mockIPC(() => undefined, { shouldMockEvents: true });
    const listener = vi.fn();
    const stop = createInventoryApi().onChange(listener);
    await waitFor(async () => {
      await emit("store-changed", { recordType: "forward", ids: ["forward-1"] });
      expect(listener).toHaveBeenCalled();
    });
    stop();
    const count = listener.mock.calls.length;
    await emit("store-changed", { recordType: "forward", ids: ["forward-1"] });
    expect(listener).toHaveBeenCalledTimes(count);
  });
  it("delivers changes of the requested types and stops on unmount", async () => {
    mockIPC(() => undefined, { shouldMockEvents: true });
    const heard: StoreChanged[] = [];
    const view = render(<Listener onChange={(change) => heard.push(change)} />);
    const host: StoreChanged = { profileGeneration: "1", recordType: "host", ids: ["0190-a"] };
    await waitFor(async () => {
      await emit("store-changed", host);
      expect(heard.length).toBeGreaterThan(0);
    });
    heard.length = 0;
    await emit("store-changed", { recordType: "snippet", ids: ["0190-b"] });
    await emit("store-changed", { recordType: "accessProfile", ids: ["0190-c"] });
    expect(heard).toEqual([{ recordType: "accessProfile", ids: ["0190-c"] }]);

    view.unmount();
    await emit("store-changed", host);
    expect(heard).toHaveLength(1);
  });
});
