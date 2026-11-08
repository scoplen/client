// SPDX-License-Identifier: Apache-2.0
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { sampleHosts, sampleInventory } from "../src/gallery/sample-inventory";
import type { OpenSshExportChoice } from "../src/inventory/api";
import { createInventoryApi } from "../src/inventory/core-api";

afterEach(() => clearMocks());

it("preserves the reviewed native export, external identity choices, locale and native cancellation", async () => {
  const choices: OpenSshExportChoice[] = [{ profileId: "l-1", identityFile: "/home/fixture/.ssh/deployment" }];
  const prepared = await sampleInventory(sampleHosts()).previewOpenSshExport(choices);
  if (prepared.status !== "ok") throw new Error("The export fixture could not be prepared");
  const preview = prepared.data;
  const native = vi.fn((command: string) => (command === "inventory_export_open_ssh_config" ? null : preview));
  mockIPC(native);
  const api = createInventoryApi();

  expect(await api.previewOpenSshExport()).toEqual({ status: "ok", data: preview });
  expect(native).toHaveBeenLastCalledWith("inventory_preview_open_ssh_export", { choices: null });
  expect(await api.previewOpenSshExport(choices)).toEqual({ status: "ok", data: preview });
  expect(native).toHaveBeenLastCalledWith("inventory_preview_open_ssh_export", { choices });
  expect(await api.exportOpenSshConfig(preview, "zh-Hans")).toEqual({ status: "ok", data: null });
  expect(native).toHaveBeenLastCalledWith("inventory_export_open_ssh_config", { preview, locale: "zh-Hans" });
});
