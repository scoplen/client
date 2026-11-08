// SPDX-License-Identifier: Apache-2.0
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { sampleInventory } from "../src/gallery/sample-inventory";
import type { OpenSshImportChoice } from "../src/inventory/api";
import { createInventoryApi } from "../src/inventory/core-api";

afterEach(() => clearMocks());

it("carries identity choices and the complete reviewed revision through the native boundary", async () => {
  const path = "/home/fixture/.ssh/config";
  const choices: OpenSshImportChoice[] = [{ alias: "prod-api", identityFile: null, credentialId: "c-laptop" }];
  const prepared = await sampleInventory([]).previewOpenSshConfig(path, choices);
  if (prepared.status !== "ok") throw new Error("The import fixture could not be prepared");
  const preview = prepared.data;
  const accepted = {
    hosts: [],
    created: 1,
    updated: 0,
    unchanged: 0,
    trustRecords: 1,
    skippedHosts: [],
    unsupported: [],
  };
  const native = vi.fn((command: string) => (command === "inventory_import_open_ssh_config" ? accepted : preview));
  mockIPC(native);
  const api = createInventoryApi();

  expect(await api.previewOpenSshConfig(path)).toEqual({ status: "ok", data: preview });
  expect(native).toHaveBeenLastCalledWith("inventory_preview_open_ssh_config", { path, choices: null });
  expect(await api.previewOpenSshConfig(path, choices)).toEqual({ status: "ok", data: preview });
  expect(native).toHaveBeenLastCalledWith("inventory_preview_open_ssh_config", { path, choices });
  expect(await api.importOpenSshConfig(preview)).toEqual({ status: "ok", data: accepted });
  expect(native).toHaveBeenLastCalledWith("inventory_import_open_ssh_config", { preview });
});
