// SPDX-License-Identifier: Apache-2.0
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { sampleInventory } from "../src/gallery/sample-inventory";
import { createInventoryApi } from "../src/inventory/core-api";

afterEach(() => clearMocks());

it("preserves native generated Include reviews, identity choices, receipts and lifecycle commands", async () => {
  const gallery = sampleInventory([]);
  const status = await gallery.generatedOpenSshStatus();
  const preview = await gallery.generatedOpenSshPreview();
  if (status.status !== "ok" || preview.status !== "ok") throw new Error("The Include fixture could not be prepared");
  const generated = { status: status.data, hosts: 0, files: 2 };
  const native = vi.fn((command: string) => {
    if (command === "generated_open_ssh_status" || command === "generated_open_ssh_clear") return status.data;
    if (command === "generated_open_ssh_preview") return preview.data;
    if (command === "generated_open_ssh_generate") return generated;
    return null;
  });
  mockIPC(native);
  const api = createInventoryApi();

  expect(await api.generatedOpenSshStatus()).toEqual(status);
  expect(native).toHaveBeenLastCalledWith("generated_open_ssh_status", {});
  expect(await api.generatedOpenSshPreview()).toEqual(preview);
  expect(native).toHaveBeenLastCalledWith("generated_open_ssh_preview", { choices: null });
  const choices = [{ profileId: "login-fixture", identityFile: "/home/fixture/.ssh/deployment key" }];
  expect(await api.generatedOpenSshPreview(choices)).toEqual(preview);
  expect(native).toHaveBeenLastCalledWith("generated_open_ssh_preview", { choices });
  expect(await api.generatedOpenSshGenerate(preview.data.id)).toEqual({ status: "ok", data: generated });
  expect(native).toHaveBeenLastCalledWith("generated_open_ssh_generate", { previewId: preview.data.id });
  expect(await api.generatedOpenSshClear()).toEqual(status);
  expect(native).toHaveBeenLastCalledWith("generated_open_ssh_clear", {});
  expect(await api.generatedOpenSshDiscard()).toEqual({ status: "ok", data: null });
  expect(native).toHaveBeenLastCalledWith("generated_open_ssh_discard", {});
});

it("preserves structured native refusal without substituting a success result", async () => {
  const error = { kind: "targetChanged" };
  mockIPC(() => Promise.reject(error));
  expect(await createInventoryApi().generatedOpenSshGenerate("expired-review")).toEqual({ status: "error", error });
});
