// SPDX-License-Identifier: Apache-2.0
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { sampleHosts, sampleInventory } from "../src/gallery/sample-inventory";
import { createInventoryApi } from "../src/inventory/core-api";

afterEach(() => clearMocks());

it("passes source selection, opaque review, consent and write-only passphrases through the typed native surface", async () => {
  const prepared = await sampleInventory(sampleHosts()).portableArchivePreview(true, null, "en");
  if (prepared.status !== "ok") throw new Error("The archive fixture could not be prepared");
  const preview = prepared.data;
  const native = vi.fn((command: string) =>
    command === "portable_archive_preview"
      ? preview
      : command === "portable_archive_import"
        ? { created: 1, updated: 2, unchanged: 3 }
        : null,
  );
  mockIPC(native);
  const api = createInventoryApi();
  expect(await api.portableArchivePreview(true, null, "zh-Hans")).toEqual({ status: "ok", data: preview });
  expect(native).toHaveBeenLastCalledWith("portable_archive_preview", {
    chooseFile: true,
    passphrase: null,
    locale: "zh-Hans",
  });
  await api.portableArchivePreview(false, "fixture-only archive passphrase", "en");
  expect(native).toHaveBeenLastCalledWith("portable_archive_preview", {
    chooseFile: false,
    passphrase: "fixture-only archive passphrase",
    locale: "en",
  });
  const consent = { retainSecretSourceIds: ["source-credential"], trustSourceIds: ["source-trust"] };
  expect(await api.portableArchiveImport("opaque-review-id", "fixture-only archive passphrase", consent)).toEqual({
    status: "ok",
    data: { created: 1, updated: 2, unchanged: 3 },
  });
  expect(native).toHaveBeenLastCalledWith("portable_archive_import", {
    previewId: "opaque-review-id",
    passphrase: "fixture-only archive passphrase",
    consent,
  });
  expect(await api.portableArchiveExport({ secrets: "omitted" }, null, "en")).toEqual({ status: "ok", data: null });
  expect(native).toHaveBeenLastCalledWith("portable_archive_export", {
    options: { secrets: "omitted" },
    passphrase: null,
    locale: "en",
  });
  await api.portableArchiveExport({ secrets: "included" }, "fixture-only export passphrase", "zh-Hans");
  expect(native).toHaveBeenLastCalledWith("portable_archive_export", {
    options: { secrets: "included" },
    passphrase: "fixture-only export passphrase",
    locale: "zh-Hans",
  });
  expect(await api.portableArchiveDiscard()).toEqual({ status: "ok", data: null });
  expect(native).toHaveBeenLastCalledWith("portable_archive_discard", {});
});

it("retains picker cancellation and fixed native archive errors without translation or fallback", async () => {
  const native = vi
    .fn()
    .mockResolvedValueOnce(null)
    .mockRejectedValueOnce("decryption")
    .mockRejectedValueOnce("destinationExists");
  mockIPC(native);
  const api = createInventoryApi();
  expect(await api.portableArchivePreview(true, null, "en")).toEqual({ status: "ok", data: null });
  expect(await api.portableArchivePreview(false, "wrong fixture passphrase", "en")).toEqual({
    status: "error",
    error: "decryption",
  });
  expect(await api.portableArchiveExport({ secrets: "omitted" }, null, "en")).toEqual({
    status: "error",
    error: "destinationExists",
  });
});
