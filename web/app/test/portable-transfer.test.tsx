// SPDX-License-Identifier: Apache-2.0
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { violations } from "../../ui/test/axe";
import { sampleHosts, sampleInventory } from "../src/gallery/sample-inventory";
import { I18nProvider } from "../src/i18n";
import {
  InventoryContext,
  type InventoryApi,
  type PortableArchiveError,
  type PortableArchiveImportEntry,
  type PortableArchiveImportPreview,
} from "../src/inventory/api";
import { PortableTransferSettings } from "../src/inventory/portable-transfer";

const fingerprint = "SHA256:O7eF0pQnTwA5kHRhgJ19fwzD12pE7nECpMX0gxW1pfA";
function entry(change: Partial<PortableArchiveImportEntry> = {}): PortableArchiveImportEntry {
  return {
    sourceId: "source-host",
    targetId: null,
    objectType: "Host",
    action: "create",
    omittedSecrets: [],
    retainSecretAvailable: false,
    requiresDeviceSetup: false,
    trust: null,
    problem: null,
    ...change,
  };
}
function preview(entries = [entry()]): PortableArchiveImportPreview {
  return {
    id: "review-id",
    sourceRevision: "source-revision",
    destinationRevision: "destination-revision",
    destination: { scope: "personal", ownerId: "account-id", vaultId: "vault-id" },
    entries,
    canImport: true,
  };
}
function setup(value = preview()) {
  const api = sampleInventory(sampleHosts());
  vi.spyOn(api, "portableArchivePreview").mockResolvedValue({ status: "ok", data: value });
  vi.spyOn(api, "portableArchiveImport").mockResolvedValue({
    status: "ok",
    data: { created: 1, updated: 0, unchanged: 0 },
  });
  vi.spyOn(api, "portableArchiveExport").mockResolvedValue({
    status: "ok",
    data: {
      destination: { scope: "local" },
      objects: 3,
      secrets: "omitted",
    },
  });
  vi.spyOn(api, "portableArchiveDiscard");
  return api;
}
function show(api: InventoryApi, locale: "en" | "zh-Hans" = "en") {
  return render(
    <I18nProvider locale={locale}>
      <InventoryContext.Provider value={api}>
        <PortableTransferSettings />
      </InventoryContext.Provider>
    </I18nProvider>,
  );
}
async function openImport(api: InventoryApi) {
  show(api);
  await userEvent.click(screen.getByRole("button", { name: "Import Scoplen backup" }));
  return screen.findByRole("dialog", { name: "Review Scoplen import" });
}
async function openExport(api: InventoryApi) {
  show(api);
  await userEvent.click(screen.getByRole("button", { name: "Export Scoplen backup" }));
  return screen.findByRole("dialog", { name: "Export Scoplen backup" });
}

describe("portable inventory backup", () => {
  it("previews the explicit destination and mapped targets before confirming a whole import", async () => {
    const api = setup(
      preview([
        entry(),
        entry({ sourceId: "source-group", objectType: "HostGroup", action: "replace", targetId: "existing-group" }),
        entry({
          sourceId: "source-route",
          objectType: "Route",
          action: "unchanged",
          targetId: "existing-route",
          requiresDeviceSetup: true,
        }),
      ]),
    );
    const dialog = await openImport(api);
    expect(api.portableArchivePreview).toHaveBeenCalledWith(true, null, "en");
    expect(api.portableArchiveImport).not.toHaveBeenCalled();
    expect(within(dialog).getByText("Destination: Personal")).toBeTruthy();
    expect(within(dialog).getByText("account-id")).toBeTruthy();
    expect(within(dialog).getByText("vault-id")).toBeTruthy();
    expect(within(dialog).getByText("existing-group")).toBeTruthy();
    expect(within(dialog).getByText("New: 1 · Updated: 1 · Unchanged: 1 · Blocked: 0")).toBeTruthy();
    expect(within(dialog).getByText(/Set up this device-bound credential/)).toBeTruthy();
    await userEvent.click(within(dialog).getByRole("button", { name: "Import reviewed backup" }));
    expect(api.portableArchiveImport).toHaveBeenCalledWith("review-id", null, {
      retainSecretSourceIds: [],
      trustSourceIds: [],
    });
    expect((await screen.findByRole("status")).textContent).toContain("Imported: 1 new");
    expect(api.portableArchiveDiscard).toHaveBeenCalled();
  });

  it("requires each credential retention and complete trust acceptance while leaving snippet retention optional", async () => {
    const api = setup(
      preview([
        entry({
          sourceId: "source-credential",
          objectType: "Credential",
          targetId: "existing-key",
          action: "replace",
          omittedSecrets: ["/secret"],
          retainSecretAvailable: true,
        }),
        entry({
          sourceId: "source-snippet",
          objectType: "Snippet",
          targetId: "existing-snippet",
          action: "replace",
          omittedSecrets: ["/variables/key/default"],
          retainSecretAvailable: true,
        }),
        entry({
          sourceId: "source-trust",
          objectType: "TrustRecord",
          trust: { algorithm: "ssh-ed25519", fingerprint, isCa: true, revoked: true, requiresConsent: true },
        }),
      ]),
    );
    const dialog = await openImport(api);
    const submit = within(dialog).getByRole("button", { name: "Import reviewed backup" });
    const choices = within(dialog).getAllByRole("checkbox");
    expect(choices).toHaveLength(3);
    for (const choice of choices) expect((choice as HTMLInputElement).checked).toBe(false);
    expect((submit as HTMLButtonElement).disabled).toBe(true);
    expect(within(dialog).getByText(fingerprint)).toBeTruthy();
    expect(within(dialog).getByText("ssh-ed25519")).toBeTruthy();
    expect(within(dialog).getByText("Certificate authority key · Revoked")).toBeTruthy();
    expect(within(dialog).getByRole("checkbox", { description: new RegExp(fingerprint) })).toBe(choices[2]);
    expect(within(dialog).getByText(/omitted Secret defaults are cleared/)).toBeTruthy();
    await userEvent.click(choices[0]!);
    expect((submit as HTMLButtonElement).disabled).toBe(true);
    await userEvent.click(choices[2]!);
    expect((submit as HTMLButtonElement).disabled).toBe(false);
    await userEvent.click(submit);
    expect(api.portableArchiveImport).toHaveBeenCalledWith("review-id", null, {
      retainSecretSourceIds: ["source-credential"],
      trustSourceIds: ["source-trust"],
    });
  });

  it("allows a new snippet without secret defaults and does not offer to retain nonexistent values", async () => {
    const api = setup(preview([entry({ objectType: "Snippet", omittedSecrets: ["/variables/token/default"] })]));
    const dialog = await openImport(api);
    expect(
      within(dialog).getByText("This backup omits these Secret defaults. Enter them when running the snippet."),
    ).toBeTruthy();
    expect(within(dialog).queryByRole("checkbox")).toBeNull();
    expect((within(dialog).getByRole("button", { name: "Import reviewed backup" }) as HTMLButtonElement).disabled).toBe(
      false,
    );
  });

  it("clears consents on refresh and disables confirmation after inventory changes", async () => {
    const api = setup(
      preview([
        entry({
          sourceId: "source-trust",
          objectType: "TrustRecord",
          trust: {
            algorithm: "ssh-ed25519",
            fingerprint,
            isCa: false,
            revoked: false,
            requiresConsent: true,
          },
        }),
      ]),
    );
    let changed = () => {};
    vi.spyOn(api, "onChange").mockImplementation((listener) => {
      changed = listener;
      return () => {};
    });
    const dialog = await openImport(api);
    await userEvent.click(within(dialog).getByRole("checkbox"));
    const submit = within(dialog).getByRole("button", { name: "Import reviewed backup" });
    expect((submit as HTMLButtonElement).disabled).toBe(false);
    act(() => changed());
    expect((submit as HTMLButtonElement).disabled).toBe(true);
    await userEvent.click(within(dialog).getByRole("button", { name: "Refresh preview" }));
    expect(api.portableArchivePreview).toHaveBeenLastCalledWith(false, null, "en");
    expect((within(dialog).getByRole("checkbox") as HTMLInputElement).checked).toBe(false);
    expect((submit as HTMLButtonElement).disabled).toBe(true);
  });

  it.each(["sourceChanged", "destinationChanged", "contextChanged", "previewExpired"] as const)(
    "requires a fresh review after %s",
    async (error) => {
      const api = setup();
      vi.mocked(api.portableArchiveImport).mockResolvedValue({ status: "error", error });
      const dialog = await openImport(api);
      const submit = within(dialog).getByRole("button", { name: "Import reviewed backup" });
      await userEvent.click(submit);
      expect(await within(dialog).findByRole("alert")).toBeTruthy();
      expect((submit as HTMLButtonElement).disabled).toBe(true);
      await userEvent.click(within(dialog).getByRole("button", { name: "Refresh preview" }));
      await waitFor(() => expect((submit as HTMLButtonElement).disabled).toBe(false));
    },
  );

  it.each([
    "missingReference",
    "missingSecret",
    "incompatibleTarget",
    "deletedTarget",
    "preferenceConflict",
    "unsupportedData",
    "invalidTrust",
  ] as const)("blocks the whole import for %s", async (problem) => {
    const value = preview([entry({ action: "blocked", problem }), entry({ sourceId: "unblocked-source" })]);
    value.canImport = false;
    const api = setup(value);
    const dialog = await openImport(api);
    expect((within(dialog).getByRole("button", { name: "Import reviewed backup" }) as HTMLButtonElement).disabled).toBe(
      true,
    );
    expect(within(dialog).getByText(/Nothing can be imported until every blocked entry/)).toBeTruthy();
    expect(api.portableArchiveImport).not.toHaveBeenCalled();
  });

  it("unlocks the same native source without exposing a path, and clears each transient passphrase", async () => {
    const api = setup();
    vi.mocked(api.portableArchivePreview).mockResolvedValueOnce({ status: "error", error: "passphraseRequired" });
    const dialog = await openImport(api);
    const input = within(dialog).getByLabelText<HTMLInputElement>("Backup passphrase");
    await userEvent.type(input, "fixture archive passphrase");
    await userEvent.click(within(dialog).getByRole("button", { name: "Preview encrypted backup" }));
    expect(api.portableArchivePreview).toHaveBeenLastCalledWith(false, "fixture archive passphrase", "en");
    expect(input.value).toBe("");
    const submit = within(dialog).getByRole("button", { name: "Import reviewed backup" });
    expect((submit as HTMLButtonElement).disabled).toBe(true);
    await userEvent.type(input, "fixture archive passphrase");
    let resolve: ((value: Awaited<ReturnType<InventoryApi["portableArchiveImport"]>>) => void) | undefined;
    vi.mocked(api.portableArchiveImport).mockImplementation(
      () =>
        new Promise((done) => {
          resolve = done;
        }),
    );
    await userEvent.click(submit);
    expect(input.value).toBe("");
    expect(api.portableArchiveImport).toHaveBeenCalledWith("review-id", "fixture archive passphrase", {
      retainSecretSourceIds: [],
      trustSourceIds: [],
    });
    await act(async () => resolve?.({ status: "error", error: "decryption" }));
    expect((await within(dialog).findByRole("alert")).textContent).toMatch(/could not be decrypted or verified/);
    expect((submit as HTMLButtonElement).disabled).toBe(true);
    expect(input.value).toBe("");
  });

  it("handles file-picker cancellation without an import, and discards pending source on cancel or unmount", async () => {
    const api = setup();
    vi.mocked(api.portableArchivePreview).mockResolvedValueOnce({ status: "ok", data: null });
    const view = show(api);
    await userEvent.click(screen.getByRole("button", { name: "Import Scoplen backup" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Import Scoplen backup" }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(api.portableArchiveDiscard).toHaveBeenCalledTimes(1);
    expect(api.portableArchiveImport).not.toHaveBeenCalled();
    view.unmount();
    expect(api.portableArchiveDiscard).toHaveBeenCalledTimes(2);
  });

  it("defaults to omitted-secret JSON and reports a completed native export", async () => {
    const api = setup();
    const dialog = await openExport(api);
    expect((within(dialog).getByRole("checkbox") as HTMLInputElement).checked).toBe(false);
    expect(within(dialog).queryByLabelText("Backup passphrase")).toBeNull();
    await userEvent.click(within(dialog).getByRole("button", { name: "Save backup" }));
    expect(api.portableArchiveExport).toHaveBeenCalledWith({ secrets: "omitted" }, null, "en");
    expect((await within(dialog).findByRole("status")).textContent).toContain("Exported 3 objects");
    expect(within(dialog).getByText("Saved as JSON with portable secrets omitted.")).toBeTruthy();
  });

  it("requires an explicit secret choice and matching passphrases, clearing both before native completion", async () => {
    const api = setup();
    let resolve: ((value: Awaited<ReturnType<InventoryApi["portableArchiveExport"]>>) => void) | undefined;
    vi.mocked(api.portableArchiveExport).mockImplementation(
      () =>
        new Promise((done) => {
          resolve = done;
        }),
    );
    const dialog = await openExport(api);
    await userEvent.click(within(dialog).getByRole("checkbox"));
    const save = within(dialog).getByRole("button", { name: "Save backup" });
    expect((save as HTMLButtonElement).disabled).toBe(true);
    const input = within(dialog).getByLabelText<HTMLInputElement>("Backup passphrase");
    const repeated = within(dialog).getByLabelText<HTMLInputElement>("Repeat passphrase");
    await userEvent.type(input, "fixture encrypted export");
    expect((save as HTMLButtonElement).disabled).toBe(true);
    await userEvent.type(repeated, "different fixture passphrase");
    expect(within(dialog).getByText("The two passphrases are different.")).toBeTruthy();
    expect(repeated.getAttribute("aria-invalid")).toBe("true");
    await userEvent.click(save);
    expect(api.portableArchiveExport).not.toHaveBeenCalled();
    await userEvent.clear(repeated);
    await userEvent.type(repeated, "fixture encrypted export");
    expect((save as HTMLButtonElement).disabled).toBe(false);
    expect(within(dialog).queryByText("The two passphrases are different.")).toBeNull();
    await userEvent.click(save);
    expect(api.portableArchiveExport).toHaveBeenCalledWith({ secrets: "included" }, "fixture encrypted export", "en");
    expect(input.value).toBe("");
    expect(repeated.value).toBe("");
    expect((save as HTMLButtonElement).disabled).toBe(true);
    await act(async () => resolve?.({ status: "ok", data: null }));
    expect((await within(dialog).findByRole("status")).textContent).toContain("Save cancelled");
    expect((save as HTMLButtonElement).disabled).toBe(true);
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await userEvent.click(screen.getByRole("button", { name: "Export Scoplen backup" }));
    expect((within(await screen.findByRole("dialog")).getByRole("checkbox") as HTMLInputElement).checked).toBe(false);
  });

  it.each(["Cancel", "Close backup review"])("clears both unsubmitted export passphrases on %s", async (button) => {
    const api = setup();
    const dialog = await openExport(api);
    await userEvent.click(within(dialog).getByRole("checkbox"));
    const input = within(dialog).getByLabelText<HTMLInputElement>("Backup passphrase");
    const repeated = within(dialog).getByLabelText<HTMLInputElement>("Repeat passphrase");
    await userEvent.type(input, "fixture export not submitted");
    await userEvent.type(repeated, "fixture export not submitted");
    await userEvent.click(within(dialog).getByRole("button", { name: button }));
    expect(input.value).toBe("");
    expect(repeated.value).toBe("");
    expect(api.portableArchiveExport).not.toHaveBeenCalled();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("submits matching encrypted-export passphrases with the keyboard and shows the native completed result", async () => {
    const api = setup();
    vi.mocked(api.portableArchiveExport).mockResolvedValue({
      status: "ok",
      data: {
        destination: { scope: "personal", ownerId: "export-account", vaultId: "export-vault" },
        objects: 4,
        secrets: "included",
      },
    });
    const dialog = await openExport(api);
    await userEvent.click(within(dialog).getByRole("checkbox"));
    const input = within(dialog).getByLabelText<HTMLInputElement>("Backup passphrase");
    const repeated = within(dialog).getByLabelText<HTMLInputElement>("Repeat passphrase");
    await userEvent.type(input, "fixture matching export");
    await userEvent.type(repeated, "fixture matching export");
    await userEvent.tab();
    await userEvent.tab();
    expect(document.activeElement).toBe(within(dialog).getByRole("button", { name: "Save backup" }));
    await userEvent.keyboard("{Enter}");
    expect(api.portableArchiveExport).toHaveBeenCalledWith({ secrets: "included" }, "fixture matching export", "en");
    expect((await within(dialog).findByRole("status")).textContent).toContain("Exported 4 objects.");
    expect(within(dialog).getByText("Saved as an encrypted age backup with portable secrets included.")).toBeTruthy();
    expect(within(dialog).getByText("export-account")).toBeTruthy();
    expect(input.value).toBe("");
    expect(repeated.value).toBe("");
  });

  it.each([
    "decryption",
    "invalidArchive",
    "unsupportedDestination",
    "destinationExists",
    "io",
  ] satisfies PortableArchiveError[])("shows a localized safe %s refusal", async (error) => {
    const api = setup();
    vi.mocked(api.portableArchivePreview).mockResolvedValue({ status: "error", error });
    show(api, "zh-Hans");
    await userEvent.click(screen.getByRole("button", { name: "导入 Scoplen 备份" }));
    expect(api.portableArchivePreview).toHaveBeenCalledWith(true, null, "zh-Hans");
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(api.portableArchiveImport).not.toHaveBeenCalled();
  });

  it("keeps raw thrown details out of user-facing errors", async () => {
    const api = setup();
    vi.mocked(api.portableArchivePreview).mockRejectedValue(new Error("private fixture path and diagnostic"));
    show(api);
    await userEvent.click(screen.getByRole("button", { name: "Import Scoplen backup" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/could not be read or written completely/);
    expect(screen.queryByText(/private fixture path/)).toBeNull();
  });

  it.each(["en", "zh-Hans"] as const)(
    "refuses plaintext secrets without asking for a useless passphrase in %s",
    async (locale) => {
      const api = setup();
      vi.mocked(api.portableArchivePreview).mockResolvedValue({ status: "error", error: "unencryptedSecrets" });
      show(api, locale);
      await userEvent.click(
        screen.getByRole("button", { name: locale === "en" ? "Import Scoplen backup" : "导入 Scoplen 备份" }),
      );
      expect((await screen.findByRole("alert")).textContent).toBe(
        locale === "en"
          ? "This plaintext file contains secrets. Use the original encrypted age archive; plaintext secret files cannot be imported."
          : "此明文文件包含秘密。请选择原始 age 加密文件，不能导入包含秘密的明文文件。",
      );
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(api.portableArchivePreview).toHaveBeenCalledExactlyOnceWith(true, null, locale);
      expect(api.portableArchiveImport).not.toHaveBeenCalled();
    },
  );

  it("leaves passphrase review when a replacement file contains plaintext secrets", async () => {
    const api = setup();
    vi.mocked(api.portableArchivePreview)
      .mockResolvedValueOnce({ status: "error", error: "passphraseRequired" })
      .mockResolvedValueOnce({ status: "error", error: "unencryptedSecrets" });
    const dialog = await openImport(api);
    expect(within(dialog).getByLabelText("Backup passphrase")).toBeTruthy();
    await userEvent.click(within(dialog).getByRole("button", { name: "Choose another file" }));
    expect((await screen.findByRole("alert")).textContent).toContain("Use the original encrypted age archive");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(api.portableArchiveImport).not.toHaveBeenCalled();
    expect(api.portableArchiveDiscard).toHaveBeenCalled();
  });

  it("requires a fresh review when the import result cannot be confirmed", async () => {
    const api = setup();
    vi.mocked(api.portableArchiveImport).mockRejectedValue(new Error("private native diagnostic"));
    const dialog = await openImport(api);
    const submit = within(dialog).getByRole<HTMLButtonElement>("button", { name: "Import reviewed backup" });
    await userEvent.click(submit);
    expect((await within(dialog).findByRole("alert")).textContent).toContain(
      "The import result could not be confirmed.",
    );
    expect(submit.disabled).toBe(true);
    expect(screen.queryByText(/private native diagnostic/)).toBeNull();
  });

  it("has labelled controls, keyboard cancellation and no automated accessibility violations", async () => {
    const api = setup();
    const dialog = await openImport(api);
    expect(await violations(dialog)).toEqual([]);
    await userEvent.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Import Scoplen backup" }));
  });
});
