// SPDX-License-Identifier: Apache-2.0
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { sampleHosts, sampleInventory } from "../src/gallery/sample-inventory";
import { I18nProvider } from "../src/i18n";
import {
  InventoryContext,
  type InventoryApi,
  type OpenSshExportEntry,
  type OpenSshExportPreview,
} from "../src/inventory/api";
import { SettingsView } from "../src/settings";
import { violations } from "../../ui/test/axe";

const folder = "/home/fixture/Exports/scoplen-openssh-1730000000000";
const keyPath = "/home/fixture/.ssh/production deployment key";
const entry: OpenSshExportEntry = {
  hostId: "h-nas",
  profileId: "l-nas",
  hostName: "Home storage",
  loginName: "admin",
  alias: "scoplen-storage",
  address: "storage.example.test",
  port: 22,
  username: "admin",
  authentication: "password",
  identityFile: null,
  route: { kind: "direct" },
};

function preview(): OpenSshExportPreview {
  return {
    revision: "reviewed-inventory-and-source-files",
    choices: [],
    trustRecords: 2,
    entries: [
      { ...entry },
      {
        ...entry,
        profileId: "l-agent",
        hostId: "h-agent",
        hostName: "Jump server",
        loginName: "operator",
        alias: "scoplen-jump",
        authentication: "agent",
        port: 2222,
      },
      {
        ...entry,
        profileId: "l-deploy",
        hostId: "h-deploy",
        hostName: "Application server",
        loginName: "deploy",
        alias: "scoplen-app",
        authentication: "identityFile",
        identityFile: keyPath,
        route: { kind: "jump", hops: ["scoplen-jump"] },
      },
    ],
    skipped: [
      {
        hostId: "h-db",
        profileId: "l-db",
        hostName: "Database",
        loginName: "maintenance",
        reason: "identityFileRequired",
      },
      {
        hostId: "h-legacy",
        profileId: "l-legacy",
        hostName: "Legacy server",
        loginName: "operator",
        reason: "unsupportedRoute",
      },
      { hostId: "h-empty", profileId: null, hostName: "Unconfigured host", loginName: null, reason: "missingLogin" },
    ],
  };
}

function setup(initial = preview()) {
  const api = sampleInventory(sampleHosts());
  vi.spyOn(api, "previewOpenSshExport").mockResolvedValue({ status: "ok", data: initial });
  vi.spyOn(api, "exportOpenSshConfig").mockResolvedValue({
    status: "ok",
    data: { directory: folder, hosts: initial.entries.length, files: 3 },
  });
  return api;
}

function show(api: InventoryApi, locale: "en" | "zh-Hans" = "en") {
  return render(
    <I18nProvider locale={locale}>
      <InventoryContext.Provider value={api}>
        <SettingsView section="data" status={{ state: "open", protection: "keystore" }} onStatus={() => {}} />
      </InventoryContext.Provider>
    </I18nProvider>,
  );
}

async function open(api: InventoryApi, locale: "en" | "zh-Hans" = "en") {
  show(api, locale);
  await userEvent.click(screen.getByRole("button", { name: locale === "en" ? "Export OpenSSH" : "导出 OpenSSH" }));
  return screen.findByRole("dialog", { name: locale === "en" ? "Review OpenSSH export" : "检查 OpenSSH 导出" });
}

describe("OpenSSH export", () => {
  it("reviews the full scope, authentication, route, key source and every skipped entry before any native save", async () => {
    const api = setup();
    const dialog = await open(api);
    expect(api.previewOpenSshExport).toHaveBeenCalledWith();
    expect(within(dialog).getByText(/entire Personal inventory/)).toBeTruthy();
    expect(within(dialog).getByText(/Passwords and private keys are not copied/)).toBeTruthy();
    expect(within(dialog).getByText("SSH entries: 3 · Skipped: 3 · Trust records: 2")).toBeTruthy();
    expect(within(dialog).getByText("admin@storage.example.test:2222")).toBeTruthy();
    expect(within(dialog).getByText("Jump: scoplen-jump")).toBeTruthy();
    expect(within(dialog).getByText(keyPath)).toBeTruthy();
    expect(within(dialog).getByText(/OpenSSH asks for the password/)).toBeTruthy();
    expect(within(dialog).getByText(/matching key must already be loaded/)).toBeTruthy();
    expect(within(dialog).getByText("Database · maintenance")).toBeTruthy();
    expect(within(dialog).getByText("Legacy server · operator")).toBeTruthy();
    expect(within(dialog).getByText("Unconfigured host")).toBeTruthy();
    expect(api.exportOpenSshConfig).not.toHaveBeenCalled();
    expect(document.activeElement?.textContent).toBe("Cancel");
    expect(await violations(document.body)).toEqual([]);
  });

  it("offers full-inventory export from Data settings without loading or filtering Hosts", async () => {
    const api = setup();
    const hosts = vi.spyOn(api, "hosts");
    show(api);
    expect(screen.getByRole("tab", { name: "Data" }).getAttribute("aria-selected")).toBe("true");
    await userEvent.click(screen.getByRole("button", { name: "Export OpenSSH" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("SSH entries: 3 · Skipped: 3 · Trust records: 2")).toBeTruthy();
    expect(api.previewOpenSshExport).toHaveBeenCalledWith();
    expect(hosts).not.toHaveBeenCalled();
  });

  it("cancels the review without opening a destination or writing", async () => {
    const api = setup();
    const dialog = await open(api);
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(api.exportOpenSshConfig).not.toHaveBeenCalled();
  });

  it("retains the preview after native folder cancellation and writes only on another explicit save", async () => {
    const api = setup();
    vi.mocked(api.exportOpenSshConfig).mockResolvedValueOnce({ status: "ok", data: null });
    const dialog = await open(api);
    const save = within(dialog).getByRole("button", { name: "Choose folder and export…" });
    await userEvent.click(save);
    expect(await within(dialog).findByText(/Folder selection cancelled/)).toBeTruthy();
    expect(api.exportOpenSshConfig).toHaveBeenCalledTimes(1);
    expect(api.exportOpenSshConfig).toHaveBeenCalledWith(preview(), "en");
    await userEvent.click(save);
    expect(await within(dialog).findByText("Exported 3 SSH entries in 3 files.")).toBeTruthy();
    expect(within(dialog).getByText(folder)).toBeTruthy();
    expect(within(dialog).getByText(`Config file: ${folder}/config`)).toBeTruthy();
    expect(within(dialog).getByText("ssh -F <config> scoplen-storage")).toBeTruthy();
    expect(document.activeElement?.textContent).toContain("Exported 3 SSH entries");
    expect(within(dialog).getByText("Legacy server · operator")).toBeTruthy();
    expect(api.exportOpenSshConfig).toHaveBeenCalledTimes(2);
    await userEvent.click(within(dialog).getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("chooses a matching external key and saves the recomputed native preview", async () => {
    const api = setup();
    const choose = vi.spyOn(api, "chooseKeyFile").mockResolvedValue(keyPath);
    vi.mocked(api.previewOpenSshExport).mockImplementation(async (choices = []) => {
      const next = preview();
      next.choices = choices;
      if (choices.length) {
        next.entries.push({
          ...entry,
          hostId: "h-db",
          profileId: "l-db",
          alias: "scoplen-db",
          hostName: "Database",
          loginName: "maintenance",
          authentication: "identityFile",
          identityFile: choices[0]!.identityFile,
        });
        next.skipped = next.skipped.filter((row) => row.profileId !== "l-db");
        next.revision = "refreshed-key-source";
      }
      return { status: "ok", data: next };
    });
    const dialog = await open(api);
    await userEvent.click(within(dialog).getByRole("button", { name: "Choose matching key for maintenance…" }));
    await within(dialog).findByText("SSH entries: 4 · Skipped: 2 · Trust records: 2");
    expect(document.activeElement?.textContent).toBe("Refresh preview");
    expect(choose).toHaveBeenCalledTimes(1);
    expect(api.previewOpenSshExport).toHaveBeenLastCalledWith([{ profileId: "l-db", identityFile: keyPath }]);
    await userEvent.click(within(dialog).getByRole("button", { name: "Choose folder and export…" }));
    expect(api.exportOpenSshConfig).toHaveBeenCalledWith(
      expect.objectContaining({
        revision: "refreshed-key-source",
        choices: [{ profileId: "l-db", identityFile: keyPath }],
        entries: expect.arrayContaining([expect.objectContaining({ profileId: "l-db", identityFile: keyPath })]),
      }),
      "en",
    );
  });

  it("keeps a mismatching key visible in the complete skip report and lets the user replace it", async () => {
    const api = setup();
    vi.spyOn(api, "chooseKeyFile").mockResolvedValue(keyPath);
    vi.mocked(api.previewOpenSshExport).mockImplementation(async (choices = []) => {
      const next = preview();
      next.choices = choices;
      if (choices.length) next.skipped[0]!.reason = "identityFileMismatch";
      return { status: "ok", data: next };
    });
    const dialog = await open(api);
    await userEvent.click(within(dialog).getByRole("button", { name: "Choose matching key for maintenance…" }));
    expect(await within(dialog).findByText(/The selected file does not match/)).toBeTruthy();
    expect(within(dialog).getAllByText(keyPath)).toHaveLength(2);
    expect(within(dialog).getByRole("button", { name: "Choose matching key for maintenance…" })).toBeTruthy();
    expect(api.exportOpenSshConfig).not.toHaveBeenCalled();
  });

  it("leaves an unchanged preview available when the identity picker is cancelled", async () => {
    const api = setup();
    vi.spyOn(api, "chooseKeyFile").mockResolvedValue(null);
    const dialog = await open(api);
    await userEvent.click(within(dialog).getByRole("button", { name: "Choose matching key for maintenance…" }));
    await waitFor(() =>
      expect(within(dialog).getByRole("button", { name: "Choose folder and export…" }).hasAttribute("disabled")).toBe(
        false,
      ),
    );
    expect(api.previewOpenSshExport).toHaveBeenCalledTimes(1);
  });

  it.each(["inventoryChanged", "sourceChanged"] as const)("requires a fresh preview after %s", async (kind) => {
    const api = setup();
    vi.mocked(api.exportOpenSshConfig).mockResolvedValueOnce({ status: "error", error: { kind } });
    const dialog = await open(api);
    const save = within(dialog).getByRole("button", { name: "Choose folder and export…" });
    await userEvent.click(save);
    expect(await within(dialog).findByRole("alert")).toBeTruthy();
    expect(save.hasAttribute("disabled")).toBe(true);
    expect(api.exportOpenSshConfig).toHaveBeenCalledTimes(1);
    await userEvent.click(within(dialog).getByRole("button", { name: "Refresh preview" }));
    await waitFor(() => expect(save.hasAttribute("disabled")).toBe(false));
    expect(api.previewOpenSshExport).toHaveBeenCalledTimes(2);
  });

  it("shows a retained partial directory without treating it as a successful export", async () => {
    const api = setup();
    vi.mocked(api.exportOpenSshConfig).mockResolvedValue({
      status: "error",
      error: { kind: "writeFailed", directory: folder },
    });
    const dialog = await open(api);
    await userEvent.click(within(dialog).getByRole("button", { name: "Choose folder and export…" }));
    expect(await within(dialog).findByRole("alert")).toHaveProperty("textContent", expect.stringContaining(folder));
    expect(within(dialog).getByRole("alert").textContent).toContain("incomplete folder could not be removed");
    expect(within(dialog).queryByText(/Exported 3 SSH entries/)).toBeNull();
  });

  it("does not claim a response failure left the destination unchanged", async () => {
    const api = setup();
    vi.mocked(api.exportOpenSshConfig).mockRejectedValue(new Error("response unavailable"));
    const dialog = await open(api);
    await userEvent.click(within(dialog).getByRole("button", { name: "Choose folder and export…" }));
    expect(await within(dialog).findByRole("alert")).toHaveProperty(
      "textContent",
      expect.stringContaining("Check your selected parent folder"),
    );
    expect(within(dialog).getByRole("button", { name: "Choose folder and export…" }).hasAttribute("disabled")).toBe(
      true,
    );
    expect(api.exportOpenSshConfig).toHaveBeenCalledTimes(1);
  });

  it("shows the full report when nothing is exportable and does not allow an empty save", async () => {
    const initial = preview();
    initial.entries = [];
    initial.trustRecords = 0;
    const api = setup(initial);
    const dialog = await open(api);
    expect(within(dialog).getByText(/No SSH entries can be exported yet/)).toBeTruthy();
    expect(within(dialog).getByText("Legacy server · operator")).toBeTruthy();
    expect(within(dialog).getByRole("button", { name: "Choose folder and export…" }).hasAttribute("disabled")).toBe(
      true,
    );
    expect(api.exportOpenSshConfig).not.toHaveBeenCalled();
  });

  it("renders Chinese and passes its language to the native destination picker", async () => {
    const api = setup();
    const dialog = await open(api, "zh-Hans");
    expect(within(dialog).getByText(/完整个人清单/)).toBeTruthy();
    await userEvent.click(within(dialog).getByRole("button", { name: "选择目录并导出…" }));
    expect(await within(dialog).findByText("已将 3 个 SSH 条目导出到 3 个文件。")).toBeTruthy();
    expect(api.exportOpenSshConfig).toHaveBeenCalledWith(preview(), "zh-Hans");
  });

  it("reports initial preview failure without opening an export dialog", async () => {
    const api = setup();
    vi.mocked(api.previewOpenSshExport).mockRejectedValue(new Error("unavailable"));
    show(api);
    await userEvent.click(screen.getByRole("button", { name: "Export OpenSSH" }));
    expect(await screen.findByText(/The export preview could not be prepared/)).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(api.exportOpenSshConfig).not.toHaveBeenCalled();
  });
});
