// SPDX-License-Identifier: Apache-2.0
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { sampleInventory } from "../src/gallery/sample-inventory";
import { I18nProvider } from "../src/i18n";
import {
  InventoryContext,
  type InventoryApi,
  type OpenSshGeneratedPreview,
  type OpenSshGeneratedStatus,
} from "../src/inventory/api";
import { GeneratedConfigSettings } from "../src/inventory/generated-config";
import { violations } from "../../ui/test/axe";

const status: OpenSshGeneratedStatus = {
  destination: { scope: "local" },
  includePath: "/home/fixture/App data/openssh/local/active.conf",
  includeLine: 'Include "/home/fixture/App data/openssh/local/active.conf"',
  active: true,
};

function preview(id = "native-review-id"): OpenSshGeneratedPreview {
  return {
    id,
    destination: { scope: "local" },
    report: {
      revision: "native-source-revision",
      choices: [],
      trustRecords: 1,
      entries: [
        {
          hostId: "host-api",
          profileId: "login-api",
          alias: "scoplen-login-api",
          hostName: "prod-api",
          loginName: "deploy",
          address: "api.example.test",
          port: 22,
          username: "deploy",
          authentication: "password",
          identityFile: null,
          route: { kind: "direct" },
        },
      ],
      skipped: [
        {
          hostId: "host-db",
          profileId: "login-db",
          hostName: "Database",
          loginName: "admin",
          reason: "identityFileRequired",
        },
      ],
    },
    aliases: [
      { hostId: "host-api", hostName: "prod-api", profileId: "login-api", alias: "prod-api", problem: null },
      { hostId: "host-db", hostName: "Database", profileId: "login-db", alias: null, problem: "incompatibleLogin" },
      { hostId: "host-collision", hostName: "shared-name", profileId: null, alias: null, problem: "duplicateName" },
    ],
  };
}

function setup(initial = preview()) {
  const api = sampleInventory([]);
  vi.spyOn(api, "generatedOpenSshStatus").mockResolvedValue({ status: "ok", data: status });
  vi.spyOn(api, "generatedOpenSshPreview").mockResolvedValue({ status: "ok", data: initial });
  vi.spyOn(api, "generatedOpenSshGenerate").mockResolvedValue({
    status: "ok",
    data: { status, hosts: initial.report.entries.length, files: 3 },
  });
  vi.spyOn(api, "generatedOpenSshClear").mockResolvedValue({ status: "ok", data: { ...status, active: false } });
  vi.spyOn(api, "generatedOpenSshDiscard");
  return api;
}

function show(api: InventoryApi, locale: "en" | "zh-Hans" = "en") {
  return render(
    <I18nProvider locale={locale}>
      <InventoryContext.Provider value={api}>
        <GeneratedConfigSettings />
      </InventoryContext.Provider>
    </I18nProvider>,
  );
}

async function open(api: InventoryApi) {
  show(api);
  await userEvent.click(screen.getByRole("button", { name: "Manage OpenSSH config" }));
  return screen.findByRole("dialog", { name: "Review generated OpenSSH config" });
}

it("loads only after an explicit action and reviews the native Include, aliases and external authentication", async () => {
  const api = setup();
  show(api);
  expect(api.generatedOpenSshStatus).not.toHaveBeenCalled();
  expect(api.generatedOpenSshPreview).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Manage OpenSSH config" }));
  const dialog = await screen.findByRole("dialog", { name: "Review generated OpenSSH config" });
  expect(within(dialog).getByText(status.includeLine)).toBeTruthy();
  expect(within(dialog).getByText("ssh prod-api")).toBeTruthy();
  expect(within(dialog).getByText(/default Login cannot be exported/)).toBeTruthy();
  expect(within(dialog).getByText(/name is shared by more than one Host/)).toBeTruthy();
  expect(within(dialog).getByText(/OpenSSH asks for the password/)).toBeTruthy();
  expect(within(dialog).getByText("scoplen-login-api")).toBeTruthy();
  expect(api.generatedOpenSshGenerate).not.toHaveBeenCalled();
  expect(await violations(dialog)).toEqual([]);
});

it("refreshes a matching external key choice through Rust and generates only the returned opaque receipt", async () => {
  const api = setup();
  const selected = preview("review-after-key-selection");
  const choices = [{ profileId: "login-db", identityFile: "/home/fixture/.ssh/deployment key" }];
  selected.report.choices = choices;
  vi.spyOn(api, "chooseKeyFile").mockResolvedValue(choices[0]!.identityFile);
  vi.mocked(api.generatedOpenSshPreview)
    .mockResolvedValueOnce({ status: "ok", data: preview() })
    .mockResolvedValue({ status: "ok", data: selected });
  const dialog = await open(api);
  await userEvent.click(within(dialog).getByRole("button", { name: /Choose matching key for admin/ }));
  await waitFor(() => expect(api.generatedOpenSshPreview).toHaveBeenLastCalledWith(choices));
  await userEvent.click(within(dialog).getByRole("button", { name: "Regenerate configuration" }));
  await waitFor(() => expect(api.generatedOpenSshGenerate).toHaveBeenCalledWith("review-after-key-selection"));
  expect(await within(dialog).findByText("Configuration generated for 1 Login.")).toBeTruthy();
  expect(within(dialog).getByText(status.includeLine)).toBeTruthy();
  await userEvent.click(within(dialog).getByRole("button", { name: "Done" }));
  await waitFor(() =>
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Manage OpenSSH config" })),
  );
  expect(api.generatedOpenSshDiscard).toHaveBeenCalledOnce();
});

it("requires a fresh preview after a rejected publication and uses the new receipt", async () => {
  const api = setup();
  vi.mocked(api.generatedOpenSshGenerate).mockResolvedValueOnce({ status: "error", error: { kind: "targetChanged" } });
  const dialog = await open(api);
  await userEvent.click(within(dialog).getByRole("button", { name: "Regenerate configuration" }));
  expect((await within(dialog).findByRole("alert")).textContent).toContain("The generated files changed");
  expect(within(dialog).getByRole("button", { name: "Regenerate configuration" }).hasAttribute("disabled")).toBe(true);
  vi.mocked(api.generatedOpenSshPreview).mockResolvedValue({ status: "ok", data: preview("fresh-native-review") });
  await userEvent.click(within(dialog).getByRole("button", { name: "Refresh preview" }));
  await waitFor(() =>
    expect(within(dialog).getByRole("button", { name: "Regenerate configuration" }).hasAttribute("disabled")).toBe(
      false,
    ),
  );
  await userEvent.click(within(dialog).getByRole("button", { name: "Regenerate configuration" }));
  await waitFor(() => expect(api.generatedOpenSshGenerate).toHaveBeenLastCalledWith("fresh-native-review"));
});

it("allows an empty inventory to replace stale generated entries", async () => {
  const empty = preview();
  empty.report.entries = [];
  empty.report.skipped = [];
  empty.aliases = [];
  const api = setup(empty);
  const dialog = await open(api);
  expect(
    within(dialog).getByText(/Generating replaces this inventory's previous entries with an empty configuration/),
  ).toBeTruthy();
  expect(within(dialog).getByRole("button", { name: "Regenerate configuration" }).hasAttribute("disabled")).toBe(false);
  await userEvent.click(within(dialog).getByRole("button", { name: "Regenerate configuration" }));
  expect(await within(dialog).findByText("Configuration generated for 0 Logins.")).toBeTruthy();
});

it("recovers Refresh after a selected Login is removed by discarding invalid external key choices", async () => {
  const api = setup();
  const selected = preview("selected-key-review");
  selected.report.choices = [{ profileId: "login-db", identityFile: "/home/fixture/.ssh/deployment" }];
  vi.spyOn(api, "chooseKeyFile").mockResolvedValue(selected.report.choices[0]!.identityFile);
  vi.mocked(api.generatedOpenSshPreview)
    .mockResolvedValueOnce({ status: "ok", data: preview() })
    .mockResolvedValueOnce({ status: "ok", data: selected })
    .mockResolvedValueOnce({ status: "error", error: { kind: "invalidSelection" } })
    .mockResolvedValue({ status: "ok", data: preview("review-without-deleted-login") });
  vi.mocked(api.generatedOpenSshGenerate).mockResolvedValueOnce({
    status: "error",
    error: { kind: "inventoryChanged" },
  });
  const dialog = await open(api);
  await userEvent.click(within(dialog).getByRole("button", { name: /Choose matching key for admin/ }));
  await waitFor(() => expect(api.generatedOpenSshPreview).toHaveBeenLastCalledWith(selected.report.choices));
  await userEvent.click(within(dialog).getByRole("button", { name: "Regenerate configuration" }));
  await within(dialog).findByRole("alert");
  await userEvent.click(within(dialog).getByRole("button", { name: "Refresh preview" }));
  await waitFor(() => expect(api.generatedOpenSshPreview).toHaveBeenLastCalledWith());
  await waitFor(() =>
    expect(within(dialog).getByRole("button", { name: "Regenerate configuration" }).hasAttribute("disabled")).toBe(
      false,
    ),
  );
  await userEvent.click(within(dialog).getByRole("button", { name: "Regenerate configuration" }));
  await waitFor(() => expect(api.generatedOpenSshGenerate).toHaveBeenLastCalledWith("review-without-deleted-login"));
});

it("confirms Clear separately and publishes only the native cleared result", async () => {
  const api = setup();
  const dialog = await open(api);
  await userEvent.click(within(dialog).getByRole("button", { name: "Clear generated configuration" }));
  const confirmation = screen.getByRole("dialog", { name: "Clear generated OpenSSH config?" });
  expect(api.generatedOpenSshClear).not.toHaveBeenCalled();
  expect(within(confirmation).getByText(/saved hosts, credentials and own SSH config are kept/)).toBeTruthy();
  await userEvent.click(within(confirmation).getByRole("button", { name: "Cancel" }));
  expect(api.generatedOpenSshClear).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Clear generated configuration" }));
  await userEvent.click(screen.getByRole("button", { name: "Clear generated configuration" }));
  expect(
    await screen.findByText("Generated connection entries cleared. The Include file remains valid and empty."),
  ).toBeTruthy();
  expect(api.generatedOpenSshClear).toHaveBeenCalledOnce();
  expect(api.generatedOpenSshGenerate).not.toHaveBeenCalled();
});

it("refreshes the cleared Include after retained-file cleanup fails without claiming complete cleanup", async () => {
  const api = setup();
  vi.mocked(api.generatedOpenSshStatus)
    .mockResolvedValueOnce({ status: "ok", data: status })
    .mockResolvedValue({ status: "ok", data: { ...status, active: false } });
  vi.mocked(api.generatedOpenSshClear).mockResolvedValue({
    status: "error",
    error: { kind: "clearFailed", directory: "/home/fixture/generated" },
  });
  const dialog = await open(api);
  await userEvent.click(within(dialog).getByRole("button", { name: "Clear generated configuration" }));
  await userEvent.click(screen.getByRole("button", { name: "Clear generated configuration" }));
  expect((await screen.findByRole("alert")).textContent).toContain("/home/fixture/generated");
  expect(screen.queryByText(/Generated connection entries cleared/)).toBeNull();
  await waitFor(() => expect(api.generatedOpenSshStatus).toHaveBeenCalledTimes(2));
  expect(screen.getByRole("button", { name: "Generate configuration" }).hasAttribute("disabled")).toBe(true);
  await userEvent.click(screen.getByRole("button", { name: "Refresh preview" }));
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Generate configuration" }).hasAttribute("disabled")).toBe(false),
  );
});

it("keeps the review open and prevents other actions while publishing", async () => {
  const api = setup();
  let finish!: (value: Awaited<ReturnType<InventoryApi["generatedOpenSshGenerate"]>>) => void;
  vi.mocked(api.generatedOpenSshGenerate).mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const dialog = await open(api);
  await userEvent.click(within(dialog).getByRole("button", { name: "Regenerate configuration" }));
  expect(within(dialog).getByRole("button", { name: "Cancel" }).hasAttribute("disabled")).toBe(true);
  expect(within(dialog).getByRole("button", { name: "Clear generated configuration" }).hasAttribute("disabled")).toBe(
    true,
  );
  await userEvent.keyboard("{Escape}");
  expect(screen.getByRole("dialog")).toBeTruthy();
  finish({ status: "ok", data: { status, hosts: 1, files: 3 } });
  expect(await within(dialog).findByText("Configuration generated for 1 Login.")).toBeTruthy();
});

it("does not prepare or mutate after a native status error", async () => {
  const api = setup();
  vi.mocked(api.generatedOpenSshStatus).mockResolvedValue({ status: "error", error: { kind: "contextChanged" } });
  show(api);
  await userEvent.click(screen.getByRole("button", { name: "Manage OpenSSH config" }));
  expect((await screen.findByRole("alert")).textContent).toContain("The active profile changed");
  expect(api.generatedOpenSshPreview).not.toHaveBeenCalled();
  expect(screen.queryByRole("dialog")).toBeNull();
});

it("uses the localized interface and native Personal destination", async () => {
  const api = setup();
  vi.mocked(api.generatedOpenSshStatus).mockResolvedValue({
    status: "ok",
    data: { ...status, active: false, destination: { scope: "personal", ownerId: "account", vaultId: "vault" } },
  });
  show(api, "zh-Hans");
  await userEvent.click(screen.getByRole("button", { name: "管理 OpenSSH 配置" }));
  const dialog = await screen.findByRole("dialog", { name: "检查生成的 OpenSSH 配置" });
  expect(within(dialog).getByRole("button", { name: "生成配置" })).toBeTruthy();
  expect(within(dialog).getByText("目标位置：个人库")).toBeTruthy();
  expect(await violations(dialog)).toEqual([]);
});
