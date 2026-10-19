// SPDX-License-Identifier: Apache-2.0
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { sampleHosts, sampleInventory } from "../src/gallery/sample-inventory";
import { I18nProvider } from "../src/i18n";
import { InventoryContext, type InventoryApi, type RouteInput } from "../src/inventory/api";
import { InventoryObjects, type ObjectSection } from "../src/inventory/objects";
import { violations } from "../../ui/test/axe";

function show(api: InventoryApi, section: ObjectSection = "logins") {
  return render(
    <I18nProvider locale="en">
      <InventoryContext.Provider value={api}>
        <InventoryObjects section={section} onBack={() => undefined} />
      </InventoryContext.Provider>
    </I18nProvider>,
  );
}

describe("independent inventory objects", () => {
  it("lists access profiles and keeps the screen accessible", async () => {
    const { container } = show(sampleInventory(sampleHosts()));
    expect((await screen.findAllByText("deploy@prod-api-01")).length).toBeGreaterThan(0);
    expect(screen.getByRole("tab", { name: "Keys" })).toBeTruthy();
    expect(screen.getByRole("tab", { name: "Routes" })).toBeTruthy();
    expect(await violations(container)).toEqual([]);
  });

  it("shows empty and failed states for each independent object list", async () => {
    const api = sampleInventory([]);
    api.accessProfiles = async () => ({ status: "ok", data: [] });
    api.credentials = async () => ({ status: "ok", data: [] });
    api.routes = async () => ({ status: "ok", data: [] });
    const { unmount } = show(api);
    expect(await screen.findByText("No saved logins yet. Add one when a host needs another account.")).toBeTruthy();
    unmount();

    const failed = sampleInventory(sampleHosts());
    failed.credentials = async () => ({
      status: "error",
      error: { kind: "failed", reference: "credential store unavailable" },
    });
    show(failed, "keys");
    expect((await screen.findByRole("alert")).textContent).toContain("credential store unavailable");
  });

  it("writes credential secrets without putting them in the rendered DTO", async () => {
    const api = sampleInventory(sampleHosts());
    show(api, "keys");
    expect(await screen.findByText("laptop")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Add key" }));
    const dialog = await screen.findByRole("dialog", { name: "New key" });
    await userEvent.type(within(dialog).getByLabelText("Name"), "one-time deploy");
    await userEvent.type(within(dialog).getByLabelText("Secret material"), "never-render-this-secret");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save changes" }));
    expect(await screen.findByText("one-time deploy")).toBeTruthy();
    expect(screen.queryByText("never-render-this-secret")).toBeNull();
    expect(screen.getAllByText(/Secret stored/).length).toBeGreaterThan(0);
  });

  it("offers unresolved device-key binding without a pasteable secret field", async () => {
    const api = sampleInventory(sampleHosts());
    show(api, "keys");
    await screen.findByText("laptop");
    await userEvent.click(screen.getByRole("button", { name: "Add key" }));
    const dialog = await screen.findByRole("dialog", { name: "New key" });
    await userEvent.selectOptions(within(dialog).getByLabelText("Kind"), "deviceKey");

    const binding = within(dialog).getByLabelText("Storage");
    expect(within(binding).getByRole("option", { name: "This device only" })).toBeTruthy();
    expect(within(binding).getByRole("option", { name: "Resolved at connect time" })).toBeTruthy();
    expect(within(dialog).queryByLabelText("Device-only material")).toBeNull();
    await userEvent.selectOptions(binding, "none");
    await userEvent.type(within(dialog).getByLabelText("Name"), "platform key");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save changes" }));
    expect(await screen.findByText("platform key")).toBeTruthy();
  });

  it("keeps an in-use route and managed routes read-only", async () => {
    const api = sampleInventory(sampleHosts());
    show(api, "routes");
    expect(await screen.findByText("prod-jump")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Delete prod-jump" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Delete prod-jump?" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete prod-jump" }));
    expect((await within(dialog).findByRole("alert")).textContent).toContain("Remove the references");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.getByText("staging-net")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Edit staging-net" }).hasAttribute("disabled")).toBe(true);
    expect(screen.getByRole("button", { name: "Delete staging-net" }).hasAttribute("disabled")).toBe(true);
  });

  it("edits a proxy username with only password credentials and clears the pair", async () => {
    const api = sampleInventory(sampleHosts());
    const create = api.createRoute;
    const update = api.updateRoute;
    const created: RouteInput[] = [];
    const updated: RouteInput[] = [];
    api.createRoute = (input) => {
      created.push(input);
      return create(input);
    };
    api.updateRoute = (id, input) => {
      updated.push(input);
      return update(id, input);
    };
    show(api, "routes");
    await screen.findByText("prod-jump");
    await userEvent.click(screen.getByRole("button", { name: "Add route" }));
    const dialog = await screen.findByRole("dialog", { name: "New route" });
    await userEvent.type(within(dialog).getByLabelText("Name"), "office proxy");
    await userEvent.selectOptions(within(dialog).getByLabelText("Kind"), "httpConnect");
    await userEvent.type(within(dialog).getByLabelText("Proxy endpoint"), "proxy.example:8080");
    const credential = within(dialog).getByLabelText("Proxy credential");
    expect(
      within(credential)
        .getAllByRole("option")
        .map((option) => (option as HTMLOptionElement).value),
    ).toEqual(["", "c-nas"]);
    await userEvent.selectOptions(credential, "c-nas");
    expect(within(dialog).getByText(/plain TCP/)).toBeTruthy();
    await userEvent.type(within(dialog).getByLabelText("Proxy username"), "proxy-user");
    expect(await violations(dialog)).toEqual([]);
    await userEvent.click(within(dialog).getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(created).toHaveLength(1));
    expect(created[0]?.definition).toEqual({
      kind: "httpConnect",
      proxy: "proxy.example:8080",
      credential: "c-nas",
      username: "proxy-user",
    });
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "New route" })).toBeNull());
    await userEvent.click(screen.getByRole("button", { name: "Edit office proxy" }));
    const edit = await screen.findByRole("dialog", { name: "Edit office proxy" });
    expect((within(edit).getByLabelText("Proxy username") as HTMLInputElement).value).toBe("proxy-user");
    await userEvent.selectOptions(within(edit).getByLabelText("Proxy credential"), "");
    expect(within(edit).queryByLabelText("Proxy username")).toBeNull();
    await userEvent.click(within(edit).getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(updated).toHaveLength(1));
    expect(updated[0]?.definition).toEqual({
      kind: "httpConnect",
      proxy: "proxy.example:8080",
      credential: null,
      username: null,
    });
  });

  it("presents orphaned logins with restore and delete actions", async () => {
    const api = sampleInventory(sampleHosts());
    const accessProfiles = api.accessProfiles;
    let holdReload = false;
    let releaseReload!: () => void;
    const reload = new Promise<void>((resolve) => {
      releaseReload = resolve;
    });
    api.accessProfiles = async () => {
      const result = await accessProfiles();
      if (holdReload) await reload;
      return result;
    };
    await api.deleteHost("h-api-1");
    show(api, "logins");
    expect(await screen.findByRole("heading", { name: "Orphaned items" })).toBeTruthy();
    expect(screen.getAllByText(/Host no longer available/).length).toBeGreaterThan(0);
    const restore = screen.getAllByRole("button", { name: "Restore reference" })[0]!;
    holdReload = true;
    await userEvent.click(restore);
    expect(await screen.findByText("Referenced object restored")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Orphaned items" })).toBeTruthy();
    releaseReload();
    await waitFor(() => expect(screen.queryByRole("heading", { name: "Orphaned items" })).toBeNull());
    expect((await screen.findAllByText("deploy@prod-api-01")).length).toBeGreaterThan(0);
  });

  it("edits the tunnels attached to a login and preserves the selection", async () => {
    const api = sampleInventory(sampleHosts());
    show(api, "logins");
    expect((await screen.findAllByText("dba@prod-db-01")).length).toBeGreaterThan(0);
    await userEvent.click(screen.getByRole("button", { name: "Edit dba@prod-db-01" }));
    const dialog = await screen.findByRole("dialog", { name: "Edit dba" });
    const postgres = within(dialog).getByRole("checkbox", { name: /postgres-prod/ });
    const socks = within(dialog).getByRole("checkbox", { name: /staging-socks/ });
    expect((postgres as HTMLInputElement).checked).toBe(true);
    expect((socks as HTMLInputElement).checked).toBe(false);
    await userEvent.click(postgres);
    await userEvent.click(socks);
    await userEvent.click(within(dialog).getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    await userEvent.click(screen.getByRole("button", { name: "Edit dba@prod-db-01" }));
    const reopened = await screen.findByRole("dialog", { name: "Edit dba" });
    expect((within(reopened).getByRole("checkbox", { name: /postgres-prod/ }) as HTMLInputElement).checked).toBe(false);
    expect((within(reopened).getByRole("checkbox", { name: /staging-socks/ }) as HTMLInputElement).checked).toBe(true);
  });

  it("keeps profile editing blocked when tunnel inventory cannot be loaded", async () => {
    const api = sampleInventory(sampleHosts());
    api.forwards = async () => ({
      status: "error",
      error: { kind: "failed", reference: "forward store unavailable" },
    });
    show(api, "logins");
    expect((await screen.findAllByText("dba@prod-db-01")).length).toBeGreaterThan(0);
    await userEvent.click(screen.getByRole("button", { name: "Edit dba@prod-db-01" }));
    const dialog = await screen.findByRole("dialog", { name: "Edit dba" });
    expect((await within(dialog).findByRole("alert")).textContent).toContain("forward store unavailable");
    expect(within(dialog).getByRole("button", { name: "Save changes" }).hasAttribute("disabled")).toBe(true);
  });
});
