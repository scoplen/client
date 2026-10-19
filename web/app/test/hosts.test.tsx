// SPDX-License-Identifier: Apache-2.0
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { sampleHosts, sampleInventory } from "../src/gallery/sample-inventory";
import { I18nProvider } from "../src/i18n";
import { InventoryContext, type InventoryApi } from "../src/inventory/api";
import { HostsHome } from "../src/inventory/home";
import { violations } from "../../ui/test/axe";

function show(
  api: InventoryApi,
  locale: "en" | "zh-Hans" = "en",
  onConnect?: (profileId: string, label: string) => void,
) {
  return render(
    <I18nProvider locale={locale}>
      <InventoryContext.Provider value={api}>
        <HostsHome onConnect={onConnect} />
      </InventoryContext.Provider>
    </I18nProvider>,
  );
}

const list = () => screen.getByRole("list", { name: "Hosts" });
const names = () =>
  within(list())
    .getAllByRole("button", { name: /^(?!Add|Remove)/ })
    .map((b) => b.textContent);

describe("the host list", () => {
  it("lists hosts with favorites first and shows the count", async () => {
    const { container } = show(sampleInventory(sampleHosts()));
    expect(await screen.findByText("7 hosts")).toBeTruthy();
    const rows = names();
    expect(rows[0]).toContain("prod-api-01");
    expect(rows[1]).toContain("prod-db-01");
    expect(screen.getByText("dba@10.0.4.12")).toBeTruthy();
    expect(screen.getByText("· Through prod-jump")).toBeTruthy();
    expect(screen.getByText("mia@jump.example.com:2222")).toBeTruthy();
    expect(await violations(container)).toEqual([]);
  });

  it("searches by name, address, user, and tag, and explains no match", async () => {
    show(sampleInventory(sampleHosts()));
    await screen.findByText("7 hosts");
    const search = screen.getByRole("searchbox", { name: "Search hosts" });
    await userEvent.type(search, "role:queue");
    await waitFor(() => expect(names()).toHaveLength(1));
    expect(names()[0]).toContain("staging-worker-03");
    await userEvent.clear(search);
    await userEvent.type(search, "nothing-like-this");
    expect(await screen.findByText("No hosts match “nothing-like-this”.")).toBeTruthy();
    // The field's own clear button and the one in the message both work; use the message's.
    const clear = screen.getAllByRole("button", { name: "Clear search" });
    await userEvent.click(clear[clear.length - 1]!);
    expect(await screen.findByText("7 hosts")).toBeTruthy();
  });

  it("filters by sidebar sources, including nested groups", async () => {
    show(sampleInventory(sampleHosts()));
    await screen.findByText("7 hosts");
    const sidebar = screen.getByRole("navigation", { name: "Hosts" });
    await userEvent.click(within(sidebar).getByRole("button", { name: "Databases" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Databases" })).toBeTruthy();
    await waitFor(() => expect(names()).toHaveLength(1));
    expect(within(sidebar).getByRole("button", { name: "Databases" }).getAttribute("aria-current")).toBe("page");
  });

  it("shows redacted recent session history and keeps it separate from host loading", async () => {
    const onConnect = vi.fn();
    const { unmount } = show(sampleInventory(sampleHosts()), "en", onConnect);
    await screen.findByText("7 hosts");
    const sidebar = screen.getByRole("navigation", { name: "Hosts" });
    const recent = within(sidebar).getByRole("button", { name: "Recent" });
    recent.focus();
    await userEvent.keyboard("{Enter}");
    expect(recent.getAttribute("aria-current")).toBe("page");
    expect(await screen.findByRole("heading", { level: 2, name: "Recent sessions" })).toBeTruthy();
    expect(screen.getByRole("list", { name: "Recent sessions" })).toBeTruthy();
    expect(screen.getByRole("button", { name: /prod-api-01.*Terminal/i })).toBeTruthy();
    expect(screen.getByRole("button", { name: /prod-db-01.*Files/i })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Reconnect prod-db-01" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Reconnect prod-api-01" }));
    await waitFor(() => expect(onConnect).toHaveBeenCalledWith("l-1", "prod-api-01 · deploy"));

    unmount();
    show(sampleInventory(sampleHosts(), { failRecentSessions: true }));
    await screen.findByText("7 hosts");
    await userEvent.click(
      within(screen.getByRole("navigation", { name: "Hosts" })).getByRole("button", { name: "Recent" }),
    );
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("local session history is unavailable");
    expect(await screen.findByText("2 hosts")).toBeTruthy();
  });

  it("does not offer reconnect without a connection owner and keeps lookup failures local", async () => {
    const api = sampleInventory(sampleHosts());
    const { unmount } = show(api);
    await screen.findByText("7 hosts");
    await userEvent.click(
      within(screen.getByRole("navigation", { name: "Hosts" })).getByRole("button", { name: "Recent" }),
    );
    expect(screen.queryByRole("button", { name: "Reconnect prod-api-01" })).toBeNull();
    unmount();

    const onConnect = vi.fn();
    api.reconnectSession = vi.fn().mockResolvedValue({ status: "error", error: { kind: "profileNotFound" } });
    show(api, "en", onConnect);
    await screen.findByText("7 hosts");
    await userEvent.click(
      within(screen.getByRole("navigation", { name: "Hosts" })).getByRole("button", { name: "Recent" }),
    );
    await userEvent.click(screen.getByRole("button", { name: "Reconnect prod-api-01" }));
    expect(await screen.findByText("This session could not be reconnected.")).toBeTruthy();
    expect(onConnect).not.toHaveBeenCalled();
  });

  it("stars and unstars a host", async () => {
    show(sampleInventory(sampleHosts()));
    await screen.findByText("7 hosts");
    await userEvent.click(screen.getByRole("button", { name: "Add nas to favorites" }));
    const star = await screen.findByRole("button", { name: "Remove nas from favorites" });
    expect(star.getAttribute("aria-pressed")).toBe("true");
  });

  it("moves the selection with the arrow keys and shows details", async () => {
    show(sampleInventory(sampleHosts()));
    await screen.findByText("7 hosts");
    await userEvent.click(within(list()).getByText("prod-api-01"));
    expect(await screen.findByRole("heading", { level: 2, name: "prod-api-01" })).toBeTruthy();
    expect(screen.getByText("Break glass")).toBeTruthy();
    await userEvent.keyboard("{ArrowDown}");
    expect(await screen.findByRole("heading", { level: 2, name: "prod-db-01" })).toBeTruthy();
    expect(screen.getByText("Key laptop · Through prod-jump")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Copy public key" })).toBeTruthy();
  });

  it("offers a connection entry for each saved login", async () => {
    const onConnect = vi.fn();
    show(sampleInventory(sampleHosts()), "en", onConnect);
    await screen.findByText("7 hosts");
    await userEvent.click(within(list()).getByText("prod-api-01"));
    const connect = await screen.findAllByRole("button", { name: "Connect" });
    expect(connect).toHaveLength(2);
    await userEvent.click(connect[0]!);
    expect(onConnect).toHaveBeenCalledWith("l-1", "prod-api-01 · deploy");
  });

  it("explains an empty inventory and a failure to load", async () => {
    const { container, unmount } = show(sampleInventory([]));
    expect(await screen.findByRole("heading", { name: "No hosts yet" })).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Add host" })).toHaveLength(2);
    expect(screen.getByRole("button", { name: "Import OpenSSH config" })).toBeTruthy();
    expect(await violations(container)).toEqual([]);
    unmount();

    show(sampleInventory(sampleHosts(), { failHosts: true }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Nothing was changed.");
    expect(alert.textContent).toContain("database is locked");
  });
});

describe("importing an OpenSSH config", () => {
  async function open(api: InventoryApi) {
    show(api);
    await screen.findByRole("heading", { name: "No hosts yet" });
    await userEvent.click(screen.getByRole("button", { name: "Import OpenSSH config" }));
    return screen.findByRole("dialog", { name: "Review OpenSSH import" });
  }

  it("previews only importable hosts and reports skipped hosts and directives", async () => {
    const api = sampleInventory([]);
    const preview = vi.spyOn(api, "previewOpenSshConfig");
    const { container } = show(api);
    await screen.findByRole("heading", { name: "No hosts yet" });
    await userEvent.click(screen.getByRole("button", { name: "Import OpenSSH config" }));
    const dialog = await screen.findByRole("dialog", { name: "Review OpenSSH import" });
    expect(preview).toHaveBeenCalledWith("/Users/mia/.ssh/config");
    expect(within(dialog).getByText("Source: /Users/mia/.ssh/config")).toBeTruthy();
    expect(within(dialog).getByRole("heading", { name: "Hosts to import (1)" })).toBeTruthy();
    expect(within(dialog).getByText("prod-api")).toBeTruthy();
    expect(within(dialog).getByText("deploy@prod.example.com")).toBeTruthy();
    expect(within(dialog).getByRole("heading", { name: "Skipped hosts (1)" })).toBeTruthy();
    expect(within(dialog).getByText("legacy")).toBeTruthy();
    expect(within(dialog).getByText(/Uses unsupported ForwardAgent/)).toBeTruthy();
    expect(within(dialog).getByRole("heading", { name: "Unsupported directives (1)" })).toBeTruthy();
    expect(within(dialog).getByText("line 7: ForwardAgent")).toBeTruthy();
    expect(document.activeElement?.textContent).toBe("Cancel");
    expect(await violations(container)).toEqual([]);
  });

  it("cancels without importing", async () => {
    const api = sampleInventory([]);
    const importHosts = vi.spyOn(api, "importOpenSshConfig");
    const dialog = await open(api);
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Review OpenSSH import" })).toBeNull());
    expect(importHosts).not.toHaveBeenCalled();
    expect(screen.getByText("0 hosts")).toBeTruthy();
  });

  it("imports the listed hosts and reports skipped hosts in the result", async () => {
    const api = sampleInventory([]);
    const importHosts = vi.spyOn(api, "importOpenSshConfig");
    const dialog = await open(api);
    await userEvent.click(within(dialog).getByRole("button", { name: "Import hosts" }));
    expect(importHosts).toHaveBeenCalledWith(
      expect.objectContaining({
        path: "/Users/mia/.ssh/config",
        entries: [{ alias: "prod-api", address: "prod.example.com", port: 22, username: "deploy", identityFile: null }],
      }),
    );
    expect(await screen.findByText("Imported 1 host. Skipped 1 host.")).toBeTruthy();
    expect(await screen.findByText("1 host")).toBeTruthy();
    expect(await screen.findByRole("heading", { level: 2, name: "prod-api" })).toBeTruthy();
    expect(screen.queryByRole("dialog", { name: "Review OpenSSH import" })).toBeNull();
  });

  it("shows a report with no importable hosts and disables the import action", async () => {
    const api = sampleInventory([]);
    api.previewOpenSshConfig = vi.fn(async (path) => ({
      status: "ok" as const,
      data: {
        path,
        entries: [],
        skippedHosts: [
          { alias: "prod-*", line: 1, reason: { kind: "globalRules" as const, directive: "Host *" } },
          { alias: "duplicate", line: 4, reason: { kind: "duplicateAlias" as const } },
          { alias: "bad-port", line: 8, reason: { kind: "invalidValue" as const, directive: "Port" } },
        ],
        unsupported: [{ line: 2, directive: "Include" }],
      },
    }));
    const importHosts = vi.spyOn(api, "importOpenSshConfig");
    const dialog = await open(api);
    expect(within(dialog).getByText(/No hosts can be imported from this file/)).toBeTruthy();
    expect(within(dialog).getByRole("heading", { name: "Hosts to import (0)" })).toBeTruthy();
    expect(within(dialog).getByRole("heading", { name: "Skipped hosts (3)" })).toBeTruthy();
    expect(within(dialog).getByText(/Affected by Host \* rules/)).toBeTruthy();
    expect(within(dialog).getByText(/appears in more than one Host block/)).toBeTruthy();
    expect(within(dialog).getByText(/The Port value cannot be imported/)).toBeTruthy();
    expect(within(dialog).getByText("line 2: Include")).toBeTruthy();
    expect(within(dialog).getByRole("button", { name: "Import hosts" }).hasAttribute("disabled")).toBe(true);
    expect(importHosts).not.toHaveBeenCalled();
  });

  it("keeps the report open after an import error and allows retry", async () => {
    const api = sampleInventory([]);
    const importOriginal = api.importOpenSshConfig;
    const importHosts = vi
      .spyOn(api, "importOpenSshConfig")
      .mockResolvedValueOnce({ status: "error", error: { kind: "identityNotFound", path: "/missing/key" } })
      .mockImplementation(importOriginal);
    const dialog = await open(api);
    await userEvent.click(within(dialog).getByRole("button", { name: "Import hosts" }));
    expect(await within(dialog).findByRole("alert")).toHaveProperty(
      "textContent",
      "The import failed. No hosts were changed. The identity file could not be read: /missing/key. Check the path in the config and try again.",
    );
    expect(screen.getByText("0 hosts")).toBeTruthy();
    await userEvent.click(within(dialog).getByRole("button", { name: "Import hosts" }));
    expect(importHosts).toHaveBeenCalledTimes(2);
    expect(await screen.findByText("Imported 1 host. Skipped 1 host.")).toBeTruthy();
  });

  it("requires a new preview when the source changed", async () => {
    const api = sampleInventory([]);
    api.importOpenSshConfig = vi.fn(async () => ({
      status: "error" as const,
      error: { kind: "sourceChanged" as const },
    }));
    const dialog = await open(api);
    await userEvent.click(within(dialog).getByRole("button", { name: "Import hosts" }));
    expect(await within(dialog).findByRole("alert")).toHaveProperty(
      "textContent",
      "The import failed. No hosts were changed. The source config changed since this preview. Close it and choose the file again.",
    );
    expect(within(dialog).getByRole("button", { name: "Import hosts" }).hasAttribute("disabled")).toBe(true);
    expect(screen.getByText("0 hosts")).toBeTruthy();
  });

  it("reports preview failures without opening an import dialog", async () => {
    const api = sampleInventory([]);
    api.previewOpenSshConfig = vi.fn(async () => ({ status: "error" as const, error: { kind: "tooLarge" as const } }));
    const importHosts = vi.spyOn(api, "importOpenSshConfig");
    show(api);
    await screen.findByRole("heading", { name: "No hosts yet" });
    await userEvent.click(screen.getByRole("button", { name: "Import OpenSSH config" }));
    expect(
      await screen.findByText(/The preview could not be prepared.*config exceeds the import size limit/),
    ).toBeTruthy();
    expect(screen.queryByRole("dialog", { name: "Review OpenSSH import" })).toBeNull();
    expect(importHosts).not.toHaveBeenCalled();
  });

  it("does nothing when the file picker is canceled", async () => {
    const api = sampleInventory([]);
    api.chooseOpenSshConfig = vi.fn(async () => null);
    const preview = vi.spyOn(api, "previewOpenSshConfig");
    show(api);
    await screen.findByRole("heading", { name: "No hosts yet" });
    await userEvent.click(screen.getByRole("button", { name: "Import OpenSSH config" }));
    await waitFor(() => expect(api.chooseOpenSshConfig).toHaveBeenCalledTimes(1));
    expect(preview).not.toHaveBeenCalled();
    expect(screen.queryByRole("dialog", { name: "Review OpenSSH import" })).toBeNull();
  });
});

describe("deleting a host", () => {
  it("asks first, then offers undo", async () => {
    show(sampleInventory(sampleHosts()));
    await screen.findByText("7 hosts");
    await userEvent.click(within(list()).getByText("nas"));
    await userEvent.click(await screen.findByRole("button", { name: "Delete host" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Delete nas?" });
    expect(document.activeElement?.textContent).toBe("Cancel");
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete host" }));
    expect(await screen.findByText("Deleted nas.")).toBeTruthy();
    expect(await screen.findByText("6 hosts")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Undo" }));
    expect(await screen.findByText("7 hosts")).toBeTruthy();
  });
});

describe("adding a host", () => {
  async function open() {
    show(sampleInventory(sampleHosts()));
    await screen.findByText("7 hosts");
    await userEvent.click(screen.getByRole("button", { name: "Add host" }));
    return screen.findByRole("dialog", { name: "Add host" });
  }

  it("asks only for the address, username, and how to sign in", async () => {
    const dialog = await open();
    expect(
      within(dialog)
        .getAllByRole("textbox")
        .map((f) => f.getAttribute("type") ?? "text"),
    ).toHaveLength(2);
    expect(within(dialog).getByLabelText("Password", { selector: "input[type=password]" })).toBeTruthy();
    expect(within(dialog).queryByLabelText("Name")).toBeNull();
    expect(await violations(dialog)).toEqual([]);
  });

  it("explains missing answers next to their fields", async () => {
    const dialog = await open();
    await userEvent.click(within(dialog).getByRole("button", { name: "Add host" }));
    expect(within(dialog).getByLabelText("Address").getAttribute("aria-invalid")).toBe("true");
    expect(within(dialog).getByText("Enter a DNS name or an IP address.")).toBeTruthy();
    await userEvent.type(within(dialog).getByLabelText("Address"), "10.0.9.9");
    await userEvent.type(within(dialog).getByLabelText("Username"), "ops");
    await userEvent.click(within(dialog).getByRole("button", { name: "Add host" }));
    expect(within(dialog).getByText("Enter the password, or choose another way to sign in.")).toBeTruthy();
  });

  it("explains a public key pasted where the private key belongs", async () => {
    const dialog = await open();
    await userEvent.type(within(dialog).getByLabelText("Address"), "10.0.9.9");
    await userEvent.type(within(dialog).getByLabelText("Username"), "ops");
    await userEvent.click(within(dialog).getByRole("radio", { name: "Key" }));
    await userEvent.click(within(dialog).getByRole("radio", { name: /Paste a key/ }));
    await userEvent.type(within(dialog).getByLabelText("Private key"), "ssh-ed25519 AAAA");
    await userEvent.click(within(dialog).getByRole("button", { name: "Add host" }));
    expect(await within(dialog).findByText(/This is a public key/)).toBeTruthy();
  });

  it("adds a host with a key file and selects it", async () => {
    const dialog = await open();
    await userEvent.type(within(dialog).getByLabelText("Address"), "build.example.com");
    await userEvent.type(within(dialog).getByLabelText("Username"), "ci");
    await userEvent.click(within(dialog).getByRole("radio", { name: "Key" }));
    await userEvent.click(within(dialog).getByRole("button", { name: "Choose key file" }));
    expect(await within(dialog).findByText("/Users/mia/.ssh/id_ed25519")).toBeTruthy();
    await userEvent.click(within(dialog).getByRole("button", { name: /More options/ }));
    await userEvent.type(within(dialog).getByLabelText("Port"), "70000");
    await userEvent.click(within(dialog).getByRole("button", { name: "Add host" }));
    expect(within(dialog).getByText("Enter a port from 1 to 65535.")).toBeTruthy();
    await userEvent.clear(within(dialog).getByLabelText("Port"));
    await userEvent.type(within(dialog).getByLabelText("Port"), "2200");
    await userEvent.click(within(dialog).getByRole("button", { name: "Add host" }));
    expect(await screen.findByText("Added build.example.com.")).toBeTruthy();
    expect(await screen.findByRole("heading", { level: 2, name: "build.example.com" })).toBeTruthy();
    expect(screen.getByText("build.example.com:2200")).toBeTruthy();
  });
});

describe("editing a host", () => {
  async function open() {
    show(sampleInventory(sampleHosts()));
    await screen.findByText("7 hosts");
    await userEvent.click(within(list()).getByText("nas"));
    await userEvent.click(await screen.findByRole("button", { name: "Edit host" }));
    return screen.findByRole("dialog", { name: "Edit host" });
  }

  it("updates metadata, tags, and group membership", async () => {
    const dialog = await open();
    await userEvent.clear(within(dialog).getByLabelText("Name"));
    await userEvent.type(within(dialog).getByLabelText("Name"), "home-nas");
    await userEvent.clear(within(dialog).getByLabelText("Address"));
    await userEvent.type(within(dialog).getByLabelText("Address"), "nas.home.example");
    await userEvent.clear(within(dialog).getByLabelText("Port"));
    await userEvent.type(within(dialog).getByLabelText("Port"), "2200");
    await userEvent.type(within(dialog).getByLabelText("Notes"), " updated");
    await userEvent.clear(within(dialog).getByLabelText("Tags"));
    await userEvent.type(within(dialog).getByLabelText("Tags"), "env=home\nowner=mia");
    await userEvent.click(within(dialog).getByRole("checkbox", { name: "Home lab" }));
    await userEvent.click(within(dialog).getByRole("button", { name: "Create group" }));
    const groupDialog = await screen.findByRole("dialog", { name: "Create group" });
    await userEvent.type(within(groupDialog).getByLabelText("Group name"), "Personal");
    await userEvent.click(within(groupDialog).getByRole("button", { name: "Save changes" }));
    expect(await screen.findByRole("checkbox", { name: "Personal" })).toBeTruthy();
    await userEvent.click(within(dialog).getByRole("button", { name: "Edit Personal" }));
    const editGroupDialog = await screen.findByRole("dialog", { name: "Edit group" });
    await userEvent.clear(within(editGroupDialog).getByLabelText("Group name"));
    await userEvent.type(within(editGroupDialog).getByLabelText("Group name"), "Personal work");
    await userEvent.click(within(editGroupDialog).getByRole("button", { name: "Save changes" }));
    expect(await screen.findByRole("checkbox", { name: "Personal work" })).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(await screen.findByRole("heading", { level: 2, name: "home-nas" })).toBeTruthy();
    expect(screen.getByText("nas.home.example:2200")).toBeTruthy();
    expect(screen.getAllByText("env: home").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Personal work").length).toBeGreaterThan(0);
  });

  it("keeps the form open and reports invalid metadata", async () => {
    const dialog = await open();
    await userEvent.clear(within(dialog).getByLabelText("Address"));
    await userEvent.type(within(dialog).getByLabelText("Address"), "bad address");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save changes" }));
    expect(within(dialog).getByText("Enter a DNS name or an IP address without spaces.")).toBeTruthy();
    expect(screen.getByRole("dialog", { name: "Edit host" })).toBeTruthy();
  });
});

describe("in Chinese", () => {
  it("uses the Chinese vocabulary", async () => {
    show(sampleInventory(sampleHosts()), "zh-Hans");
    expect(await screen.findByText("7 台主机")).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1, name: "我的主机" })).toBeTruthy();
    expect(screen.getByText("· 经由堡垒机（staging-net）")).toBeTruthy();
  });
});
