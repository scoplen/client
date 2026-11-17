// SPDX-License-Identifier: Apache-2.0
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { emit } from "@tauri-apps/api/event";
import type { Channel } from "@tauri-apps/api/core";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState, type ReactNode } from "react";
import { AppearanceProvider } from "@scoplen/ui";
import type { ScoplenTerminalElement } from "@scoplen/terminal";
import { I18nProvider } from "../src/i18n";
import { TerminalColorsProvider, useTerminalColors } from "../src/terminal-colors";
import { AccountProfilesBoundary, useProfileCommands } from "../src/account-profiles";
import { TerminalProfilesProvider, TerminalProfileSelect, useTerminalProfiles } from "../src/terminal-profiles";
import { TerminalProfileSettingsPanel } from "../src/terminal-profile-settings";
import { SessionTerminal } from "../src/session";
import type {
  SessionEvent,
  TerminalProfileDirectory,
  TerminalProfileSettings,
  TerminalProfileIssue,
} from "../src/ipc/bindings";
import { selectOption } from "./select-option";
import { InventoryObjects } from "../src/inventory/objects";
import { InventoryContext } from "../src/inventory/api";
import { sampleHosts, sampleInventory } from "../src/gallery/sample-inventory";
import { TeamAuthoringFields } from "../src/team-authoring-fields";
import type { TeamAuthoringData } from "../src/ipc/bindings";

const defaults: TerminalProfileSettings = {
  fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace",
  fontSize: 14,
  cursorStyle: "block",
  cursorBlink: true,
  scrollback: 2000,
};
const snapshot = { version: 1 as const, columns: 80, rows: 24, data: "retained exact output" };
beforeEach(() => {
  vi.stubGlobal("matchMedia", () => ({
    matches: false,
    addListener() {},
    removeListener() {},
    addEventListener() {},
    removeEventListener() {},
  }));
});
afterEach(() => {
  cleanup();
  clearMocks();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  localStorage.clear();
});

function fixture(initial: TerminalProfileDirectory = { defaultProfile: defaults, named: [] }) {
  let directory = structuredClone(initial);
  let failure: TerminalProfileIssue | null = null;
  let holdList: Promise<TerminalProfileDirectory> | null = null;
  let holdSave: Promise<TerminalProfileDirectory> | null = null;
  const calls: Array<{ command: string; args: Record<string, unknown> }> = [];
  const connections: Array<{ sessionId: string; messages: Channel<SessionEvent | ArrayBuffer> }> = [];
  mockIPC(
    (command, args) => {
      const input = (args ?? {}) as Record<string, unknown>;
      calls.push({ command, args: input });
      if (command === "account_profiles_snapshot")
        return { generation: "1", selected: null, accounts: [], retainedProfile: false };
      if (command.startsWith("terminal_profiles_")) {
        if (failure) throw failure;
        if (command === "terminal_profiles_list") return holdList ?? structuredClone(directory);
        if (command === "terminal_profiles_create")
          directory.named.push({ name: input.name as string, settings: structuredClone(directory.defaultProfile) });
        if (command === "terminal_profiles_save") {
          if (holdSave) return holdSave;
          if (input.name === null) directory.defaultProfile = input.settings as TerminalProfileSettings;
          else
            directory.named.find((entry) => entry.name === input.name)!.settings =
              input.settings as TerminalProfileSettings;
        }
        if (command === "terminal_profiles_reset_default") directory.defaultProfile = structuredClone(defaults);
        if (command === "terminal_profiles_delete")
          directory.named = directory.named.filter((entry) => entry.name !== input.name);
        return structuredClone(directory);
      }
      if (command === "session_connect") {
        connections.push(input as unknown as (typeof connections)[number]);
        return new Promise(() => undefined);
      }
      if (command === "session_transfer_queue")
        return {
          sessionId: input.sessionId,
          queueId: "q",
          revision: "1",
          capacity: 16,
          outstanding: 0,
          pickerBusy: false,
          blocksFileOperations: false,
          items: [],
          recent: [],
        };
      return null;
    },
    { shouldMockEvents: true },
  );
  return {
    connections,
    calls,
    directory: () => directory,
    fail: (issue: TerminalProfileIssue | null) => {
      failure = issue;
    },
    setDirectory: (value: TerminalProfileDirectory) => {
      directory = value;
    },
    holdList: (value: Promise<TerminalProfileDirectory> | null) => {
      holdList = value;
    },
    holdSave: (value: Promise<TerminalProfileDirectory>) => {
      holdSave = value;
    },
  };
}

function view(children: ReactNode, account = false) {
  return render(
    <AppearanceProvider>
      <TerminalColorsProvider>
        <I18nProvider locale="en">
          {account ? (
            <AccountProfilesBoundary>{children}</AccountProfilesBoundary>
          ) : (
            <TerminalProfilesProvider>{children}</TerminalProfilesProvider>
          )}
        </I18nProvider>
      </TerminalColorsProvider>
    </AppearanceProvider>,
  );
}

it("creates from current Default, edits immutable named settings, deletes and resets Default through local commands", async () => {
  const f = fixture();
  view(<TerminalProfileSettingsPanel />);
  const size = await screen.findByLabelText("Font size (8–48 px)");
  fireEvent.change(size, { target: { value: "18" } });
  await userEvent.click(screen.getByRole("button", { name: "Save profile" }));
  await screen.findByText("Profile saved. Open terminals now use these settings.");
  await userEvent.click(screen.getByRole("button", { name: "Create profile" }));
  const dialog = await screen.findByRole("dialog", { name: "Create profile" });
  await userEvent.type(within(dialog).getByLabelText("Profile name"), "Work");
  await userEvent.click(within(dialog).getByRole("button", { name: "Create profile" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect((screen.getByLabelText("Font size (8–48 px)") as HTMLInputElement).value).toBe("18");
  expect(screen.queryByLabelText("Profile name")).toBeNull();
  await selectOption(screen.getByLabelText("Cursor shape"), "Bar");
  fireEvent.change(screen.getByLabelText("Scrollback rows (0–100,000)"), { target: { value: "0" } });
  await userEvent.click(screen.getByRole("checkbox", { name: "Blink cursor" }));
  await userEvent.click(screen.getByRole("button", { name: "Save profile" }));
  await screen.findByText("Profile saved. Open terminals now use these settings.");
  expect(f.directory().named[0]).toMatchObject({
    name: "Work",
    settings: { cursorStyle: "bar", cursorBlink: false, scrollback: 0 },
  });
  await userEvent.click(screen.getByRole("button", { name: "Delete profile" }));
  const confirmation = await screen.findByRole("alertdialog");
  expect(confirmation.textContent).toContain("Logins keep this name");
  await userEvent.click(within(confirmation).getByRole("button", { name: "Delete profile" }));
  await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
  await userEvent.click(screen.getByRole("button", { name: "Reset Default" }));
  await waitFor(() => expect(f.directory().defaultProfile.fontSize).toBe(14));
  expect(f.directory().named).toEqual([]);
  expect(f.calls.every((call) => call.command.startsWith("terminal_profiles_"))).toBe(true);
});

it("keeps unavailable exact names in the custom selector until explicit replacement", async () => {
  fixture({ defaultProfile: defaults, named: [{ name: "work", settings: defaults }] });
  function Login() {
    const [name, setName] = useState<string | null>("Work");
    return (
      <>
        <TerminalProfileSelect label="Appearance" value={name} onChange={setName} />
        <output>{name ?? "unset"}</output>
      </>
    );
  }
  const result = view(<Login />);
  await screen.findByText("“Work” is unavailable on this device. Using Default.");
  const select = screen.getByLabelText("Appearance");
  expect(select.tagName).toBe("BUTTON");
  expect(select.textContent).toContain("Work (unavailable on this device)");
  expect(result.container.querySelector("select")).toBeNull();
  await selectOption(select, "work");
  expect(screen.getByRole("status").textContent).toBe("work");
  expect(screen.queryByText(/Using Default/)).toBeNull();
});

it("connects Personal and Organization Login editors to the same local custom selector", async () => {
  fixture({ defaultProfile: defaults, named: [{ name: "Work", settings: defaults }] });
  const api = sampleInventory(sampleHosts());
  const update = vi.spyOn(api, "updateAccessProfile");
  const personal = view(
    <InventoryContext.Provider value={api}>
      <InventoryObjects section="logins" onBack={() => undefined} />
    </InventoryContext.Provider>,
  );
  await userEvent.click(await screen.findByRole("button", { name: "Edit dba@prod-db-01" }));
  const dialog = await screen.findByRole("dialog", { name: "Edit dba" });
  const select = within(dialog).getByLabelText("Terminal profile");
  expect(select.tagName).toBe("BUTTON");
  await selectOption(select, "Work");
  await userEvent.click(within(dialog).getByRole("button", { name: "Save changes" }));
  await waitFor(() =>
    expect(update).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ terminalProfile: "Work" })),
  );
  personal.unmount();
  const change = vi.fn();
  function TeamLogin() {
    const [data, setData] = useState<TeamAuthoringData>({
      kind: "login",
      fields: { host: "host", username: "ops", route: 0, terminal_profile: "Missing" },
    });
    return (
      <TeamAuthoringFields
        data={data}
        onChange={(value) => {
          setData(value);
          change(value);
        }}
        references={{}}
        loadMore={() => undefined}
        members={[]}
        moreMembers={false}
        loadMembers={() => undefined}
        onValid={() => undefined}
      />
    );
  }
  view(<TeamLogin />);
  await screen.findByText("“Missing” is unavailable on this device. Using Default.");
  await selectOption(screen.getByRole("combobox", { name: "Terminal profile" }), "Work");
  expect(change).toHaveBeenLastCalledWith(
    expect.objectContaining({ kind: "login", fields: expect.objectContaining({ terminal_profile: "Work" }) }),
  );
  await selectOption(screen.getByRole("combobox", { name: "Terminal profile" }), "Default");
  expect(change).toHaveBeenLastCalledWith(
    expect.objectContaining({ fields: expect.objectContaining({ terminal_profile: undefined }) }),
  );
});

function Controls() {
  const state = useTerminalProfiles()!;
  const commands = useProfileCommands();
  const colors = useTerminalColors();
  return (
    <>
      <button
        onClick={() =>
          void state.change(() => commands.terminalProfilesSave(null, { ...defaults, fontSize: 20, scrollback: 0 }))
        }
      >
        Change Default
      </button>
      <button
        onClick={() =>
          void state.change(() =>
            commands.terminalProfilesSave("Work", { ...defaults, fontSize: 28, cursorStyle: "bar" }),
          )
        }
      >
        Change Work
      </button>
      <button onClick={() => void state.change(() => commands.terminalProfilesDelete("Work"))}>Delete Work</button>
      <button onClick={() => colors.setColor("foreground", "#abcdef")}>Change color</button>
    </>
  );
}

it("updates target, hidden and read-only panes in place, preserves global colors, input and restoration, and ignores Jump appearance", async () => {
  const f = fixture({
    defaultProfile: defaults,
    named: [
      { name: "Work", settings: { ...defaults, fontSize: 16 } },
      { name: "Jump", settings: { ...defaults, fontSize: 40 } },
    ],
  });
  const rendered = view(
    <>
      <Controls />
      <SessionTerminal target={{ kind: "personal", profileId: "target" }} label="Target" onClose={() => undefined} />
      <div hidden>
        <SessionTerminal
          target={{ kind: "personal", profileId: "saved" }}
          label="Hidden"
          active={false}
          savedOutput={snapshot}
          savedTerminalProfile="Work"
          onClose={() => undefined}
        />
      </div>
      <SessionTerminal
        target={{ kind: "personal", profileId: "missing" }}
        label="Missing"
        savedOutput={snapshot}
        savedTerminalProfile="Missing"
        onClose={() => undefined}
      />
    </>,
  );
  await waitFor(() => expect(f.connections).toHaveLength(1));
  const panes = Array.from(rendered.container.querySelectorAll<ScoplenTerminalElement>("scoplen-terminal"));
  await waitFor(() => expect(panes[1]!.findNext(snapshot.data)).toBe(true));
  const restore = vi.spyOn(panes[1]!, "restore");
  const channel = f.connections[0]!.messages;
  const transportId = crypto.randomUUID();
  await act(() => channel.onmessage({ kind: "starting", transportId, automatic: false }));
  const context = {
    source: null,
    profileId: "target",
    hostId: "host",
    login: "ops",
    host: "Target",
    username: "ops",
    address: "example.test",
    port: 22,
    position: 1,
    total: 2,
    target: false,
    terminalProfile: "Jump",
  };
  await act(() =>
    channel.onmessage({ kind: "preparation", transportId, event: { kind: "progress", phase: "connecting", context } }),
  );
  expect(panes[0]!.profile.fontSize).toBe(14);
  await act(() =>
    channel.onmessage({
      kind: "preparation",
      transportId,
      event: {
        kind: "progress",
        phase: "authenticating",
        context: { ...context, position: 2, target: true, terminalProfile: "Work" },
      },
    }),
  );
  await act(() => channel.onmessage({ kind: "ready", transportId }));
  await waitFor(() => expect(panes[0]!.profile.fontSize).toBe(16));
  await userEvent.click(screen.getByRole("button", { name: "Change color" }));
  const colors = localStorage.getItem("scoplen.terminal-colors");
  const unaffected = vi.spyOn(panes[2]!, "profile", "set");
  await userEvent.click(screen.getByRole("button", { name: "Change Work" }));
  await waitFor(() => expect(panes[0]!.profile.fontSize).toBe(28));
  expect(panes[1]!.profile.fontSize).toBe(28);
  expect(panes[2]!.profile.fontSize).toBe(14);
  expect(unaffected).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Change Default" }));
  await waitFor(() => expect(panes[2]!.profile.fontSize).toBe(20));
  expect(panes[0]!.profile.fontSize).toBe(28);
  expect(panes[2]!.profile.scrollback).toBe(0);
  await userEvent.click(screen.getByRole("button", { name: "Delete Work" }));
  await waitFor(() => expect(panes[0]!.profile.fontSize).toBe(20));
  expect(panes[1]!.profile.fontSize).toBe(20);
  expect(screen.getAllByText("“Work” is unavailable on this device. Using Default.").length).toBe(2);
  expect(Array.from(rendered.container.querySelectorAll("scoplen-terminal"))).toEqual(panes);
  expect(restore).not.toHaveBeenCalled();
  expect(panes[1]!.readOnly).toBe(true);
  expect(panes[1]!.findNext(snapshot.data)).toBe(true);
  expect(panes.every((pane) => pane.profile.theme?.foreground === "#abcdef")).toBe(true);
  expect(localStorage.getItem("scoplen.terminal-colors")).toBe(colors);
  expect(f.calls.filter((call) => call.command === "session_input")).toHaveLength(0);
  expect(f.connections).toHaveLength(1);
  await panes[0]!.send(new Uint8Array([65]));
  await waitFor(() =>
    expect(f.calls.filter((call) => call.command === "session_input").at(-1)?.args.transportId).toBe(transportId),
  );
});

it("reports load/save failures without replacing the confirmed directory", async () => {
  const f = fixture();
  f.fail("storage");
  view(<TerminalProfileSettingsPanel />);
  expect((await screen.findByRole("alert")).textContent).toContain("could not be read or saved");
  f.fail(null);
  await userEvent.click(screen.getByRole("button", { name: "Reload profiles" }));
  const size = await screen.findByLabelText("Font size (8–48 px)");
  fireEvent.change(size, { target: { value: "18" } });
  f.fail("storage");
  await userEvent.click(screen.getByRole("button", { name: "Save profile" }));
  expect((await screen.findByRole("alert")).textContent).toContain("could not be read or saved");
  expect(f.directory().defaultProfile.fontSize).toBe(14);
  expect((screen.getByLabelText("Font size (8–48 px)") as HTMLInputElement).value).toBe("18");
});

it("waits for the local profile before restoring large saved output, preserving its oldest rows", async () => {
  const f = fixture();
  let finish!: (directory: TerminalProfileDirectory) => void;
  f.holdList(
    new Promise((resolve) => {
      finish = resolve;
    }),
  );
  const saved = {
    ...snapshot,
    data: "oldest-profile-row\r\n" + "retained row\r\n".repeat(2500) + "latest-profile-row",
  };
  const rendered = view(
    <SessionTerminal
      target={{ kind: "personal", profileId: "saved" }}
      label="Saved"
      savedOutput={saved}
      savedTerminalProfile="Long"
      onClose={() => undefined}
    />,
  );
  const element = rendered.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  const restore = vi.spyOn(element, "restore");
  expect(screen.getByText("Loading terminal profiles…")).toBeTruthy();
  await act(async () => undefined);
  expect(restore).not.toHaveBeenCalled();
  await act(async () =>
    finish({ defaultProfile: defaults, named: [{ name: "Long", settings: { ...defaults, scrollback: 5000 } }] }),
  );
  await waitFor(() => expect(restore).toHaveBeenCalledTimes(1));
  await waitFor(async () => expect((await element.serialize()).data).toContain("oldest-profile-row"));
  expect((await element.serialize()).data).toContain("latest-profile-row");
  expect(f.connections).toHaveLength(0);
});

it("offers a local retry after failed profile loading without restoring saved output under an unknown limit", async () => {
  const f = fixture();
  f.fail("storage");
  const rendered = view(
    <SessionTerminal
      target={{ kind: "personal", profileId: "saved" }}
      label="Saved"
      savedOutput={snapshot}
      onClose={() => undefined}
    />,
  );
  const element = rendered.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  const restore = vi.spyOn(element, "restore");
  expect((await screen.findByRole("alert")).textContent).toContain("could not be read or saved");
  expect(restore).not.toHaveBeenCalled();
  f.fail(null);
  await userEvent.click(screen.getByRole("button", { name: "Reload profiles" }));
  await waitFor(() => expect(restore).toHaveBeenCalledTimes(1));
  await waitFor(async () => expect((await element.serialize()).data).toContain(snapshot.data));
  expect(f.connections).toHaveLength(0);
});

it("replaces the directory and panes at the Account generation boundary and rejects late old saves", async () => {
  const f = fixture({ defaultProfile: defaults, named: [{ name: "First account", settings: defaults }] });
  let finish!: (directory: TerminalProfileDirectory) => void;
  f.holdSave(
    new Promise((resolve) => {
      finish = resolve;
    }),
  );
  const rendered = view(
    <>
      <Controls />
      <TerminalProfileSettingsPanel />
      <SessionTerminal
        target={{ kind: "personal", profileId: "saved" }}
        label="Offline"
        savedOutput={snapshot}
        onClose={() => undefined}
      />
    </>,
    true,
  );
  await screen.findByLabelText("Font size (8–48 px)");
  const original = rendered.container.querySelector("scoplen-terminal");
  await userEvent.click(screen.getByRole("button", { name: "Change Default" }));
  const next = { defaultProfile: { ...defaults, fontSize: 30 }, named: [] };
  f.setDirectory(next);
  await act(async () =>
    emit("profile-changed", { snapshot: { generation: "2", selected: null, accounts: [], retainedProfile: false } }),
  );
  await waitFor(() => expect((screen.getByLabelText("Font size (8–48 px)") as HTMLInputElement).value).toBe("30"));
  await act(async () =>
    finish({ defaultProfile: { ...defaults, fontSize: 20 }, named: [{ name: "First account", settings: defaults }] }),
  );
  expect((screen.getByLabelText("Font size (8–48 px)") as HTMLInputElement).value).toBe("30");
  expect(rendered.container.querySelector("scoplen-terminal")).not.toBe(original);
  await userEvent.click(screen.getByLabelText("Edit terminal profile"));
  expect(within(await screen.findByRole("listbox")).queryByRole("option", { name: "First account" })).toBeNull();
});
