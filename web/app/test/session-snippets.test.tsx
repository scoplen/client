// SPDX-License-Identifier: Apache-2.0
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import type { SnippetView } from "../src/ipc/bindings";
import { SessionSnippets, type SnippetTarget } from "../src/session-snippets";
import { violations } from "../../ui/test/axe";

const commands = vi.hoisted(() => ({
  snippetsList: vi.fn(),
  snippetsCreate: vi.fn(),
  snippetsUpdate: vi.fn(),
  snippetsDelete: vi.fn(),
  snippetsPrepare: vi.fn(),
  sessionInput: vi.fn(),
}));
const store = vi.hoisted(() => ({ changed: () => {} }));
vi.mock("../src/account-profiles", () => ({ useProfileCommands: () => commands }));
vi.mock("../src/ipc/store-events", () => ({
  useStoreChanges: (_types: unknown, changed: () => void) => {
    store.changed = changed;
  },
}));

const snippet: SnippetView = {
  id: "0199a653-8392-7355-8b91-70ab85182e3a",
  name: "Inspect service",
  template: "printf '%s' '{{service}}'",
  variables: [{ name: "service", kind: "text", default: "api", choices: [], hasDefault: true }],
  tags: ["operations"],
  folder: "Services",
  readOnly: false,
  issue: null,
};

beforeEach(() => {
  vi.resetAllMocks();
  commands.snippetsList.mockResolvedValue({ status: "ok", data: [snippet] });
  commands.snippetsCreate.mockResolvedValue({ status: "ok", data: snippet });
  commands.snippetsUpdate.mockResolvedValue({ status: "ok", data: snippet });
  commands.snippetsDelete.mockResolvedValue({ status: "ok", data: null });
  commands.snippetsPrepare.mockResolvedValue({
    status: "ok",
    data: { snippetId: snippet.id, command: "printf '%s' 'api'" },
  });
  commands.sessionInput.mockResolvedValue({ status: "ok", data: null });
});
afterEach(() => cleanup());

function fixture(locale: "en" | "zh-Hans" = "en", targets?: SnippetTarget[]) {
  const close = vi.fn();
  const canSend = vi.fn(() => true);
  return {
    ...render(
      <I18nProvider locale={locale}>
        <SessionSnippets
          sessionId="session-original"
          transportId="transport-original"
          target="Deployment host"
          onClose={close}
          canSend={canSend}
          getTargets={targets ? () => targets : undefined}
        />
      </I18nProvider>,
    ),
    close,
    canSend,
  };
}

function terminalTargets(count = 3): SnippetTarget[] {
  return Array.from({ length: count }, (_, index) => ({
    sessionId: index ? `session-${index}` : "session-original",
    transportId: index ? `transport-${index}` : "transport-original",
    target: index < 2 ? "Deployment host" : `Other host ${index}`,
    location: { tab: index < 2 ? 1 : 2, pane: index < 2 ? index + 1 : index - 1 },
    canSend: vi.fn(() => true),
  }));
}
async function chooseSnippet() {
  await userEvent.click(await screen.findByRole("button", { name: "Use snippet" }));
}
async function preview() {
  await chooseSnippet();
  await userEvent.click(screen.getByRole("button", { name: "Review command" }));
  await screen.findByRole("button", { name: "Send command" });
}

it("loads saved objects, exposes a keyboard entry and does not prepare or send on selection", async () => {
  fixture();
  const use = await screen.findByRole("button", { name: "Use snippet" });
  expect(screen.getByText("Folder: Services")).toBeTruthy();
  expect(screen.getByText("Tags: operations")).toBeTruthy();
  use.focus();
  await userEvent.keyboard("{Enter}");
  expect((screen.getByRole("textbox", { name: "service" }) as HTMLInputElement).value).toBe("api");
  expect(commands.snippetsPrepare).not.toHaveBeenCalled();
  expect(commands.sessionInput).not.toHaveBeenCalled();
  expect(await violations(screen.getByRole("dialog"))).toEqual([]);
});

it("shows the complete Rust command and target, then sends its exact bytes plus one CR only after confirmation", async () => {
  fixture();
  await chooseSnippet();
  const input = screen.getByRole("textbox", { name: "service" });
  await userEvent.clear(input);
  await userEvent.type(input, "服务; echo literal");
  const command = "printf '%s' '服务; echo literal'";
  commands.snippetsPrepare.mockResolvedValue({ status: "ok", data: { snippetId: snippet.id, command } });
  await userEvent.click(screen.getByRole("button", { name: "Review command" }));
  const send = await screen.findByRole("button", { name: "Send command" });
  expect(commands.snippetsPrepare).toHaveBeenCalledExactlyOnceWith(snippet.id, { service: "服务; echo literal" });
  expect(screen.getByLabelText("Complete command to send").textContent).toBe(command);
  expect(screen.getByText("Terminal: Deployment host")).toBeTruthy();
  expect(screen.getByText(/empty shell prompt/)).toBeTruthy();
  expect(commands.sessionInput).not.toHaveBeenCalled();
  send.focus();
  await userEvent.keyboard("{Enter}");
  await screen.findByText(/Sent to terminal/);
  expect(commands.sessionInput).toHaveBeenCalledExactlyOnceWith(
    "session-original",
    "transport-original",
    Array.from(new TextEncoder().encode(command + "\r")),
  );
  expect(screen.queryByRole("button", { name: "Send command" })).toBeNull();
});

it("keeps an already prepared preview exact when synchronized objects change", async () => {
  fixture();
  await preview();
  commands.snippetsList.mockResolvedValue({ status: "ok", data: [{ ...snippet, template: "new command" }] });
  act(() => store.changed());
  await waitFor(() => expect(commands.snippetsList).toHaveBeenCalledTimes(2));
  expect(screen.getByLabelText("Complete command to send").textContent).toBe("printf '%s' 'api'");
  await userEvent.click(screen.getByRole("button", { name: "Send command" }));
  expect(commands.snippetsPrepare).toHaveBeenCalledTimes(1);
  expect(commands.sessionInput.mock.calls[0]![2]).toEqual(Array.from(new TextEncoder().encode("printf '%s' 'api'\r")));
});

it.each(["error", "rejection"])(
  "never automatically retries a %s send and removes its direct retry button",
  async (failure) => {
    if (failure === "error") commands.sessionInput.mockResolvedValue({ status: "error", error: "transport stopped" });
    else commands.sessionInput.mockRejectedValue(new Error("private details"));
    fixture();
    await preview();
    await userEvent.click(screen.getByRole("button", { name: "Send command" }));
    expect((await screen.findByRole("alert")).textContent).toContain("Inspect the terminal");
    expect(document.body.textContent).not.toContain("private details");
    expect(screen.queryByRole("button", { name: "Send command" })).toBeNull();
    expect(commands.sessionInput).toHaveBeenCalledTimes(1);
  },
);

it("refuses sending when the original session is no longer ready", async () => {
  const { canSend } = fixture();
  await preview();
  canSend.mockReturnValue(false);
  await userEvent.click(screen.getByRole("button", { name: "Send command" }));
  expect(commands.sessionInput).not.toHaveBeenCalled();
});

it("discards late preparation on unmount without sending into another view", async () => {
  let finish!: (value: unknown) => void;
  commands.snippetsPrepare.mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const { unmount } = fixture();
  await chooseSnippet();
  await userEvent.click(screen.getByRole("button", { name: "Review command" }));
  unmount();
  await act(async () => finish({ status: "ok", data: { snippetId: snippet.id, command: "late" } }));
  expect(commands.sessionInput).not.toHaveBeenCalled();
  expect(screen.queryByRole("dialog")).toBeNull();
});

it("preserves invalid values and shows fixed localized Rust validation without raw errors", async () => {
  commands.snippetsPrepare.mockResolvedValue({ status: "error", error: { kind: "invalidValue", name: "service" } });
  fixture();
  await chooseSnippet();
  const input = screen.getByRole("textbox", { name: "service" }) as HTMLInputElement;
  await userEvent.type(input, "bad");
  await userEvent.click(screen.getByRole("button", { name: "Review command" }));
  expect((await screen.findByRole("alert")).textContent).toContain("Check the value for “service”");
  expect(input.value).toBe("apibad");
  expect(commands.sessionInput).not.toHaveBeenCalled();
});

it("supports exact empty choices and integer strings without JavaScript coercion", async () => {
  commands.snippetsList.mockResolvedValue({
    status: "ok",
    data: [
      {
        ...snippet,
        variables: [
          { name: "count", kind: "integer", default: "9223372036854775807", choices: [], hasDefault: true },
          { name: "toString", kind: "choice", default: null, choices: ["", " api "], hasDefault: false },
        ],
      },
    ],
  });
  fixture();
  await chooseSnippet();
  expect(screen.getByRole("combobox", { name: "toString" })).toHaveProperty("value", "");
  await userEvent.selectOptions(screen.getByRole("combobox", { name: "toString" }), "0");
  await userEvent.click(screen.getByRole("button", { name: "Review command" }));
  expect(commands.snippetsPrepare).toHaveBeenCalledExactlyOnceWith(snippet.id, {
    count: "9223372036854775807",
    toString: "",
  });
});

it("submits a visible empty Text input explicitly while leaving missing Integer values for Rust validation", async () => {
  commands.snippetsList.mockResolvedValue({
    status: "ok",
    data: [
      {
        ...snippet,
        variables: [
          { name: "text", kind: "text", default: null, choices: [], hasDefault: false },
          { name: "constructor", kind: "integer", default: null, choices: [], hasDefault: false },
        ],
      },
    ],
  });
  fixture();
  await chooseSnippet();
  expect(screen.getByRole("textbox", { name: "constructor" })).toHaveProperty("value", "");
  await userEvent.click(screen.getByRole("button", { name: "Review command" }));
  expect(commands.snippetsPrepare).toHaveBeenCalledExactlyOnceWith(snippet.id, { text: "" });
});

it("creates a real editor intent with literal template, typed variable, folder and tags", async () => {
  fixture();
  await userEvent.click(await screen.findByRole("button", { name: "Add snippet" }));
  await userEvent.type(screen.getByRole("textbox", { name: "Name" }), "Show version");
  await userEvent.click(screen.getByRole("textbox", { name: "Command template" }));
  await userEvent.paste("printf '%s' '{{version}}'");
  await userEvent.type(screen.getByRole("textbox", { name: "Folder (optional)" }), "Tools");
  await userEvent.type(screen.getByRole("textbox", { name: "Tags (optional)" }), "ops{Enter}release");
  await userEvent.click(screen.getByRole("button", { name: "Add variable" }));
  await userEvent.type(screen.getByRole("textbox", { name: "Variable name" }), "version");
  await userEvent.selectOptions(screen.getByRole("combobox", { name: "Type" }), "integer");
  await userEvent.click(screen.getByRole("checkbox", { name: "Use a default value" }));
  await userEvent.type(screen.getByRole("textbox", { name: "Default value" }), "42");
  expect(await violations(screen.getByRole("dialog"))).toEqual([]);
  await userEvent.click(screen.getByRole("button", { name: "Save snippet" }));
  expect(commands.snippetsCreate).toHaveBeenCalledExactlyOnceWith({
    name: "Show version",
    template: "printf '%s' '{{version}}'",
    folder: "Tools",
    tags: ["ops", "release"],
    variables: [{ name: "version", kind: "integer", default: "42", choices: [] }],
  });
  await screen.findByRole("list", { name: "Saved snippets" });
});

it("edits and deletes only the selected snippet after explicit confirmation", async () => {
  fixture();
  await userEvent.click(await screen.findByRole("button", { name: "Edit snippet" }));
  const name = screen.getByRole("textbox", { name: "Name" });
  await userEvent.clear(name);
  await userEvent.type(name, "Inspect current service");
  await userEvent.click(screen.getByRole("button", { name: "Save snippet" }));
  expect(commands.snippetsUpdate).toHaveBeenCalledExactlyOnceWith(snippet.id, {
    name: "Inspect current service",
    template: snippet.template,
    variables: [{ name: "service", kind: "text", default: "api", choices: [] }],
    tags: snippet.tags,
    folder: snippet.folder,
  });
  await userEvent.click(await screen.findByRole("button", { name: "Delete snippet" }));
  expect(commands.snippetsDelete).not.toHaveBeenCalled();
  expect(screen.getByText(/Delete “Inspect service”/)).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: "Delete snippet" }));
  expect(commands.snippetsDelete).toHaveBeenCalledExactlyOnceWith(snippet.id);
});

it("shows existing secret definitions as redacted read-only metadata without edit, deletion or execution", async () => {
  commands.snippetsList.mockResolvedValue({
    status: "ok",
    data: [
      {
        ...snippet,
        readOnly: true,
        issue: { kind: "secretUnsupported" },
        variables: [{ name: "password", kind: "secret", default: null, choices: [], hasDefault: true }],
      },
    ],
  });
  fixture();
  await userEvent.click(await screen.findByRole("button", { name: "View snippet" }));
  expect(screen.getByText("password · Secret · Default saved")).toBeTruthy();
  expect(screen.queryByRole("textbox")).toBeNull();
  expect(screen.queryByRole("button", { name: "Edit snippet" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Delete snippet" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Review command" })).toBeNull();
  expect(commands.snippetsPrepare).not.toHaveBeenCalled();
});

it("keeps a synchronized invalid definition visibly unavailable for execution while allowing an edit to repair it", async () => {
  commands.snippetsList.mockResolvedValue({
    status: "ok",
    data: [{ ...snippet, issue: { kind: "invalidDefault", name: "service" } }],
  });
  fixture();
  await userEvent.click(await screen.findByRole("button", { name: "View snippet" }));
  expect(screen.getByText(/Check the default for/)).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Review command" })).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Back to snippets" }));
  await userEvent.click(screen.getByRole("button", { name: "Edit snippet" }));
  expect(screen.getByRole("textbox", { name: "Default value" })).toHaveProperty("value", "api");
  expect(commands.snippetsPrepare).not.toHaveBeenCalled();
});

it("renders Chinese labels, recovers list errors through an explicit refresh and handles empty state", async () => {
  commands.snippetsList.mockRejectedValueOnce(new Error("private details"));
  commands.snippetsList.mockResolvedValue({ status: "ok", data: [] });
  fixture("zh-Hans");
  expect((await screen.findByRole("alert")).textContent).toContain("无法确认本地操作结果");
  await userEvent.click(screen.getByRole("button", { name: "刷新片段" }));
  expect(await screen.findByText(/还没有命令片段/)).toBeTruthy();
  expect(screen.queryByRole("alert")).toBeNull();
  expect(await violations(screen.getByRole("dialog"))).toEqual([]);
});

it("defaults only to the current target and reviews same-Login siblings and other tabs before sending", async () => {
  fixture("en", terminalTargets());
  await chooseSnippet();
  const checkboxes = screen.getAllByRole("checkbox") as HTMLInputElement[];
  expect(checkboxes.map((checkbox) => checkbox.checked)).toEqual([true, false, false]);
  await userEvent.click(checkboxes[1]!);
  await userEvent.click(checkboxes[2]!);
  expect(commands.sessionInput).not.toHaveBeenCalled();
  expect(commands.snippetsPrepare).not.toHaveBeenCalled();
  expect(await violations(screen.getByRole("dialog"))).toEqual([]);
  await userEvent.click(screen.getByRole("button", { name: "Review command" }));
  const targets = await screen.findByRole("list", { name: "Confirmed target terminals" });
  expect(
    within(targets)
      .getAllByRole("listitem")
      .map((item) => item.textContent),
  ).toEqual(["Deployment hostTab 1 · Pane 1", "Deployment hostTab 1 · Pane 2", "Other host 2Tab 2 · Pane 1"]);
  expect(screen.getByLabelText("Complete command to send").textContent).toBe("printf '%s' 'api'");
  await userEvent.click(screen.getByRole("button", { name: "Send to selected terminals" }));
  await waitFor(() => expect(commands.sessionInput).toHaveBeenCalledTimes(3));
  expect(commands.sessionInput.mock.calls).toEqual(
    terminalTargets().map((target) => [
      target.sessionId,
      target.transportId,
      Array.from(new TextEncoder().encode("printf '%s' 'api'\r")),
    ]),
  );
  expect(commands.snippetsPrepare).toHaveBeenCalledTimes(1);
  expect(screen.getAllByText("Sent to terminal")).toHaveLength(3);
  expect(screen.queryByRole("button", { name: "Send to selected terminals" })).toBeNull();
});

it("requires a new preparation after changing command values or the reviewed targets", async () => {
  fixture("en", terminalTargets());
  await preview();
  await userEvent.click(screen.getByRole("button", { name: "Change command or targets" }));
  expect(screen.queryByRole("button", { name: "Send command" })).toBeNull();
  await userEvent.clear(screen.getByRole("textbox", { name: "service" }));
  await userEvent.type(screen.getByRole("textbox", { name: "service" }), "worker");
  await userEvent.click(screen.getAllByRole("checkbox")[1]!);
  commands.snippetsPrepare.mockResolvedValue({
    status: "ok",
    data: { snippetId: snippet.id, command: "worker command" },
  });
  await userEvent.click(screen.getByRole("button", { name: "Review command" }));
  await screen.findByRole("button", { name: "Send to selected terminals" });
  expect(commands.snippetsPrepare).toHaveBeenLastCalledWith(snippet.id, { service: "worker" });
  expect(screen.getByLabelText("Complete command to send").textContent).toBe("worker command");
  expect(
    within(screen.getByRole("list", { name: "Confirmed target terminals" })).getAllByRole("listitem"),
  ).toHaveLength(2);
  expect(commands.sessionInput).not.toHaveBeenCalled();
});

it.each(["error", "rejection"])(
  "sends in order, skips known stale targets and continues after an uncertain %s",
  async (failure) => {
    const targets = terminalTargets(4);
    fixture("en", targets);
    await chooseSnippet();
    for (const checkbox of screen.getAllByRole("checkbox").slice(1)) await userEvent.click(checkbox);
    await userEvent.click(screen.getByRole("button", { name: "Review command" }));
    await screen.findByRole("button", { name: "Send to selected terminals" });
    vi.mocked(targets[1]!.canSend).mockReturnValue(false);
    let finish!: (value: unknown) => void;
    commands.sessionInput.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
    if (failure === "error")
      commands.sessionInput.mockResolvedValueOnce({ status: "error", error: "private native detail" });
    else commands.sessionInput.mockRejectedValueOnce(new Error("private IPC detail"));
    await userEvent.click(screen.getByRole("button", { name: "Send to selected terminals" }));
    expect(commands.sessionInput).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: "Send to selected terminals" })).toBeNull();
    await act(async () => finish({ status: "ok", data: null }));
    await waitFor(() => expect(commands.sessionInput).toHaveBeenCalledTimes(3));
    expect(commands.sessionInput.mock.calls.map((args) => args.slice(0, 2))).toEqual([
      ["session-original", "transport-original"],
      ["session-2", "transport-2"],
      ["session-3", "transport-3"],
    ]);
    const rows = within(screen.getByRole("list", { name: "Per-terminal send results" })).getAllByRole("listitem");
    expect(rows[0]!.textContent).toContain("Sent to terminal");
    expect(rows[1]!.textContent).toContain("Not sent");
    expect(rows[2]!.textContent).toContain("Result unknown");
    expect(rows[3]!.textContent).toContain("Sent to terminal");
    expect(document.body.textContent).not.toContain("private native detail");
    expect(document.body.textContent).not.toContain("private IPC detail");
    expect(commands.snippetsPrepare).toHaveBeenCalledTimes(1);
  },
);

it("stops starting further sends after its owning view unmounts and discards late results", async () => {
  const view = fixture("en", terminalTargets());
  await chooseSnippet();
  await userEvent.click(screen.getAllByRole("checkbox")[1]!);
  await userEvent.click(screen.getByRole("button", { name: "Review command" }));
  let finish!: (value: unknown) => void;
  commands.sessionInput.mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  await userEvent.click(await screen.findByRole("button", { name: "Send to selected terminals" }));
  expect(commands.sessionInput).toHaveBeenCalledTimes(1);
  view.unmount();
  fixture("en", terminalTargets());
  await screen.findByRole("button", { name: "Use snippet" });
  await act(async () => finish({ status: "ok", data: null }));
  expect(commands.sessionInput).toHaveBeenCalledTimes(1);
  expect(screen.queryByRole("list", { name: "Per-terminal send results" })).toBeNull();
});

it.each(["before-send", "pending-send"] as const)(
  "invalidates its source even when only other ready terminals are selected: %s",
  async (phase) => {
    const targets = terminalTargets();
    const { canSend, close } = fixture("en", targets);
    await chooseSnippet();
    for (const checkbox of screen.getAllByRole("checkbox")) await userEvent.click(checkbox);
    await userEvent.click(screen.getByRole("button", { name: "Review command" }));
    const send = await screen.findByRole("button", { name: "Send to selected terminals" });
    let finish!: (value: unknown) => void;
    commands.sessionInput.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
    if (phase === "before-send") canSend.mockReturnValue(false);
    await userEvent.click(send);
    if (phase === "pending-send") {
      expect(commands.sessionInput).toHaveBeenCalledTimes(1);
      canSend.mockReturnValue(false);
      await act(async () => finish({ status: "ok", data: null }));
    }
    expect(commands.sessionInput).toHaveBeenCalledTimes(phase === "before-send" ? 0 : 1);
    expect(close).toHaveBeenCalledTimes(1);
    expect(screen.queryByText("Sent to terminal")).toBeNull();
    expect(targets.every((target) => target.canSend())).toBe(true);
  },
);

it.each(["empty", "duplicate", "unavailable"] as const)(
  "refuses %s target selection before preparing or sending",
  async (problem) => {
    const targets = terminalTargets(1);
    if (problem === "duplicate") targets.push({ ...targets[0]! });
    fixture("en", targets);
    await chooseSnippet();
    if (problem === "empty") await userEvent.click(screen.getByRole("checkbox"));
    if (problem === "unavailable") vi.mocked(targets[0]!.canSend).mockReturnValue(false);
    await userEvent.click(screen.getByRole("button", { name: "Review command" }));
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(commands.snippetsPrepare).not.toHaveBeenCalled();
    expect(commands.sessionInput).not.toHaveBeenCalled();
  },
);

it("accepts 64 distinct targets but explicitly refuses selecting a 65th", async () => {
  fixture("en", terminalTargets(65));
  await chooseSnippet();
  const choices = screen.getAllByRole("checkbox") as HTMLInputElement[];
  for (const checkbox of choices.slice(1)) await userEvent.click(checkbox);
  expect(choices.filter((checkbox) => checkbox.checked)).toHaveLength(64);
  expect(choices[64]!.checked).toBe(false);
  expect((await screen.findByRole("alert")).textContent).toContain("no more than 64");
  await userEvent.click(screen.getByRole("button", { name: "Review command" }));
  const reviewed = await screen.findByRole("list", { name: "Confirmed target terminals" });
  expect(within(reviewed).getAllByRole("listitem")).toHaveLength(64);
  expect(commands.snippetsPrepare).toHaveBeenCalledTimes(1);
  expect(commands.sessionInput).not.toHaveBeenCalled();
}, 15_000);

it("localizes target selection, confirmation and individual results in Chinese", async () => {
  const targets = terminalTargets(2);
  fixture("zh-Hans", targets);
  await userEvent.click(await screen.findByRole("button", { name: "使用片段" }));
  const other = screen.getAllByRole("checkbox")[1]!;
  other.focus();
  await userEvent.keyboard(" ");
  await userEvent.click(screen.getByRole("button", { name: "预览命令" }));
  await screen.findByRole("list", { name: "已确认的目标终端" });
  vi.mocked(targets[1]!.canSend).mockReturnValue(false);
  await userEvent.click(screen.getByRole("button", { name: "发送到所选终端" }));
  expect(await screen.findByText("已发送到终端")).toBeTruthy();
  expect(screen.getByText("未发送，此连接已不可用。")).toBeTruthy();
  expect(commands.sessionInput).toHaveBeenCalledTimes(1);
});
