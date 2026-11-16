// SPDX-License-Identifier: Apache-2.0
import { ScoplenTerminalElement } from "@scoplen/terminal";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import { SessionSearch } from "../src/session-search";

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
  document.body.replaceChildren();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

async function fixture() {
  const element = document.createElement("scoplen-terminal") as ScoplenTerminalElement;
  const write = vi.fn();
  const subscribe = vi.fn((emit: (bytes: Uint8Array) => void) => {
    emit(new TextEncoder().encode("first token [x].*\r\nsecond token [x].*\r\nlast line"));
    return () => undefined;
  });
  element.source = { subscribe };
  element.sink = write;
  document.body.append(element);
  await element.serialize();
  return { element, write, subscribe };
}

function panel(element: ScoplenTerminalElement | null, onClose = vi.fn(), locale: "en" | "zh-Hans" = "en") {
  return (
    <I18nProvider locale={locale}>
      <SessionSearch open active terminal={{ current: element }} input={{ current: null }} onClose={onClose} />
    </I18nProvider>
  );
}

it("finds exact literal text through the public terminal export without writing input or replacing its source", async () => {
  const f = await fixture();
  const next = vi.spyOn(f.element, "findNext");
  const previous = vi.spyOn(f.element, "findPrevious");
  const original = f.element.getOutput();
  render(panel(f.element));
  const query = screen.getByRole("textbox", { name: "Find in terminal output" });
  expect(document.activeElement).toBe(query);
  await userEvent.type(query, "token [[x].*");
  await userEvent.keyboard("{Enter}");
  expect(next).toHaveBeenLastCalledWith("token [x].*", { caseSensitive: true, regex: false, wholeWord: false });
  expect(screen.getByRole("status").textContent).toBe("Match selected.");
  await userEvent.keyboard("{Shift>}{Enter}{/Shift}");
  expect(previous).toHaveBeenLastCalledWith("token [x].*", { caseSensitive: true, regex: false, wholeWord: false });
  await userEvent.click(screen.getByRole("button", { name: "Next" }));
  expect(next).toHaveBeenCalledTimes(2);
  await userEvent.click(screen.getByRole("button", { name: "Previous" }));
  expect(previous).toHaveBeenCalledTimes(2);
  expect(f.write).not.toHaveBeenCalled();
  expect(f.subscribe).toHaveBeenCalledTimes(1);
  expect(f.element.getOutput()).toEqual(original);
});

it("clears empty queries and reports fixed case-sensitive no-match status", async () => {
  const f = await fixture();
  const clear = vi.spyOn(f.element, "clearSearch");
  render(panel(f.element));
  const query = screen.getByRole("textbox");
  expect(screen.getByRole<HTMLButtonElement>("button", { name: "Next" }).disabled).toBe(true);
  await userEvent.type(query, "TOKEN [[x].*");
  await userEvent.click(screen.getByRole("button", { name: "Next" }));
  expect(screen.getByRole("status").textContent).toBe("No matching text in retained output.");
  await userEvent.clear(query);
  expect(clear).toHaveBeenCalled();
  expect(screen.queryByRole("status")).toBeNull();
  expect(screen.getByRole<HTMLButtonElement>("button", { name: "Previous" }).disabled).toBe(true);
  expect(f.write).not.toHaveBeenCalled();
});

it("keeps the query and shows fixed text for thrown and unavailable public search calls", async () => {
  const f = await fixture();
  vi.spyOn(f.element, "findNext").mockImplementation(() => {
    throw new Error("private search diagnostic");
  });
  const view = render(panel(f.element));
  await userEvent.type(screen.getByRole("textbox"), "keep this query");
  await userEvent.click(screen.getByRole("button", { name: "Next" }));
  const message = "This output could not be searched. Your query is kept; try Find again.";
  expect(screen.getByRole("alert").textContent).toBe(message);
  expect(screen.queryByText("private search diagnostic")).toBeNull();
  expect(screen.getByRole<HTMLInputElement>("textbox").value).toBe("keep this query");
  view.rerender(panel(null));
  await userEvent.click(screen.getByRole("button", { name: "Previous" }));
  expect(screen.getByRole("alert").textContent).toBe(message);
  expect(f.write).not.toHaveBeenCalled();
});

it("clears decorations on Escape and the labeled close action", async () => {
  const f = await fixture();
  const clear = vi.spyOn(f.element, "clearSearch");
  const close = vi.fn();
  render(panel(f.element, close));
  await userEvent.type(screen.getByRole("textbox"), "token");
  await userEvent.keyboard("{Enter}");
  clear.mockClear();
  await userEvent.keyboard("{Escape}");
  expect(clear).toHaveBeenCalledTimes(1);
  expect(close).toHaveBeenCalledTimes(1);
  screen.getByRole("button", { name: "Close find" }).focus();
  await userEvent.keyboard("{Enter}");
  expect(clear).toHaveBeenCalledTimes(2);
  expect(close).toHaveBeenCalledTimes(2);
  expect(f.write).not.toHaveBeenCalled();
});

it("uses the same literal case-sensitive profile in the public text fallback", async () => {
  const f = await fixture();
  f.element.remove();
  const options = { caseSensitive: true, regex: false, wholeWord: false };
  expect(f.element.findNext("token [x].*", options)).toBe(true);
  expect(f.element.findPrevious("TOKEN [x].*", options)).toBe(false);
  expect(f.element.findNext("token x", options)).toBe(false);
  f.element.clearSearch();
  expect(f.write).not.toHaveBeenCalled();
});

it("localizes the labeled search and no-match state in Chinese", async () => {
  const f = await fixture();
  render(panel(f.element, vi.fn(), "zh-Hans"));
  expect(screen.getByRole("search", { name: "查找" })).toBeTruthy();
  await userEvent.type(screen.getByRole("textbox", { name: "查找终端输出" }), "missing");
  await userEvent.click(screen.getByRole("button", { name: "下一处" }));
  expect(screen.getByRole("status").textContent).toBe("保留的输出中没有匹配文字。");
  expect(screen.getByRole("button", { name: "关闭查找" })).toBeTruthy();
});
