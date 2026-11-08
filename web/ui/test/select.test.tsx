// SPDX-License-Identifier: Apache-2.0
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { Button, Select } from "../src";
import { violations } from "./axe";

const options = [
  { value: "", label: "Local" },
  { value: "work", label: "Work account" },
  { value: "locked", label: "Unavailable account", disabled: true },
];

describe("Select", () => {
  it("selects by keyboard, refuses disabled options and returns focus", async () => {
    const onValueChange = vi.fn();
    function Example() {
      const [value, setValue] = useState("");
      return (
        <Select
          label="Open profile"
          options={options}
          value={value}
          onValueChange={(next) => {
            onValueChange(next);
            setValue(next);
          }}
        />
      );
    }
    render(<Example />);
    const trigger = screen.getByRole("combobox", { name: "Open profile" });
    expect(trigger.tagName).toBe("BUTTON");
    await userEvent.tab();
    expect(document.activeElement).toBe(trigger);
    await userEvent.keyboard("{ArrowDown}");
    await screen.findByRole("listbox", { name: "Open profile" });
    await userEvent.keyboard("{End}{Enter}");
    expect(onValueChange).not.toHaveBeenCalled();
    await userEvent.keyboard("{ArrowUp}{Enter}");
    expect(onValueChange).toHaveBeenCalledExactlyOnceWith("work");
    await waitFor(() => expect(screen.queryByRole("listbox")).toBeNull());
    expect(trigger.textContent).toBe("Work account");
    await waitFor(() => expect(document.activeElement).toBe(trigger));
  });

  it("supports typeahead and the empty-string option", async () => {
    const onValueChange = vi.fn();
    render(<Select label="Open profile" options={options} value="work" onValueChange={onValueChange} />);
    await userEvent.click(screen.getByRole("combobox"));
    await screen.findByRole("listbox");
    await userEvent.keyboard("Local{Enter}");
    expect(onValueChange).toHaveBeenCalledExactlyOnceWith("");
  });

  it("cancels by Escape and treats the current selection as a no-op", async () => {
    const onValueChange = vi.fn();
    render(<Select label="Open profile" options={options} value="" onValueChange={onValueChange} />);
    const trigger = screen.getByRole("combobox");
    await userEvent.click(trigger);
    await screen.findByRole("listbox");
    await userEvent.keyboard("{End}{Escape}");
    await waitFor(() => expect(screen.queryByRole("listbox")).toBeNull());
    await waitFor(() => expect(document.activeElement).toBe(trigger));
    expect(onValueChange).not.toHaveBeenCalled();
    await userEvent.click(trigger);
    await userEvent.click(await screen.findByRole("option", { name: "Local" }));
    expect(onValueChange).not.toHaveBeenCalled();
  });

  it("cannot open while disabled and is skipped in the Tab order", async () => {
    const onValueChange = vi.fn();
    render(
      <>
        <Select label="Open profile" options={options} value="" onValueChange={onValueChange} disabled />
        <Button>After</Button>
      </>,
    );
    expect(screen.getByRole("combobox")).toHaveProperty("disabled", true);
    await userEvent.click(screen.getByRole("combobox"));
    await userEvent.tab();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "After" }));
    expect(screen.queryByRole("listbox")).toBeNull();
    expect(onValueChange).not.toHaveBeenCalled();
  });

  it("keeps focus on an outside control when that control closes the popup", async () => {
    render(
      <>
        <Select label="Identity" options={options} value="" onValueChange={() => {}} />
        <Button>After</Button>
      </>,
    );
    await userEvent.click(screen.getByRole("combobox"));
    await screen.findByRole("listbox");
    const after = screen.getByRole("button", { name: "After" });
    await userEvent.click(after);
    await waitFor(() => expect(screen.queryByRole("listbox")).toBeNull());
    await waitFor(() => expect(document.activeElement).toBe(after));
  });

  it.each([false, true])(
    "restores focus after an asynchronous choice without stealing another control's focus (%s)",
    async (moveFocus) => {
      let complete!: () => void;
      const pending = new Promise<void>((resolve) => {
        complete = resolve;
      });
      function Example() {
        const [value, setValue] = useState("");
        const [busy, setBusy] = useState(false);
        return (
          <>
            <Select
              label="Identity"
              options={options}
              value={value}
              disabled={busy}
              onValueChange={(next) => {
                setValue(next);
                setBusy(true);
                void pending.then(() => setBusy(false));
              }}
            />
            <Button>After</Button>
          </>
        );
      }
      render(<Example />);
      const trigger = screen.getByRole("combobox");
      await userEvent.click(trigger);
      await userEvent.click(await screen.findByRole("option", { name: "Work account" }));
      await waitFor(() => expect(trigger).toHaveProperty("disabled", true));
      const after = screen.getByRole("button", { name: "After" });
      if (moveFocus) await userEvent.click(after);
      await act(async () => complete());
      await waitFor(() => expect(trigger).toHaveProperty("disabled", false));
      await waitFor(() => expect(document.activeElement).toBe(moveFocus ? after : trigger));
    },
  );

  it("names the control and options for assistive technology", async () => {
    const { container } = render(<Select label="Open profile" options={options} value="" onValueChange={() => {}} />);
    expect(await violations(container)).toEqual([]);
    await userEvent.click(screen.getByRole("combobox"));
    const list = await screen.findByRole("listbox", { name: "Open profile" });
    expect(screen.getByRole("option", { name: "Local" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByRole("option", { name: "Unavailable account" }).getAttribute("aria-disabled")).toBe("true");
    expect(await violations(list)).toEqual([]);
  });

  it("retains field labels, required validation and named option groups", async () => {
    function Example() {
      const [value, setValue] = useState("");
      return (
        <form aria-label="Identity form">
          <label htmlFor="identity">Identity</label>
          <span id="identity-hint">Choose a saved identity.</span>
          <Select
            id="identity"
            label="Identity"
            aria-describedby="identity-hint"
            size="field"
            required
            value={value}
            onValueChange={setValue}
            options={[
              { value: "", label: "Choose identity" },
              { value: "file", label: "Key file", group: "Files" },
              { value: "saved", label: "Saved key", group: "Saved credentials" },
            ]}
          />
        </form>
      );
    }
    render(<Example />);
    const form = screen.getByRole("form") as HTMLFormElement;
    const trigger = screen.getByLabelText("Identity");
    expect(trigger.tagName).toBe("BUTTON");
    expect(trigger.getAttribute("aria-describedby")).toBe("identity-hint");
    expect(form.checkValidity()).toBe(false);
    await userEvent.click(trigger);
    const files = await screen.findByRole("group", { name: "Files" });
    expect(screen.getByRole("group", { name: "Saved credentials" })).toBeTruthy();
    expect(await violations(screen.getByRole("listbox"))).toEqual([]);
    await userEvent.click(within(files).getByRole("option", { name: "Key file" }));
    expect(trigger.textContent).toBe("Key file");
    expect(form.checkValidity()).toBe(true);
  });
});
