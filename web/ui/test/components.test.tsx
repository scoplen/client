// SPDX-License-Identifier: Apache-2.0
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  Button,
  ChoiceList,
  HostEgg,
  Lockup,
  Mark,
  Notice,
  Pick,
  SearchField,
  Segmented,
  SkipLink,
  Toolbar,
  bodyPath,
} from "../src";
import { violations } from "./axe";

describe("Button", () => {
  it("is a button that does not submit forms unless asked", () => {
    render(<Button>Add host</Button>);
    expect(screen.getByRole("button", { name: "Add host" })).toHaveProperty("type", "button");
  });

  it("keeps its label and size while busy and reports it", () => {
    render(<Button busy>Connect</Button>);
    const button = screen.getByRole("button", { name: "Connect" });
    expect(button.getAttribute("aria-busy")).toBe("true");
    expect(button).toHaveProperty("disabled", true);
    expect(button.textContent).toBe("Connect");
  });

  it("does not run its action while busy or disabled", async () => {
    const onClick = vi.fn();
    render(
      <>
        <Button busy onClick={onClick}>
          One
        </Button>
        <Button disabled onClick={onClick}>
          Two
        </Button>
      </>,
    );
    await userEvent.click(screen.getByRole("button", { name: "One" }));
    await userEvent.click(screen.getByRole("button", { name: "Two" }));
    expect(onClick).not.toHaveBeenCalled();
  });
});

describe("Toolbar", () => {
  function Bar() {
    return (
      <Toolbar label="Session">
        <Button>Copy</Button>
        <Button disabled>Paste</Button>
        <Button>Find</Button>
        <Button>Split</Button>
      </Toolbar>
    );
  }

  it("is one Tab stop", async () => {
    render(
      <>
        <Bar />
        <Button>After</Button>
      </>,
    );
    await userEvent.tab();
    expect(document.activeElement?.textContent).toBe("Copy");
    await userEvent.tab();
    expect(document.activeElement?.textContent).toBe("After");
  });

  it("moves with arrows, Home, and End, skipping disabled controls and wrapping", async () => {
    render(<Bar />);
    await userEvent.tab();
    await userEvent.keyboard("{ArrowRight}");
    expect(document.activeElement?.textContent).toBe("Find");
    await userEvent.keyboard("{End}");
    expect(document.activeElement?.textContent).toBe("Split");
    await userEvent.keyboard("{ArrowRight}");
    expect(document.activeElement?.textContent).toBe("Copy");
    await userEvent.keyboard("{ArrowLeft}");
    expect(document.activeElement?.textContent).toBe("Split");
    await userEvent.keyboard("{Home}");
    expect(document.activeElement?.textContent).toBe("Copy");
  });

  it("returns Tab to the control that last had focus", async () => {
    render(
      <>
        <Button>Before</Button>
        <Bar />
      </>,
    );
    await userEvent.tab();
    await userEvent.tab();
    await userEvent.keyboard("{ArrowRight}");
    await userEvent.tab({ shift: true });
    expect(document.activeElement?.textContent).toBe("Before");
    await userEvent.tab();
    expect(document.activeElement?.textContent).toBe("Find");
  });

  it("is named and oriented for assistive technology", () => {
    render(<Bar />);
    const toolbar = screen.getByRole("toolbar", { name: "Session" });
    expect(toolbar.getAttribute("aria-orientation")).toBe("horizontal");
  });
});

describe("Mark", () => {
  it("is decorative unless named", () => {
    const { container } = render(<Mark />);
    expect(container.querySelector("svg")?.getAttribute("aria-hidden")).toBe("true");
    render(<Mark title="Scoplen" />);
    expect(screen.getByRole("img", { name: "Scoplen" })).toBeTruthy();
  });

  it("follows the geometry of the visual identity", () => {
    expect(bodyPath()).toBe(
      "M32 7C46 7 57 20.08 57 36.07C57 48.35 46 58 32 58C18 58 7 48.35 7 36.07C7 20.08 18 7 32 7Z",
    );
    const { container } = render(<Mark />);
    expect(container.querySelector("svg")?.getAttribute("viewBox")).toBe("0 0 64 64");
    expect(container.querySelectorAll("[data-eye]")).toHaveLength(2);
  });

  it("shows its mood on its face", () => {
    const { container, rerender } = render(<Mark />);
    expect(container.querySelector("svg")?.dataset.mood).toBe("rest");
    rerender(<Mark mood="closed" />);
    expect(container.querySelector("svg")?.dataset.mood).toBe("closed");
  });

  it("gives each host a stable pose and stays decorative", () => {
    const first = render(<HostEgg seed="host-1" />).container.innerHTML;
    const again = render(<HostEgg seed="host-1" />).container.innerHTML;
    expect(again.replace(/scoplen-eyes-[^")]+/g, "")).toBe(first.replace(/scoplen-eyes-[^")]+/g, ""));
    expect(
      render(<HostEgg seed="x" />)
        .container.querySelector("svg")
        ?.getAttribute("aria-hidden"),
    ).toBe("true");
  });
});

describe("accessibility", () => {
  it("has no axe violations in a composed screen", async () => {
    const { container } = render(
      <div>
        <SkipLink target="main">Skip to content</SkipLink>
        <header>
          <Lockup />
        </header>
        <main id="main">
          <h1>Hosts</h1>
          <Toolbar label="Actions">
            <Button variant="primary">Add host</Button>
            <Button variant="ghost">Import</Button>
          </Toolbar>
        </main>
      </div>,
    );
    expect(await violations(container)).toEqual([]);
  });
});

describe("Pick", () => {
  it("is decorative", () => {
    const { container } = render(
      <div className="relative">
        <Pick />
      </div>,
    );
    expect(container.querySelector("[aria-hidden=true]")).toBeTruthy();
  });
});

describe("Segmented and ChoiceList", () => {
  it("are radio groups that change with the arrow keys", async () => {
    const onChange = vi.fn();
    render(
      <Segmented
        legend="Sign in with"
        value="password"
        onChange={onChange}
        options={[
          { value: "password", label: "Password" },
          { value: "key", label: "Key" },
        ]}
      />,
    );
    const group = screen.getByRole("group", { name: "Sign in with" });
    expect(group).toBeTruthy();
    await userEvent.click(screen.getByRole("radio", { name: "Password" }));
    await userEvent.keyboard("{ArrowRight}");
    expect(onChange).toHaveBeenLastCalledWith("key");
  });

  it("describe each choice with the label", () => {
    render(
      <ChoiceList
        legend="Which key"
        value="file"
        onChange={() => {}}
        choices={[{ value: "file", label: "A key file", description: "Such as id_ed25519." }]}
      />,
    );
    expect(screen.getByRole("radio", { name: /A key file/ })).toHaveProperty("checked", true);
    expect(screen.getByText("Such as id_ed25519.")).toBeTruthy();
  });
});

describe("SearchField", () => {
  it("clears with Escape and with its button", async () => {
    const onChange = vi.fn();
    const { rerender } = render(<SearchField label="Search hosts" clearLabel="Clear" value="db" onChange={onChange} />);
    await userEvent.click(screen.getByRole("searchbox", { name: "Search hosts" }));
    await userEvent.keyboard("{Escape}");
    expect(onChange).toHaveBeenLastCalledWith("");
    onChange.mockClear();
    await userEvent.click(screen.getByRole("button", { name: "Clear" }));
    expect(onChange).toHaveBeenLastCalledWith("");
    rerender(<SearchField label="Search hosts" clearLabel="Clear" value="" onChange={onChange} />);
    expect(screen.queryByRole("button", { name: "Clear" })).toBeNull();
  });
});

describe("Notice", () => {
  it("announces, offers its action, and goes away", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const onDismiss = vi.fn();
    const onAction = vi.fn();
    render(
      <Notice message="Deleted nas." action={{ label: "Undo", onAction }} onDismiss={onDismiss} duration={1000} />,
    );
    expect(screen.getByRole("status").textContent).toContain("Deleted nas.");
    await userEvent.click(screen.getByRole("button", { name: "Undo" }));
    expect(onAction).toHaveBeenCalled();
    screen.getByRole("button", { name: "Undo" }).blur();
    await vi.advanceTimersByTimeAsync(1100);
    expect(onDismiss).toHaveBeenCalled();
    vi.useRealTimers();
  });
});
