// SPDX-License-Identifier: Apache-2.0
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import type {
  TeamAuthoringCollection,
  TeamAuthoringCreateView,
  TeamAuthoringData,
  TeamAuthoringResourceView,
} from "../src/ipc/bindings";
import { TeamAuthoring } from "../src/team-authoring";
import { TeamAuthoringFields, emptyTeamData } from "../src/team-authoring-fields";
import { violations } from "../../ui/test/axe";

const commands = vi.hoisted(() => ({
  teamAuthoringPage: vi.fn(),
  teamAuthoringResource: vi.fn(),
  pendingTeamAuthoring: vi.fn(),
  prepareTeamAuthoring: vi.fn(),
  submitTeamAuthoring: vi.fn(),
  discardTeamAuthoring: vi.fn(),
  updateTeamAuthoring: vi.fn(),
  deleteTeamAuthoring: vi.fn(),
  previewTeamSimpleRule: vi.fn(),
  teamMembers: vi.fn(),
}));
vi.mock("../src/account-profiles", () => ({ useProfileCommands: () => commands }));
const team = { id: "0199a653-8392-7355-8b91-70ab85182e30", name: "Operations", roles: ["owner"] };
const source = {
  origin: "https://sync.example",
  accountId: "0199a653-8392-7355-8b91-70ab85182e31",
  organizationId: team.id,
};
const host: TeamAuthoringResourceView = {
  ...source,
  id: "0199a653-8392-7355-8b91-70ab85182e32",
  etag: '"listed"',
  createdAt: "2026-10-26T00:00:00Z",
  updatedAt: "2026-10-26T00:00:00Z",
  readOnly: false,
  trustAttribution: null,
  data: { kind: "host", fields: { name: "Production", address: "host.example", port: 22 } },
};
const pending: TeamAuthoringCreateView = {
  ...source,
  operationId: "0199a653-8392-7355-8b91-70ab85182e33",
  resourceId: host.id,
  phase: "prepared",
  data: host.data,
};
const member = {
  id: "0199a653-8392-7355-8b91-70ab85182e34",
  organizationId: team.id,
  etag: '"member"',
  username: "alex",
  status: "active",
  roles: ["member"],
  isSelf: false,
};

beforeEach(() => {
  vi.resetAllMocks();
  commands.pendingTeamAuthoring.mockResolvedValue({ status: "ok", data: null });
  commands.teamAuthoringPage.mockImplementation((_team, collection) =>
    Promise.resolve({
      status: "ok",
      data: { ...source, collection, items: collection === "host" ? [host] : [], nextCursor: null },
    }),
  );
  commands.teamAuthoringResource.mockResolvedValue({ status: "ok", data: { ...host, etag: '"captured"' } });
  commands.prepareTeamAuthoring.mockResolvedValue({ status: "ok", data: pending });
  commands.submitTeamAuthoring.mockResolvedValue({ status: "ok", data: { ...pending, phase: "confirmed" } });
  commands.discardTeamAuthoring.mockResolvedValue({ status: "ok", data: null });
  commands.updateTeamAuthoring.mockResolvedValue({ status: "ok", data: { ...host, etag: '"updated"' } });
  commands.deleteTeamAuthoring.mockResolvedValue({ status: "ok", data: null });
  commands.teamMembers.mockResolvedValue({ status: "ok", data: { items: [member], nextCursor: null } });
  commands.previewTeamSimpleRule.mockResolvedValue({
    status: "ok",
    data: { source: 'permit(principal, action == Action::"view", resource);', dependencies: [] },
  });
});
afterEach(cleanup);

function fixture(section: "assets" | "access" = "assets") {
  return render(
    <I18nProvider locale="en">
      <TeamAuthoring team={team} section={section} onClose={vi.fn()} />
    </I18nProvider>,
  );
}
async function loaded() {
  await waitFor(() =>
    expect((screen.getByRole("button", { name: "Refresh and review" }) as HTMLButtonElement).disabled).toBe(false),
  );
}

it("creates ordinary named fields and submits only the durably prepared operation", async () => {
  fixture();
  await loaded();
  await userEvent.click(screen.getByRole("button", { name: "Create Host" }));
  expect(document.activeElement).toBe(screen.getByRole("textbox", { name: "Name" }));
  await userEvent.type(screen.getByRole("textbox", { name: "Name" }), " Team host ");
  await userEvent.type(screen.getByRole("textbox", { name: "Address" }), "server.example");
  expect(screen.queryByRole("textbox", { name: /json/i })).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Create resource" }));
  expect(await screen.findByText("The server confirmed the original creation request.")).toBeTruthy();
  expect(commands.prepareTeamAuthoring).toHaveBeenCalledExactlyOnceWith(team.id, {
    kind: "host",
    fields: { name: " Team host ", address: "server.example", port: 22 },
  });
  expect(commands.submitTeamAuthoring).toHaveBeenCalledExactlyOnceWith(team.id, pending.operationId);
});

it("returns keyboard focus to the recreated create action after cancel", async () => {
  fixture();
  await loaded();
  await userEvent.click(screen.getByRole("button", { name: "Create Host" }));
  await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(document.activeElement).toBe(screen.getByRole("button", { name: "Create Host" }));
});

it("retains uncertain creation and requires an explicit confirmation of its exact original operation", async () => {
  commands.pendingTeamAuthoring.mockResolvedValue({ status: "ok", data: { ...pending, phase: "unknown" } });
  fixture();
  await loaded();
  expect((screen.getByRole("button", { name: "Create Host" }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.queryByRole("button", { name: "Discard saved request" })).toBeNull();
  expect(commands.submitTeamAuthoring).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Confirm original request" }));
  expect(await screen.findByRole("button", { name: "Done" })).toBeTruthy();
  expect(commands.submitTeamAuthoring).toHaveBeenCalledExactlyOnceWith(team.id, pending.operationId);
  expect(commands.prepareTeamAuthoring).not.toHaveBeenCalled();
});

it("never enables new creates when retained state could not be read", async () => {
  commands.pendingTeamAuthoring.mockResolvedValue({ status: "error", error: "storage" });
  fixture();
  await loaded();
  expect((screen.getByRole("button", { name: "Create Host" }) as HTMLButtonElement).disabled).toBe(true);
  commands.pendingTeamAuthoring.mockResolvedValue({ status: "ok", data: null });
  await userEvent.click(screen.getByRole("button", { name: "Refresh and review" }));
  await waitFor(() =>
    expect((screen.getByRole("button", { name: "Create Host" }) as HTMLButtonElement).disabled).toBe(false),
  );
});

it("withdraws a previously readable directory when a current refresh denies access", async () => {
  fixture();
  await loaded();
  expect(screen.getByText("Production")).toBeTruthy();
  commands.teamAuthoringPage.mockResolvedValue({ status: "error", error: "permissionDenied" });
  await userEvent.click(screen.getByRole("button", { name: "Refresh and review" }));
  expect((await screen.findByRole("alert")).textContent).toContain("Ask a team administrator");
  expect(screen.queryByText("Production")).toBeNull();
});

it.each(["authoringConflict", "authoringUnknown"])(
  "requires an explicit fresh read after %s and uses the captured ETag",
  async (error) => {
    commands.updateTeamAuthoring.mockResolvedValueOnce({ status: "error", error });
    fixture();
    await loaded();
    await userEvent.click(screen.getByRole("button", { name: "Edit Production" }));
    await userEvent.clear(screen.getByRole("textbox", { name: "Address" }));
    await userEvent.type(screen.getByRole("textbox", { name: "Address" }), "replacement.example");
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect((screen.getByRole("button", { name: "Save changes" }) as HTMLButtonElement).disabled).toBe(true),
    );
    expect(commands.updateTeamAuthoring).toHaveBeenCalledExactlyOnceWith(team.id, host.id, '"captured"', {
      ...host.data,
      fields: { ...host.data.fields, address: "replacement.example" },
    });
    expect(commands.teamAuthoringResource).toHaveBeenCalledTimes(1);
    commands.teamAuthoringResource.mockResolvedValue({ status: "ok", data: { ...host, etag: '"reviewed"' } });
    await userEvent.click(screen.getByRole("button", { name: "Refresh and review" }));
    await waitFor(() =>
      expect((screen.getByRole("button", { name: "Save changes" }) as HTMLButtonElement).disabled).toBe(false),
    );
    expect((screen.getByRole("textbox", { name: "Address" }) as HTMLInputElement).value).toBe("host.example");
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await screen.findByText("Team resource saved.");
    expect(commands.updateTeamAuthoring.mock.calls[1]?.[2]).toBe('"reviewed"');
  },
);

it("blocks a second delete after an IPC promise fails until the user explicitly reads the resource again", async () => {
  commands.deleteTeamAuthoring.mockRejectedValue(new Error("lost invocation"));
  fixture();
  await loaded();
  await userEvent.click(screen.getByRole("button", { name: "Delete Production" }));
  const confirm = await screen.findByRole("button", { name: "Delete Production" });
  await userEvent.click(confirm);
  await waitFor(() => expect((confirm as HTMLButtonElement).disabled).toBe(true));
  expect(commands.deleteTeamAuthoring).toHaveBeenCalledExactlyOnceWith(team.id, "host", host.id, '"captured"');
  expect(commands.teamAuthoringResource).toHaveBeenCalledTimes(1);
});

it("uses the shared rule preview with Membership ids and does not implicitly grant referenced assets", async () => {
  fixture("access");
  await loaded();
  await userEvent.click(screen.getByRole("button", { name: "Create access rule" }));
  await userEvent.type(screen.getByRole("textbox", { name: "Rule name" }), "Team view");
  await userEvent.selectOptions(screen.getByRole("combobox", { name: "Member" }), member.id);
  await userEvent.click(await screen.findByRole("checkbox", { name: "Production" }));
  await userEvent.click(screen.getByRole("button", { name: "Preview rule" }));
  expect(await screen.findByText(/Each referenced asset needs its own view permission/)).toBeTruthy();
  expect(commands.previewTeamSimpleRule).toHaveBeenCalledExactlyOnceWith(team.id, {
    membershipId: member.id,
    groupId: null,
    permission: "view",
    remoteUser: null,
    resources: [{ collection: "host", id: host.id }],
  });
  const sourceInput = screen.getByRole("textbox", { name: "Cedar source" }) as HTMLTextAreaElement;
  expect(sourceInput.readOnly).toBe(true);
  await userEvent.click(screen.getByRole("button", { name: "Create resource" }));
  await screen.findByText("The server confirmed the original creation request.");
  expect(commands.prepareTeamAuthoring).toHaveBeenCalledWith(team.id, {
    kind: "policy",
    fields: { name: "Team view", source: sourceInput.value, enabled: true },
  });
});

it("keeps identity-provider groups read-only even when the user has an administrative role", async () => {
  const group = {
    ...host,
    readOnly: true,
    data: { kind: "group", fields: { name: "Identity operators", members: [member.id] } },
  };
  commands.teamAuthoringPage.mockResolvedValue({
    status: "ok",
    data: { ...source, collection: "group", items: [group], nextCursor: null },
  });
  commands.teamAuthoringResource.mockResolvedValue({ status: "ok", data: group });
  fixture("access");
  await loaded();
  await userEvent.selectOptions(screen.getByRole("combobox", { name: "Asset type" }), "group");
  await userEvent.click(await screen.findByRole("button", { name: "Edit Identity operators" }));
  expect((screen.getByRole("button", { name: "Save changes" }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByRole("textbox", { name: "Name" }).matches(":disabled")).toBe(true);
  expect(screen.queryByRole("button", { name: "Delete Identity operators" })).toBeNull();
});

it("ignores late account-bound results after unmount", async () => {
  let resolve!: (result: unknown) => void;
  commands.teamAuthoringPage.mockImplementation(
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  const rendered = fixture();
  await waitFor(() => expect(commands.teamAuthoringPage).toHaveBeenCalledTimes(1));
  rendered.unmount();
  await act(async () =>
    resolve({ status: "ok", data: { ...source, collection: "host", items: [host], nextCursor: null } }),
  );
  expect(screen.queryByText("Production")).toBeNull();
});

it("supports ordinary forms for all team collections and preserves exact form values", async () => {
  for (const kind of [
    "host",
    "login",
    "route",
    "hostGroup",
    "trustRecord",
    "snippet",
    "gatewayNetwork",
    "group",
    "policy",
  ] as TeamAuthoringCollection[]) {
    const change = vi.fn();
    const rendered = render(
      <I18nProvider locale="en">
        <TeamAuthoringFields
          data={emptyTeamData(kind)}
          onChange={change}
          references={{}}
          loadMore={vi.fn()}
          members={[member]}
          moreMembers={false}
          loadMembers={vi.fn()}
          onValid={vi.fn()}
        />
      </I18nProvider>,
    );
    expect(screen.queryByRole("textbox", { name: /json/i })).toBeNull();
    const name = screen.queryByRole("textbox", { name: "Name" });
    if (name) {
      await userEvent.type(name, " ");
      expect(change).toHaveBeenLastCalledWith(
        expect.objectContaining({ fields: expect.objectContaining({ name: " " }) }),
      );
    }
    if (kind === "group") {
      await userEvent.click(screen.getByRole("checkbox", { name: "alex" }));
      expect(change).toHaveBeenLastCalledWith({ kind, fields: { name: "", members: [member.id] } });
    }
    if (kind === "host") expect(await violations(rendered.container)).toEqual([]);
    rendered.unmount();
  }
});

it("renders a nullable snippet default as absent", () => {
  render(
    <I18nProvider locale="en">
      <TeamAuthoringFields
        data={{
          kind: "snippet",
          fields: {
            name: "Run",
            template: "echo",
            variables: { argument: { kind: 1, default: null, choices: null } },
            tags: null,
            folder: null,
          },
        }}
        onChange={vi.fn()}
        references={{}}
        loadMore={vi.fn()}
        members={[]}
        moreMembers={false}
        loadMembers={vi.fn()}
        onValid={vi.fn()}
      />
    </I18nProvider>,
  );
  expect((screen.getByRole("checkbox", { name: "Default value" }) as HTMLInputElement).checked).toBe(false);
  expect(screen.queryByRole("textbox", { name: "Default value" })).toBeNull();
});

it("removes a snippet default when changing its variable to secret input", async () => {
  let data: TeamAuthoringData = {
    kind: "snippet",
    fields: { name: "Run", template: "echo", variables: { argument: { kind: 1, default: "value" } } },
  };
  const change = vi.fn((next: TeamAuthoringData) => {
    data = next;
  });
  render(
    <I18nProvider locale="en">
      <TeamAuthoringFields
        data={data}
        onChange={change}
        references={{}}
        loadMore={vi.fn()}
        members={[]}
        moreMembers={false}
        loadMembers={vi.fn()}
        onValid={vi.fn()}
      />
    </I18nProvider>,
  );
  await userEvent.selectOptions(screen.getByRole("combobox", { name: "Variable type" }), "4");
  expect(change).toHaveBeenLastCalledWith({
    kind: "snippet",
    fields: { name: "Run", template: "echo", variables: { argument: { kind: 4 } } },
  });
  expect(screen.queryByRole("textbox", { name: "Default value" })).toBeNull();
});

it("requires a unique nonempty map key before saving", async () => {
  fixture();
  await loaded();
  await userEvent.click(screen.getByRole("button", { name: "Create Host" }));
  const tags = screen.getByRole("group", { name: "Tags" });
  await userEvent.click(within(tags).getByRole("button", { name: "Add entry" }));
  expect((screen.getByRole("button", { name: "Create resource" }) as HTMLButtonElement).disabled).toBe(true);
  await userEvent.type(within(tags).getByRole("textbox", { name: "Key 1" }), "environment");
  expect((screen.getByRole("button", { name: "Create resource" }) as HTMLButtonElement).disabled).toBe(false);
});
