// SPDX-License-Identifier: Apache-2.0
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import { TeamSshSetup } from "../src/team-ssh-setup";
import { violations } from "../../ui/test/axe";

const commands = vi.hoisted(() => ({
  teamAssets: vi.fn(),
  teamSshOperations: vi.fn(),
  teamUserCa: vi.fn(),
  prepareTeamUserCa: vi.fn(),
  confirmTeamSshOperation: vi.fn(),
  discardTeamSshOperation: vi.fn(),
}));
vi.mock("../src/account-profiles", () => ({ useProfileCommands: () => commands }));
const team = { id: "0199a653-8392-7355-8b91-70ab85182e30", name: "Operations", roles: ["owner"] };
const source = {
  origin: "https://sync.example",
  accountId: "0199a653-8392-7355-8b91-70ab85182e31",
  organizationId: team.id,
  deviceId: "0199a653-8392-7355-8b91-70ab85182e32",
};
const ca = {
  source,
  id: "0199a653-8392-7355-8b91-70ab85182e33",
  publicKey: "ssh-ed25519 fixture-public-key",
  fingerprint: "SHA256:fixture",
  setups: [],
};
const operation = {
  source,
  operationId: "0199a653-8392-7355-8b91-70ab85182e34",
  kind: "userCa",
  phase: "prepared",
  retryUntil: null,
  hostId: null,
  remoteUser: null,
};
beforeEach(() => {
  vi.resetAllMocks();
  commands.teamAssets.mockResolvedValue({ status: "ok", data: { ...source, phase: "notLoaded", assets: [] } });
  commands.teamSshOperations.mockResolvedValue({ status: "ok", data: [] });
  commands.teamUserCa.mockResolvedValue({ status: "ok", data: ca });
  commands.prepareTeamUserCa.mockResolvedValue({ status: "ok", data: operation });
  commands.confirmTeamSshOperation.mockResolvedValue({ status: "ok", data: { ...operation, phase: "confirmed" } });
  commands.discardTeamSshOperation.mockResolvedValue({ status: "ok", data: null });
});
afterEach(cleanup);
function fixture() {
  return render(
    <I18nProvider locale="en">
      <TeamSshSetup team={team} onClose={vi.fn()} />
    </I18nProvider>,
  );
}
async function loaded() {
  await waitFor(() =>
    expect((screen.getByRole("button", { name: "Refresh and review" }) as HTMLButtonElement).disabled).toBe(false),
  );
}

it("shows the actual authenticated CA and manual configuration guidance without creating one", async () => {
  const rendered = fixture();
  await loaded();
  expect((screen.getByRole("textbox", { name: "CA public key" }) as HTMLTextAreaElement).value).toBe(ca.publicKey);
  expect(screen.getByText(/sshd -t/)).toBeTruthy();
  expect(commands.teamUserCa).toHaveBeenCalledExactlyOnceWith(source);
  expect(commands.prepareTeamUserCa).not.toHaveBeenCalled();
  expect(commands.confirmTeamSshOperation).not.toHaveBeenCalled();
  expect(await violations(rendered.container)).toEqual([]);
});

it("renders the exact native scoped principal and sshd configuration for the selected visible Login", async () => {
  const setup = {
    profileId: "0199a653-8392-7355-8b91-70ab85182e35",
    hostId: "0199a653-8392-7355-8b91-70ab85182e36",
    remoteUser: "deploy",
    principal: "native-exact-scoped-principal",
    caFile: "/etc/ssh/scoplen_user_ca_keys",
    principalsFile: ".ssh/scoplen_principals",
    sshdConfig: "TrustedUserCAKeys /etc/ssh/scoplen_user_ca_keys\nAuthorizedPrincipalsFile .ssh/scoplen_principals",
  };
  commands.teamUserCa.mockResolvedValue({ status: "ok", data: { ...ca, setups: [setup] } });
  fixture();
  await loaded();
  expect((screen.getByRole("textbox", { name: "Exact authorized principal" }) as HTMLTextAreaElement).value).toBe(
    setup.principal,
  );
  expect((screen.getByRole("textbox", { name: "sshd configuration" }) as HTMLTextAreaElement).value).toBe(
    setup.sshdConfig,
  );
  expect(screen.getByText(setup.hostId)).toBeTruthy();
  expect(screen.getByText(setup.principalsFile)).toBeTruthy();
});

it("creates with the original native preparation and exact selected source only after an explicit intent", async () => {
  commands.teamUserCa.mockResolvedValueOnce({ status: "ok", data: null });
  commands.teamSshOperations
    .mockResolvedValueOnce({ status: "ok", data: [] })
    .mockResolvedValue({ status: "ok", data: [{ ...operation, phase: "confirmed" }] });
  fixture();
  await loaded();
  await userEvent.click(screen.getByRole("button", { name: "Create team user CA" }));
  expect(await screen.findByRole("textbox", { name: "CA public key" })).toBeTruthy();
  expect(commands.prepareTeamUserCa).toHaveBeenCalledExactlyOnceWith(source);
  expect(commands.confirmTeamSshOperation).toHaveBeenCalledExactlyOnceWith(source, "userCa", operation.operationId);
});

it("retains unknown issuance and confirms only its original id without automatically connecting or preparing", async () => {
  const issuance = {
    ...operation,
    kind: "certificate",
    phase: "unknown",
    hostId: "0199a653-8392-7355-8b91-70ab85182e35",
    remoteUser: "deploy",
  };
  commands.teamSshOperations.mockResolvedValue({ status: "ok", data: [issuance] });
  fixture();
  await loaded();
  expect(screen.queryByRole("button", { name: "Discard saved request" })).toBeNull();
  expect(commands.confirmTeamSshOperation).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Confirm original request" }));
  await waitFor(() =>
    expect(commands.confirmTeamSshOperation).toHaveBeenCalledExactlyOnceWith(
      source,
      "certificate",
      operation.operationId,
    ),
  );
  expect(commands.prepareTeamUserCa).not.toHaveBeenCalled();
});

it("requires explicit successful refresh before archiving expired uncertainty", async () => {
  commands.teamSshOperations.mockResolvedValue({ status: "ok", data: [{ ...operation, phase: "expired" }] });
  fixture();
  await loaded();
  const archive = screen.getByRole("button", { name: "Archive reviewed request" }) as HTMLButtonElement;
  expect(archive.disabled).toBe(true);
  await userEvent.click(screen.getByRole("button", { name: "Refresh and review" }));
  await waitFor(() => expect(archive.disabled).toBe(false));
  await userEvent.click(archive);
  expect(commands.discardTeamSshOperation).toHaveBeenCalledExactlyOnceWith(source, "userCa", operation.operationId);
});

it("keeps creation unavailable when local recovery state cannot be read", async () => {
  commands.teamSshOperations.mockResolvedValue({ status: "error", error: "storage" });
  fixture();
  await loaded();
  expect(screen.getByRole("alert")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Create team user CA" })).toBeNull();
  expect(commands.teamUserCa).not.toHaveBeenCalled();
});

it("ignores late results when the selected team's setup closes", async () => {
  let finish!: (result: unknown) => void;
  commands.teamUserCa.mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const rendered = fixture();
  await waitFor(() => expect(commands.teamUserCa).toHaveBeenCalledTimes(1));
  rendered.unmount();
  await act(async () => finish({ status: "ok", data: ca }));
  expect(screen.queryByRole("textbox", { name: "CA public key" })).toBeNull();
});
