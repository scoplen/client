// SPDX-License-Identifier: Apache-2.0
//
// Sample data for the development gallery only. It follows the inventory
// contract (../inventory/api.ts) closely enough to exercise every screen
// state; it is not part of the application and never ships.

import type {
  AccessProfileInput,
  AccessProfileSummary,
  Areas,
  CredentialLabel,
  CredentialInput,
  CredentialSummary,
  EditHost,
  ForwardSummary,
  GroupSummary,
  GroupInput,
  HostDetails,
  HostSource,
  Id,
  InventoryApi,
  LoginSummary,
  NewHost,
  ObjectEditError,
  Outcome,
  RecentSession,
  RouteDefinition,
  RouteInput,
  RouteSummary,
  RecentSessionKind,
  RecentSessionOutcome,
} from "../inventory/api";

const groups: GroupSummary[] = [
  { id: "g-prod", name: "Production", parent: null, hostCount: 4 },
  { id: "g-prod-db", name: "Databases", parent: "g-prod", hostCount: 1 },
  { id: "g-staging", name: "Staging", parent: null, hostCount: 2 },
  { id: "g-home", name: "Home lab", parent: null, hostCount: 1 },
];

const laptopKey: CredentialLabel = {
  id: "c-laptop",
  kind: "key",
  name: "laptop",
  fingerprint: "SHA256:q3Vw8mJ0yR1cZp7nT5kLx9aD2fGh4sU6eB0iO3wQ1aM",
  comment: "mia@laptop",
  publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK7m3x0fQ8yT2w1cZp7nT5kLx9aD2fGh4sU6eB0iO3wQ",
};
const deployKey: CredentialLabel = {
  id: "c-deploy",
  kind: "key",
  name: null,
  fingerprint: "SHA256:Zt1o9Lq0bN3xV7cW2eR5yU8iP4aS6dF1gH0jK3lM9nB",
  comment: "deploy@ci",
  publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq9Lq0bN3xV7cW2eR5yU8iP4aS6dF1gH0jK3lM9nBz",
};
const agent: CredentialLabel = {
  id: "c-agent",
  kind: "agent",
  name: null,
  fingerprint: null,
  comment: null,
  publicKey: null,
};
const nasPassword: CredentialLabel = {
  id: "c-nas",
  kind: "password",
  name: null,
  fingerprint: null,
  comment: null,
  publicKey: null,
};

const sampleCredentialSeeds: CredentialSummary[] = [
  {
    id: laptopKey.id,
    name: laptopKey.name,
    kind: "key",
    binding: "shared",
    hasSecret: true,
    publicKey: laptopKey.publicKey,
    provider: {},
    certificateScope: null,
    profileCount: 0,
    routeCount: 0,
    restored: false,
  },
  {
    id: deployKey.id,
    name: deployKey.name,
    kind: "key",
    binding: "shared",
    hasSecret: true,
    publicKey: deployKey.publicKey,
    provider: {},
    certificateScope: null,
    profileCount: 0,
    routeCount: 0,
    restored: false,
  },
  {
    id: agent.id,
    name: agent.name,
    kind: "agent",
    binding: "none",
    hasSecret: false,
    publicKey: null,
    provider: {},
    certificateScope: null,
    profileCount: 0,
    routeCount: 0,
    restored: false,
  },
  {
    id: nasPassword.id,
    name: nasPassword.name,
    kind: "password",
    binding: "shared",
    hasSecret: true,
    publicKey: null,
    provider: {},
    certificateScope: null,
    profileCount: 0,
    routeCount: 0,
    restored: false,
  },
];

const sampleRouteSeeds: RouteSummary[] = [
  {
    id: "r-prod-jump",
    name: "prod-jump",
    definition: { kind: "jump", hops: ["l-4"] },
    profileCount: 0,
    orphaned: false,
    restored: false,
  },
  {
    id: "r-staging-net",
    name: "staging-net",
    definition: { kind: "managed", gatewayNetwork: "gw-staging-net" },
    profileCount: 0,
    orphaned: false,
    restored: false,
  },
];

const sampleForwardSeeds: ForwardSummary[] = [
  { id: "f-db", name: "postgres-prod", kind: "local", profile: "l-3" },
  { id: "f-socks", name: "staging-socks", kind: "dynamic", profile: null },
  { id: "f-remote", name: "metrics-remote", kind: "remote", profile: "l-5" },
];

function login(
  id: Id,
  username: string,
  credential: CredentialLabel | null,
  route: LoginSummary["route"],
  isDefault = true,
  name: string | null = null,
): LoginSummary {
  return { id, name, username, credential, route, isDefault };
}

function host(
  partial: Omit<HostDetails, "username" | "loginCount" | "route" | "restored"> & { restored?: boolean },
): HostDetails {
  const primary = partial.logins.find((l) => l.isDefault) ?? partial.logins[0];
  return {
    restored: false,
    ...partial,
    username: primary?.username ?? null,
    loginCount: partial.logins.length,
    route: primary?.route ?? { kind: "direct" },
  };
}

function routeIdForLabel(route: LoginSummary["route"]): Id | null {
  if (route.kind === "jump" && route.name === "prod-jump") return "r-prod-jump";
  if (route.kind === "bastion" && route.name === "staging-net") return "r-staging-net";
  return null;
}

function routeLabelForSummary(route: RouteSummary): LoginSummary["route"] {
  switch (route.definition.kind) {
    case "jump":
      return { kind: "jump", name: route.name };
    case "socks5":
    case "httpConnect":
      return { kind: "proxy", name: route.name };
    case "command":
      return { kind: "command", name: route.name };
    case "managed":
      return { kind: "bastion", name: route.name };
  }
}

function credentialLabelForSummary(summary: CredentialSummary | undefined): CredentialLabel | null {
  if (!summary) return null;
  const kind: CredentialLabel["kind"] = summary.kind;
  return { id: summary.id, kind, name: summary.name, fingerprint: null, comment: null, publicKey: summary.publicKey };
}

function profileSeeds(hosts: HostDetails[]): AccessProfileSummary[] {
  return hosts.flatMap((current) =>
    current.logins.map((loginSummary) => ({
      id: loginSummary.id,
      host: current.id,
      hostName: current.name,
      name: loginSummary.name,
      username: loginSummary.username,
      credential: loginSummary.credential,
      credentialId: loginSummary.credential?.id ?? null,
      route: loginSummary.route,
      routeId: routeIdForLabel(loginSummary.route),
      terminalProfile: null,
      startupCommand: null,
      agentForwarding: false,
      forwards: current.id === "h-db-1" ? ["f-db"] : current.id === "h-stg-web" ? ["f-remote"] : [],
      isDefault: loginSummary.isDefault,
      orphaned: false,
      restored: current.restored,
    })),
  );
}

function countedCredentials(
  credentials: CredentialSummary[],
  profiles: AccessProfileSummary[],
  routes: RouteSummary[],
): CredentialSummary[] {
  return credentials.map((credential) => ({
    ...credential,
    profileCount: profiles.filter((profile) => profile.credentialId === credential.id).length,
    routeCount: routes.filter((route) => {
      const definition = route.definition;
      return (
        (definition.kind === "socks5" || definition.kind === "httpConnect") && definition.credential === credential.id
      );
    }).length,
  }));
}

function countedRoutes(routes: RouteSummary[], profiles: AccessProfileSummary[]): RouteSummary[] {
  return routes.map((route) => ({
    ...route,
    profileCount: profiles.filter((profile) => profile.routeId === route.id).length,
  }));
}

function objectEditFailure(reference: string): Outcome<never, ObjectEditError> {
  return { status: "error", error: { kind: "failed", reference } };
}

const jump = { kind: "jump", name: "prod-jump" } as const;

const seededRecentSessions: RecentSession[] = [
  {
    id: "s-api-1",
    hostId: "h-api-1",
    hostName: "prod-api-01",
    address: "10.0.1.24",
    port: 22,
    username: "deploy",
    kind: "terminal",
    startedAt: String(Date.UTC(2026, 9, 7, 9, 15)),
    endedAt: String(Date.UTC(2026, 9, 7, 10, 2)),
    outcome: "closed",
  },
  {
    id: "s-db-1",
    hostId: "h-db-1",
    hostName: "prod-db-01",
    address: "10.0.4.12",
    port: 22,
    username: "dba",
    kind: "files",
    startedAt: String(Date.UTC(2026, 9, 6, 16, 40)),
    endedAt: null,
    outcome: null,
  },
];

export function sampleHosts(): HostDetails[] {
  return [
    host({
      id: "h-api-1",
      name: "prod-api-01",
      address: "10.0.1.24",
      port: 22,
      favorite: true,
      tags: { env: "production", region: "nrt" },
      groups: ["g-prod"],
      notes: "API node behind the public load balancer. Deploys go through CI.",
      logins: [
        login("l-1", "deploy", laptopKey, { kind: "direct" }),
        login("l-1b", "root", agent, { kind: "direct" }, false, "Break glass"),
      ],
    }),
    host({
      id: "h-api-2",
      name: "prod-api-02",
      address: "10.0.1.25",
      port: 22,
      favorite: false,
      tags: { env: "production", region: "nrt" },
      groups: ["g-prod"],
      notes: null,
      logins: [login("l-2", "deploy", laptopKey, { kind: "direct" })],
    }),
    host({
      id: "h-db-1",
      name: "prod-db-01",
      address: "10.0.4.12",
      port: 22,
      favorite: true,
      tags: { env: "production", role: "postgres" },
      groups: ["g-prod", "g-prod-db"],
      notes: null,
      logins: [login("l-3", "dba", laptopKey, jump)],
    }),
    host({
      id: "h-jump",
      name: "prod-jump",
      address: "jump.example.com",
      port: 2222,
      favorite: false,
      tags: { env: "production" },
      groups: ["g-prod"],
      notes: null,
      logins: [login("l-4", "mia", laptopKey, { kind: "direct" })],
    }),
    host({
      id: "h-stg-web",
      name: "staging-web",
      address: "staging.example.com",
      port: 22,
      favorite: false,
      tags: { env: "staging" },
      groups: ["g-staging"],
      notes: null,
      logins: [login("l-5", "deploy", deployKey, { kind: "direct" })],
    }),
    host({
      id: "h-stg-worker",
      name: "staging-worker-03",
      address: "10.20.3.7",
      port: 22,
      favorite: false,
      tags: { env: "staging", role: "queue" },
      groups: ["g-staging"],
      notes: null,
      logins: [login("l-6", "deploy", deployKey, { kind: "bastion", name: "staging-net" })],
      restored: true,
    }),
    host({
      id: "h-nas",
      name: "nas",
      address: "192.168.1.20",
      port: 22,
      favorite: false,
      tags: {},
      groups: ["g-home"],
      notes: "Synology. Admin interface on port 5001.",
      logins: [login("l-7", "admin", nasPassword, { kind: "direct" })],
    }),
  ];
}

const ok = <T>(data: T): Outcome<T, never> => ({ status: "ok", data });
const wait = <T>(value: T) => new Promise<T>((resolve) => setTimeout(() => resolve(value), 120));
const MAX_TEXT_BYTES = 16 * 1024;

function textBytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

/** An in-memory inventory for the gallery. */
export function sampleInventory(
  initial: HostDetails[],
  options: { failHosts?: boolean; failRecentSessions?: boolean } = {},
): InventoryApi {
  let hosts = initial.map((h) => ({ ...h }));
  let availableGroups = groups.map((group) => ({ ...group }));
  const sessions = seededRecentSessions.map((session) => ({ ...session }));
  const sessionProfiles = new Map<string, Id>([
    ["s-api-1", "l-1"],
    ["s-db-1", "l-3"],
  ]);
  let profiles = profileSeeds(hosts);
  let objectCredentials = sampleCredentialSeeds.map((credential) => ({
    ...credential,
    provider: { ...credential.provider },
  }));
  let objectRoutes = sampleRouteSeeds.map((route) => ({
    ...route,
    definition: { ...route.definition } as RouteDefinition,
  }));
  const objectForwards = sampleForwardSeeds.map((forward) => ({ ...forward }));
  let sessionSequence = 0;
  const deleted = new Map<string, HostDetails>();
  const listeners = new Set<() => void>();
  const changed = () => listeners.forEach((l) => l());
  const groupSummaries = () =>
    availableGroups.map((group) => ({
      ...group,
      hostCount: hosts.filter((host) => host.groups.includes(group.id)).length,
    }));
  const recentSessionRows = () =>
    sessions
      .filter((session) => hosts.some((host) => host.id === session.hostId))
      .map((session) => {
        const current = hosts.find((host) => host.id === session.hostId);
        return current
          ? {
              ...session,
              hostName: current.name,
              address: current.address,
              port: current.port,
              username: current.username ?? session.username,
            }
          : session;
      });
  const profileRows = () =>
    profiles.map((profile) => {
      const hostRecord = hosts.find((current) => current.id === profile.host);
      const credential = objectCredentials.find((item) => item.id === profile.credentialId);
      const route = objectRoutes.find((item) => item.id === profile.routeId);
      return {
        ...profile,
        hostName: hostRecord?.name ?? null,
        credential: credentialLabelForSummary(credential),
        route: profile.routeId ? (route ? routeLabelForSummary(route) : profile.route) : { kind: "direct" as const },
        orphaned:
          profile.orphaned ||
          !hostRecord ||
          Boolean(profile.credentialId && !credential) ||
          Boolean(profile.routeId && !route),
      };
    });
  const credentialRows = () => countedCredentials(objectCredentials, profileRows(), objectRoutes);
  const routeRows = () =>
    countedRoutes(objectRoutes, profileRows()).map((route) => {
      const definition = route.definition;
      const orphanedJump =
        definition.kind === "jump" && definition.hops.some((hop) => !profiles.some((profile) => profile.id === hop));
      const orphanedProxy =
        definition.kind === "socks5" || definition.kind === "httpConnect"
          ? Boolean(
              definition.credential && !objectCredentials.some((credential) => credential.id === definition.credential),
            )
          : false;
      return { ...route, orphaned: route.orphaned || orphanedJump || orphanedProxy };
    });

  const matches = (h: HostDetails, query: string) => {
    if (!query) return true;
    const q = query.toLowerCase();
    return [h.name, h.address, h.username ?? "", ...Object.entries(h.tags).map(([k, v]) => `${k}:${v}`)].some((field) =>
      field.toLowerCase().includes(q),
    );
  };
  const inSource = (h: HostDetails, source: HostSource) =>
    source.kind === "all" ||
    (source.kind === "favorites" && h.favorite) ||
    (source.kind === "recent" && recentSessionRows().some((session) => session.hostId === h.id)) ||
    (source.kind === "group" && h.groups.includes(source.id));

  return {
    areas: () =>
      wait(
        ok<Areas>({
          favorites: hosts.some((h) => h.favorite),
          recent: recentSessionRows().length > 0,
          groups: hosts.length > 0,
          keys: true,
          routes: true,
        }),
      ),
    groups: () => wait(ok(hosts.length > 0 ? groupSummaries() : [])),
    hosts: (source, query) =>
      options.failHosts
        ? wait({
            status: "error" as const,
            error: { kind: "failed" as const, reference: "the local store is busy: database is locked" },
          })
        : wait(
            ok(
              hosts
                .filter((h) => inSource(h, source) && matches(h, query))
                .sort((a, b) => Number(b.favorite) - Number(a.favorite) || a.name.localeCompare(b.name)),
            ),
          ),
    recentSessions: () =>
      options.failRecentSessions
        ? wait({
            status: "error" as const,
            error: { kind: "failed" as const, reference: "the local session history is unavailable" },
          })
        : wait(ok(recentSessionRows())),
    openSession: (profileId: string, kind: RecentSessionKind) => {
      const current = hosts.find((host) => host.logins.some((login) => login.id === profileId));
      const login = current?.logins.find((item) => item.id === profileId);
      if (!current || !login) {
        return wait({ status: "error" as const, error: { kind: "profileNotFound" as const } });
      }
      const now = String(Date.now());
      const session: RecentSession = {
        id: `s-gallery-${++sessionSequence}`,
        hostId: current.id,
        hostName: current.name,
        address: current.address,
        port: current.port,
        username: login.username,
        kind,
        startedAt: now,
        endedAt: null,
        outcome: null,
      };
      sessions.unshift(session);
      sessionProfiles.set(session.id, profileId);
      changed();
      return wait(ok(session));
    },
    closeSession: (id: string, outcome: RecentSessionOutcome) => {
      const index = sessions.findIndex((session) => session.id === id);
      if (index < 0) return wait({ status: "error" as const, error: { kind: "sessionNotFound" as const } });
      const current = sessions[index]!;
      if (current.outcome !== null)
        return wait({ status: "error" as const, error: { kind: "alreadyClosed" as const } });
      const updated = { ...current, endedAt: String(Date.now()), outcome };
      sessions[index] = updated;
      changed();
      return wait(ok(null));
    },
    reconnectSession: (id: string) => {
      const session = sessions.find((candidate) => candidate.id === id);
      if (!session) {
        return wait({ status: "error" as const, error: { kind: "sessionNotFound" as const } });
      }
      if (session.endedAt === null || session.outcome === null) {
        return wait({ status: "error" as const, error: { kind: "activeSession" as const } });
      }
      if (session.kind !== "terminal") {
        return wait({ status: "error" as const, error: { kind: "unsupportedSessionKind" as const } });
      }
      const profile = profiles.find((candidate) => candidate.id === sessionProfiles.get(id));
      const host = hosts.find((candidate) => candidate.id === profile?.host);
      if (!profile || !host) {
        return wait({ status: "error" as const, error: { kind: "profileNotFound" as const } });
      }
      return wait(ok({ profileId: profile.id, hostName: host.name, loginName: profile.name ?? profile.username }));
    },
    forgetSession: (id: string) => {
      const index = sessions.findIndex((session) => session.id === id);
      if (index < 0) return wait({ status: "error" as const, error: { kind: "sessionNotFound" as const } });
      if (sessions[index]!.outcome === null) {
        return wait({ status: "error" as const, error: { kind: "activeSession" as const } });
      }
      sessions.splice(index, 1);
      sessionProfiles.delete(id);
      changed();
      return wait(ok(null));
    },
    host: (id) => wait(ok(hosts.find((h) => h.id === id) ?? null)),
    addHost: (input: NewHost) => {
      if (!/^[a-z0-9.:\-[\]]+$/i.test(input.address))
        return wait({ status: "error" as const, error: { kind: "invalidAddress" as const } });
      if (input.signIn.kind === "keyText" && !input.signIn.key.includes("PRIVATE KEY")) {
        return wait({
          status: "error" as const,
          error: { kind: input.signIn.key.startsWith("ssh-") ? ("publicKey" as const) : ("notAPrivateKey" as const) },
        });
      }
      const credential: CredentialLabel =
        input.signIn.kind === "password"
          ? { id: `c-${Date.now()}`, kind: "password", name: null, fingerprint: null, comment: null, publicKey: null }
          : input.signIn.kind === "agent"
            ? agent
            : { ...deployKey, id: `c-${Date.now()}`, name: null, comment: `${input.username}@scoplen` };
      const created = host({
        id: `h-${Date.now()}`,
        name: input.name ?? input.address,
        address: input.address,
        port: input.port ?? 22,
        favorite: false,
        tags: {},
        groups: [],
        notes: null,
        logins: [login(`l-${Date.now()}`, input.username, credential, { kind: "direct" })],
      });
      hosts = [...hosts, created];
      changed();
      return wait(ok(created));
    },
    updateHost: (id: string, input: EditHost) => {
      const current = hosts.find((h) => h.id === id);
      if (!current)
        return wait({ status: "error" as const, error: { kind: "failed" as const, reference: "host not found" } });
      if (!input.name.trim()) return wait({ status: "error" as const, error: { kind: "emptyName" as const } });
      if (!input.address.trim() || /\s/.test(input.address)) {
        return wait({ status: "error" as const, error: { kind: "invalidAddress" as const } });
      }
      if (!Number.isInteger(input.port) || input.port < 1 || input.port > 65535) {
        return wait({ status: "error" as const, error: { kind: "invalidPort" as const } });
      }
      if (input.notes && textBytes(input.notes) > MAX_TEXT_BYTES) {
        return wait({ status: "error" as const, error: { kind: "notesTooLong" as const } });
      }
      if (
        Object.entries(input.tags).some(
          ([key, value]) => !key.trim() || textBytes(key) > MAX_TEXT_BYTES || textBytes(value) > MAX_TEXT_BYTES,
        )
      ) {
        return wait({ status: "error" as const, error: { kind: "invalidTag" as const } });
      }
      const requestedGroups = [...new Set(input.groups)];
      if (requestedGroups.some((groupId) => !availableGroups.some((group) => group.id === groupId))) {
        return wait({ status: "error" as const, error: { kind: "groupNotFound" as const } });
      }
      const updated = {
        ...current,
        ...input,
        notes: input.notes?.trim() || null,
        groups: requestedGroups,
        tags: { ...input.tags },
      };
      hosts = hosts.map((host) => (host.id === id ? updated : host));
      changed();
      return wait(ok(updated));
    },
    createGroup: (input: GroupInput) => {
      if (!input.name.trim()) return wait({ status: "error" as const, error: { kind: "emptyName" as const } });
      if (input.parent && !availableGroups.some((group) => group.id === input.parent)) {
        return wait({ status: "error" as const, error: { kind: "parentNotFound" as const } });
      }
      const created = { id: `g-${Date.now()}`, name: input.name.trim(), parent: input.parent, hostCount: 0 };
      availableGroups = [...availableGroups, created];
      changed();
      return wait(ok(created));
    },
    updateGroup: (id: string, input: GroupInput) => {
      const current = availableGroups.find((group) => group.id === id);
      if (!current)
        return wait({ status: "error" as const, error: { kind: "failed" as const, reference: "group not found" } });
      if (!input.name.trim()) return wait({ status: "error" as const, error: { kind: "emptyName" as const } });
      if (input.parent === id) return wait({ status: "error" as const, error: { kind: "selfParent" as const } });
      if (input.parent && !availableGroups.some((group) => group.id === input.parent)) {
        return wait({ status: "error" as const, error: { kind: "parentNotFound" as const } });
      }
      const updated = {
        ...current,
        name: input.name.trim(),
        parent: input.parent,
        hostCount: hosts.filter((host) => host.groups.includes(id)).length,
      };
      availableGroups = availableGroups.map((group) => (group.id === id ? updated : group));
      changed();
      return wait(ok(updated));
    },
    accessProfiles: () => wait(ok(profileRows())),
    forwards: () => wait(ok(objectForwards.map((forward) => ({ ...forward })))),
    createAccessProfile: (input: AccessProfileInput) => {
      const currentHost = hosts.find((host) => host.id === input.host);
      if (!currentHost) return wait(objectEditFailure("host not found"));
      if (!input.username.trim()) return wait({ status: "error" as const, error: { kind: "emptyUsername" as const } });
      if (input.credential && !objectCredentials.some((credential) => credential.id === input.credential)) {
        return wait({ status: "error" as const, error: { kind: "invalidCredential" as const } });
      }
      if (input.route && !objectRoutes.some((route) => route.id === input.route)) {
        return wait({ status: "error" as const, error: { kind: "invalidRoute" as const } });
      }
      const forwards = [...new Set(input.forwards)];
      if (forwards.some((forwardId) => !objectForwards.some((forward) => forward.id === forwardId))) {
        return wait({ status: "error" as const, error: { kind: "notFound" as const, entity: "forward" } });
      }
      const id = `l-${Date.now()}`;
      if (input.defaultProfile)
        profiles = profiles.map((profile) => ({
          ...profile,
          isDefault: profile.host === input.host ? false : profile.isDefault,
        }));
      const created: AccessProfileSummary = {
        id,
        host: input.host,
        hostName: currentHost.name,
        name: input.name?.trim() || null,
        username: input.username.trim(),
        credential: credentialLabelForSummary(
          objectCredentials.find((credential) => credential.id === input.credential),
        ),
        credentialId: input.credential,
        route: input.route
          ? routeLabelForSummary(objectRoutes.find((route) => route.id === input.route) ?? sampleRouteSeeds[0]!)
          : { kind: "direct" },
        routeId: input.route,
        terminalProfile: input.terminalProfile?.trim() || null,
        startupCommand: input.startupCommand?.trim() || null,
        agentForwarding: input.agentForwarding,
        forwards,
        isDefault: input.defaultProfile,
        orphaned: false,
        restored: false,
      };
      profiles = [...profiles, created];
      changed();
      return wait(ok(created));
    },
    updateAccessProfile: (id: Id, input: AccessProfileInput) => {
      const current = profiles.find((profile) => profile.id === id);
      const currentHost = hosts.find((host) => host.id === input.host);
      if (!current || !currentHost) return wait(objectEditFailure("access profile not found"));
      if (!input.username.trim()) return wait({ status: "error" as const, error: { kind: "emptyUsername" as const } });
      if (input.credential && !objectCredentials.some((credential) => credential.id === input.credential)) {
        return wait({ status: "error" as const, error: { kind: "invalidCredential" as const } });
      }
      if (input.route && !objectRoutes.some((route) => route.id === input.route)) {
        return wait({ status: "error" as const, error: { kind: "invalidRoute" as const } });
      }
      const forwards = [...new Set(input.forwards)];
      if (forwards.some((forwardId) => !objectForwards.some((forward) => forward.id === forwardId))) {
        return wait({ status: "error" as const, error: { kind: "notFound" as const, entity: "forward" } });
      }
      if (input.defaultProfile)
        profiles = profiles.map((profile) => ({
          ...profile,
          isDefault: profile.host === input.host ? false : profile.isDefault,
        }));
      const updated: AccessProfileSummary = {
        ...current,
        host: input.host,
        hostName: currentHost.name,
        name: input.name?.trim() || null,
        username: input.username.trim(),
        credential: credentialLabelForSummary(
          objectCredentials.find((credential) => credential.id === input.credential),
        ),
        credentialId: input.credential,
        route: input.route
          ? routeLabelForSummary(objectRoutes.find((route) => route.id === input.route) ?? sampleRouteSeeds[0]!)
          : { kind: "direct" },
        routeId: input.route,
        terminalProfile: input.terminalProfile?.trim() || null,
        startupCommand: input.startupCommand?.trim() || null,
        agentForwarding: input.agentForwarding,
        forwards,
        isDefault: input.defaultProfile,
      };
      profiles = profiles.map((profile) => (profile.id === id ? updated : profile));
      changed();
      return wait(ok(updated));
    },
    deleteAccessProfile: (id: Id) => {
      const current = profiles.find((profile) => profile.id === id);
      if (!current) return wait(objectEditFailure("access profile not found"));
      if (current.isDefault) return wait({ status: "error" as const, error: { kind: "defaultProfile" as const } });
      profiles = profiles.filter((profile) => profile.id !== id);
      changed();
      return wait(ok(null));
    },
    restoreOrphanedHost: (id: Id) => {
      const entry = [...deleted.entries()].find(([, host]) => host.id === id);
      if (!entry) return wait(objectEditFailure("orphaned host not found"));
      hosts = [...hosts, { ...entry[1], restored: true }];
      deleted.delete(entry[0]);
      changed();
      return wait(ok(null));
    },
    restoreOrphanedObject: (id: Id) => {
      const entry = [...deleted.entries()].find(([, host]) => host.id === id);
      if (!entry) return wait(objectEditFailure("orphaned object not found"));
      hosts = [...hosts, { ...entry[1], restored: true }];
      deleted.delete(entry[0]);
      changed();
      return wait(ok(null));
    },
    credentials: () => wait(ok(credentialRows())),
    createCredential: (input: CredentialInput) => {
      if (input.name !== null && !input.name.trim())
        return wait({ status: "error" as const, error: { kind: "emptyName" as const } });
      if (input.binding === "shared" && (input.kind === "password" || input.kind === "key") && !input.secret) {
        return wait({ status: "error" as const, error: { kind: "secretRequired" as const } });
      }
      if (input.binding === "device" && (input.kind === "password" || input.kind === "key") && !input.deviceSecret) {
        return wait({ status: "error" as const, error: { kind: "secretRequired" as const } });
      }
      if (input.secret && input.binding !== "shared")
        return wait({ status: "error" as const, error: { kind: "secretNotAllowed" as const } });
      if (input.deviceSecret && (input.binding !== "device" || (input.kind !== "password" && input.kind !== "key")))
        return wait({ status: "error" as const, error: { kind: "secretNotAllowed" as const } });
      const created: CredentialSummary = {
        id: `c-${Date.now()}`,
        name: input.name?.trim() || null,
        kind: input.kind,
        binding: input.binding,
        hasSecret: Boolean(input.secret || input.deviceSecret),
        publicKey: input.publicKey?.trim() || null,
        provider: { ...input.provider },
        certificateScope: input.certificateScope,
        profileCount: 0,
        routeCount: 0,
        restored: false,
      };
      objectCredentials = [...objectCredentials, created];
      changed();
      return wait(ok(created));
    },
    updateCredential: (id: Id, input: CredentialInput) => {
      const current = objectCredentials.find((credential) => credential.id === id);
      if (!current) return wait(objectEditFailure("credential not found"));
      if (input.name !== null && !input.name.trim())
        return wait({ status: "error" as const, error: { kind: "emptyName" as const } });
      if (
        input.binding === "shared" &&
        (input.kind === "password" || input.kind === "key") &&
        !input.secret &&
        !current.hasSecret
      ) {
        return wait({ status: "error" as const, error: { kind: "secretRequired" as const } });
      }
      if (
        input.binding === "device" &&
        (input.kind === "password" || input.kind === "key") &&
        !input.deviceSecret &&
        (!current.hasSecret || current.binding !== "device" || current.kind !== input.kind)
      ) {
        return wait({ status: "error" as const, error: { kind: "secretRequired" as const } });
      }
      if (input.secret && input.binding !== "shared")
        return wait({ status: "error" as const, error: { kind: "secretNotAllowed" as const } });
      if (input.deviceSecret && (input.binding !== "device" || (input.kind !== "password" && input.kind !== "key")))
        return wait({ status: "error" as const, error: { kind: "secretNotAllowed" as const } });
      const updated = {
        ...current,
        name: input.name?.trim() || null,
        kind: input.kind,
        binding: input.binding,
        hasSecret:
          input.secret || input.deviceSecret
            ? true
            : input.binding === "shared" || input.binding === "device"
              ? current.hasSecret
              : false,
        publicKey: input.publicKey?.trim() || null,
        provider: { ...input.provider },
        certificateScope: input.certificateScope,
      };
      objectCredentials = objectCredentials.map((credential) => (credential.id === id ? updated : credential));
      changed();
      return wait(ok(updated));
    },
    deleteCredential: (id: Id) => {
      const current = objectCredentials.find((credential) => credential.id === id);
      if (!current) return wait(objectEditFailure("credential not found"));
      if (
        profileRows().some((profile) => profile.credentialId === id) ||
        objectRoutes.some(
          (route) =>
            (route.definition.kind === "socks5" || route.definition.kind === "httpConnect") &&
            route.definition.credential === id,
        )
      ) {
        return wait({ status: "error" as const, error: { kind: "inUse" as const } });
      }
      objectCredentials = objectCredentials.filter((credential) => credential.id !== id);
      changed();
      return wait(ok(null));
    },
    routes: () => wait(ok(routeRows())),
    createRoute: (input: RouteInput) => {
      if (!input.name.trim()) return wait({ status: "error" as const, error: { kind: "emptyName" as const } });
      if (input.definition.kind === "managed")
        return wait({ status: "error" as const, error: { kind: "managedRoute" as const } });
      const created: RouteSummary = {
        id: `r-${Date.now()}`,
        name: input.name.trim(),
        definition: input.definition,
        profileCount: 0,
        orphaned: false,
        restored: false,
      };
      objectRoutes = [...objectRoutes, created];
      changed();
      return wait(ok(created));
    },
    updateRoute: (id: Id, input: RouteInput) => {
      const current = objectRoutes.find((route) => route.id === id);
      if (!current) return wait(objectEditFailure("route not found"));
      if (!input.name.trim()) return wait({ status: "error" as const, error: { kind: "emptyName" as const } });
      if (input.definition.kind === "managed")
        return wait({ status: "error" as const, error: { kind: "managedRoute" as const } });
      const updated = { ...current, name: input.name.trim(), definition: input.definition };
      objectRoutes = objectRoutes.map((route) => (route.id === id ? updated : route));
      changed();
      return wait(ok(updated));
    },
    deleteRoute: (id: Id) => {
      const current = objectRoutes.find((route) => route.id === id);
      if (!current) return wait(objectEditFailure("route not found"));
      if (current.definition.kind === "managed")
        return wait({ status: "error" as const, error: { kind: "managedRoute" as const } });
      if (profileRows().some((profile) => profile.routeId === id))
        return wait({ status: "error" as const, error: { kind: "inUse" as const } });
      objectRoutes = objectRoutes.filter((route) => route.id !== id);
      changed();
      return wait(ok(null));
    },
    setFavorite: (id, favorite) => {
      hosts = hosts.map((h) => (h.id === id ? { ...h, favorite } : h));
      changed();
      return wait(ok(null));
    },
    deleteHost: (id) => {
      const found = hosts.find((h) => h.id === id);
      hosts = hosts.filter((h) => h.id !== id);
      if (found) deleted.set(`undo-${id}`, found);
      changed();
      return wait(ok({ token: `undo-${id}` }));
    },
    undoDelete: (token) => {
      const found = deleted.get(token);
      if (found) hosts = [...hosts, found];
      deleted.delete(token);
      changed();
      return wait(ok(null));
    },
    chooseKeyFile: () => wait("/Users/mia/.ssh/id_ed25519"),
    chooseOpenSshConfig: () => wait("/Users/mia/.ssh/config"),
    previewOpenSshConfig: (path) =>
      wait(
        ok({
          path,
          entries: [
            { alias: "prod-api", address: "prod.example.com", port: 22, username: "deploy", identityFile: null },
          ],
          skippedHosts: [
            { alias: "legacy", line: 5, reason: { kind: "unsupportedDirective", directive: "ForwardAgent" } },
          ],
          unsupported: [{ line: 7, directive: "ForwardAgent" }],
        }),
      ),
    importOpenSshConfig: (preview) => {
      if (hosts.length > 0) return wait({ status: "error" as const, error: { kind: "inventoryNotEmpty" as const } });
      if (preview.entries.length === 0) return wait({ status: "error" as const, error: { kind: "noHosts" as const } });
      const imported = host({
        id: `h-${Date.now()}`,
        name: "prod-api",
        address: "prod.example.com",
        port: 22,
        favorite: false,
        tags: {},
        groups: [],
        notes: null,
        logins: [login(`l-${Date.now()}`, "deploy", agent, { kind: "direct" })],
      });
      hosts = [imported];
      changed();
      return wait(
        ok({
          hosts: [imported],
          skippedHosts: preview.skippedHosts,
          unsupported: preview.unsupported,
        }),
      );
    },
    onChange: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}
