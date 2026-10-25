// SPDX-License-Identifier: Apache-2.0
//
// The production inventory adapter. It is deliberately a thin translation
// layer: the Rust core owns validation, persistence, secrets, and atomicity;
// the interface only receives the redacted DTOs defined by inventory/api.ts.

import {
  commands as applicationCommands,
  events,
  type AddHostError as IpcAddHostError,
  type AccessProfileInput as IpcAccessProfileInput,
  type AccessProfileSummary as IpcAccessProfileSummary,
  type Areas as IpcAreas,
  type EditHost as IpcEditHost,
  type EditHostError as IpcEditHostError,
  type CredentialInput as IpcCredentialInput,
  type CredentialSummary as IpcCredentialSummary,
  type Failure as IpcFailure,
  type GroupError as IpcGroupError,
  type GroupInput as IpcGroupInput,
  type GroupSummary as IpcGroupSummary,
  type HostDetails as IpcHostDetails,
  type HostSource as IpcHostSource,
  type HostSummary as IpcHostSummary,
  type NewHost as IpcNewHost,
  type RecentSession as IpcRecentSession,
  type ReconnectTarget as IpcReconnectTarget,
  type OpenSshImportError as IpcOpenSshImportError,
  type OpenSshImportPreview as IpcOpenSshImportPreview,
  type OpenSshImportResult as IpcOpenSshImportResult,
  type ObjectEditError as IpcObjectEditError,
  type RouteInput as IpcRouteInput,
  type RouteSummary as IpcRouteSummary,
  type ForwardSummary as IpcForwardSummary,
  type ForwardInput as IpcForwardInput,
  type RecentSessionKind as IpcRecentSessionKind,
  type RecentSessionOutcome as IpcRecentSessionOutcome,
  type SessionError as IpcSessionError,
} from "../ipc/bindings";
import type {
  AddHostError,
  AccessProfileInput,
  AccessProfileSummary,
  Deletion,
  EditHost,
  EditHostError,
  CredentialInput,
  CredentialSummary,
  Failure,
  GroupError,
  GroupInput,
  GroupSummary,
  HostDetails,
  HostSource,
  InventoryApi,
  NewHost,
  OpenSshImportError,
  OpenSshImportPreview,
  OpenSshImportResult,
  ObjectEditError,
  Outcome,
  RecentSession,
  ReconnectTarget,
  RouteInput,
  RouteSummary,
  ForwardSummary,
  ForwardInput,
  RecentSessionKind,
  RecentSessionOutcome,
  SessionError,
} from "./api";

type Result<T, E> = { status: "ok"; data: T } | { status: "error"; error: E };

const inventoryRecordTypes = new Set(["host", "accessProfile", "credential", "route", "hostGroup", "forward"]);

function failure(error: IpcFailure | unknown): Failure {
  if (typeof error === "object" && error !== null && "kind" in error && error.kind === "failed") {
    const reference =
      "reference" in error && typeof error.reference === "string" ? error.reference : "inventory operation failed";
    return { kind: "failed", reference };
  }
  return { kind: "failed", reference: String(error) };
}

function outcome<T, E>(result: Result<T, E>): Outcome<T, E> {
  return result.status === "ok" ? result : { status: "error", error: result.error };
}

function inventoryOutcome<T>(result: Result<T, IpcFailure>): Outcome<T, Failure> {
  return result.status === "ok" ? result : { status: "error", error: failure(result.error) };
}

function inventoryObjectOutcome<T>(result: Result<T, IpcObjectEditError>): Outcome<T, ObjectEditError> {
  return result.status === "ok" ? result : { status: "error", error: result.error as ObjectEditError };
}

/** Creates the desktop adapter used by the real Hosts screen. */
export function createInventoryApi(commands = applicationCommands, profileGeneration?: string): InventoryApi {
  return {
    areas: async () => inventoryOutcome((await commands.inventoryAreas()) as Result<IpcAreas, IpcFailure>),
    groups: async () => inventoryOutcome((await commands.inventoryGroups()) as Result<IpcGroupSummary[], IpcFailure>),
    hosts: async (source: HostSource, query: string) =>
      inventoryOutcome(
        (await commands.inventoryHosts(source as IpcHostSource, query)) as Result<IpcHostSummary[], IpcFailure>,
      ),
    savedOutput: async (id) => outcome(await commands.sessionSavedOutput(id)),
    recentSessions: async () =>
      inventoryOutcome((await commands.inventoryRecentSessions()) as Result<IpcRecentSession[], IpcFailure>) as Outcome<
        RecentSession[],
        Failure
      >,
    openSession: async (profileId: string, kind: RecentSessionKind) =>
      outcome(
        (await commands.sessionOpen(profileId, kind as IpcRecentSessionKind)) as Result<
          IpcRecentSession,
          IpcSessionError
        >,
      ) as Outcome<RecentSession, SessionError>,
    closeSession: async (id: string, sessionOutcome: RecentSessionOutcome) =>
      outcome(
        (await commands.sessionClose(id, sessionOutcome as IpcRecentSessionOutcome)) as Result<null, IpcSessionError>,
      ) as Outcome<null, SessionError>,
    reconnectSession: async (id: string) =>
      outcome((await commands.sessionReconnect(id)) as Result<IpcReconnectTarget, IpcSessionError>) as Outcome<
        ReconnectTarget,
        SessionError
      >,
    forgetSession: async (id: string) =>
      outcome((await commands.sessionForget(id)) as Result<null, IpcSessionError>) as Outcome<null, SessionError>,
    host: async (id: string) =>
      inventoryOutcome((await commands.inventoryHost(id)) as Result<IpcHostDetails | null, IpcFailure>),
    addHost: async (input: NewHost) =>
      outcome(
        (await commands.inventoryAddHost(input as IpcNewHost)) as Result<HostDetails, IpcAddHostError>,
      ) as Outcome<HostDetails, AddHostError>,
    updateHost: async (id: string, input: EditHost) =>
      outcome(
        (await commands.inventoryUpdateHost(id, input as IpcEditHost)) as Result<HostDetails, IpcEditHostError>,
      ) as Outcome<HostDetails, EditHostError>,
    createGroup: async (input: GroupInput) =>
      outcome(
        (await commands.inventoryCreateGroup(input as IpcGroupInput)) as Result<GroupSummary, IpcGroupError>,
      ) as Outcome<GroupSummary, GroupError>,
    updateGroup: async (id: string, input: GroupInput) =>
      outcome(
        (await commands.inventoryUpdateGroup(id, input as IpcGroupInput)) as Result<GroupSummary, IpcGroupError>,
      ) as Outcome<GroupSummary, GroupError>,
    accessProfiles: async () =>
      inventoryObjectOutcome(
        (await commands.inventoryAccessProfiles()) as Result<IpcAccessProfileSummary[], IpcObjectEditError>,
      ) as Outcome<AccessProfileSummary[], ObjectEditError>,
    forwards: async () =>
      inventoryObjectOutcome(
        (await commands.inventoryForwards()) as Result<IpcForwardSummary[], IpcObjectEditError>,
      ) as Outcome<ForwardSummary[], ObjectEditError>,
    createForward: async (input: ForwardInput) =>
      inventoryObjectOutcome(await commands.inventoryCreateForward(input as IpcForwardInput)) as Outcome<
        ForwardSummary,
        ObjectEditError
      >,
    updateForward: async (id: string, input: ForwardInput) =>
      inventoryObjectOutcome(await commands.inventoryUpdateForward(id, input as IpcForwardInput)) as Outcome<
        ForwardSummary,
        ObjectEditError
      >,
    deleteForward: async (id: string) =>
      inventoryObjectOutcome(await commands.inventoryDeleteForward(id)) as Outcome<null, ObjectEditError>,
    createAccessProfile: async (input: AccessProfileInput) =>
      inventoryObjectOutcome(
        (await commands.inventoryCreateAccessProfile(input as IpcAccessProfileInput)) as Result<
          IpcAccessProfileSummary,
          IpcObjectEditError
        >,
      ) as Outcome<AccessProfileSummary, ObjectEditError>,
    updateAccessProfile: async (id: string, input: AccessProfileInput) =>
      inventoryObjectOutcome(
        (await commands.inventoryUpdateAccessProfile(id, input as IpcAccessProfileInput)) as Result<
          IpcAccessProfileSummary,
          IpcObjectEditError
        >,
      ) as Outcome<AccessProfileSummary, ObjectEditError>,
    deleteAccessProfile: async (id: string) =>
      inventoryObjectOutcome(
        (await commands.inventoryDeleteAccessProfile(id)) as Result<null, IpcObjectEditError>,
      ) as Outcome<null, ObjectEditError>,
    restoreOrphanedHost: async (id: string) =>
      inventoryObjectOutcome(
        (await commands.inventoryRestoreOrphanedHost(id)) as Result<null, IpcObjectEditError>,
      ) as Outcome<null, ObjectEditError>,
    restoreOrphanedObject: async (id: string) =>
      inventoryObjectOutcome(
        (await commands.inventoryRestoreOrphanedObject(id)) as Result<null, IpcObjectEditError>,
      ) as Outcome<null, ObjectEditError>,
    credentials: async () =>
      inventoryObjectOutcome(
        (await commands.inventoryCredentials()) as Result<IpcCredentialSummary[], IpcObjectEditError>,
      ) as Outcome<CredentialSummary[], ObjectEditError>,
    createCredential: async (input: CredentialInput) =>
      inventoryObjectOutcome(
        (await commands.inventoryCreateCredential(input as IpcCredentialInput)) as Result<
          IpcCredentialSummary,
          IpcObjectEditError
        >,
      ) as Outcome<CredentialSummary, ObjectEditError>,
    updateCredential: async (id: string, input: CredentialInput) =>
      inventoryObjectOutcome(
        (await commands.inventoryUpdateCredential(id, input as IpcCredentialInput)) as Result<
          IpcCredentialSummary,
          IpcObjectEditError
        >,
      ) as Outcome<CredentialSummary, ObjectEditError>,
    deleteCredential: async (id: string) =>
      inventoryObjectOutcome(
        (await commands.inventoryDeleteCredential(id)) as Result<null, IpcObjectEditError>,
      ) as Outcome<null, ObjectEditError>,
    routes: async () =>
      inventoryObjectOutcome(
        (await commands.inventoryRoutes()) as Result<IpcRouteSummary[], IpcObjectEditError>,
      ) as Outcome<RouteSummary[], ObjectEditError>,
    createRoute: async (input: RouteInput) =>
      inventoryObjectOutcome(
        (await commands.inventoryCreateRoute(input as IpcRouteInput)) as Result<IpcRouteSummary, IpcObjectEditError>,
      ) as Outcome<RouteSummary, ObjectEditError>,
    updateRoute: async (id: string, input: RouteInput) =>
      inventoryObjectOutcome(
        (await commands.inventoryUpdateRoute(id, input as IpcRouteInput)) as Result<
          IpcRouteSummary,
          IpcObjectEditError
        >,
      ) as Outcome<RouteSummary, ObjectEditError>,
    deleteRoute: async (id: string) =>
      inventoryObjectOutcome((await commands.inventoryDeleteRoute(id)) as Result<null, IpcObjectEditError>) as Outcome<
        null,
        ObjectEditError
      >,
    setFavorite: async (id: string, favorite: boolean) =>
      inventoryOutcome((await commands.inventorySetFavorite(id, favorite)) as Result<null, IpcFailure>),
    deleteHost: async (id: string) =>
      inventoryOutcome((await commands.inventoryDeleteHost(id)) as Result<Deletion, IpcFailure>),
    undoDelete: async (token: string) =>
      inventoryOutcome((await commands.inventoryUndoDelete(token)) as Result<null, IpcFailure>),
    chooseKeyFile: async () => {
      const result = await commands.chooseKeyFile();
      if (result.status === "ok") return result.data;
      throw new Error(failure(result.error).reference);
    },
    chooseOpenSshConfig: async () => {
      const result = await commands.chooseOpenSshConfig();
      if (result.status === "ok") return result.data;
      throw new Error(failure(result.error).reference);
    },
    previewOpenSshConfig: async (path: string) =>
      outcome(
        (await commands.inventoryPreviewOpenSshConfig(path)) as Result<IpcOpenSshImportPreview, IpcOpenSshImportError>,
      ) as Outcome<OpenSshImportPreview, OpenSshImportError>,
    importOpenSshConfig: async (preview: OpenSshImportPreview) =>
      outcome(
        (await commands.inventoryImportOpenSshConfig(preview as IpcOpenSshImportPreview)) as Result<
          IpcOpenSshImportResult,
          IpcOpenSshImportError
        >,
      ) as Outcome<OpenSshImportResult, OpenSshImportError>,
    onChange: (listener) => {
      let stopped = false;
      const unlisteners: (() => void | Promise<void>)[] = [];
      const dispose = (callback: () => void | Promise<void>) => {
        void Promise.resolve(callback()).catch(() => undefined);
      };
      void events.storeChanged
        .listen((event) => {
          if (
            !stopped &&
            (profileGeneration === undefined || event.payload.profileGeneration === profileGeneration) &&
            inventoryRecordTypes.has(event.payload.recordType)
          )
            listener();
        })
        .then((unlistenFn) => {
          if (stopped) dispose(unlistenFn);
          else unlisteners.push(unlistenFn);
        });
      void events.sessionChanged
        .listen((event) => {
          if (!stopped && (profileGeneration === undefined || event.payload.profileGeneration === profileGeneration))
            listener();
        })
        .then((unlistenFn) => {
          if (stopped) dispose(unlistenFn);
          else unlisteners.push(unlistenFn);
        });
      return () => {
        stopped = true;
        while (unlisteners.length > 0) dispose(unlisteners.pop()!);
      };
    },
  };
}
