// SPDX-License-Identifier: Apache-2.0
import { Button, Dialog, TextAreaField } from "@scoplen/ui";
import { useEffect, useRef, useState } from "react";
import { useProfileCommands } from "./account-profiles";
import { useI18n } from "./i18n";
import type { TeamSshOperationView, TeamSshSource, TeamSummary, TeamUserCaView } from "./ipc/bindings";
import { TeamSelect } from "./team-authoring-fields";

export function TeamSshSetup({ team, onClose }: { team: TeamSummary; onClose: () => void }) {
  const commands = useProfileCommands();
  const { t } = useI18n();
  const [source, setSource] = useState<TeamSshSource | null>(null);
  const [ca, setCa] = useState<TeamUserCaView | null>(null);
  const [operations, setOperations] = useState<TeamSshOperationView[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(true);
  const [failed, setFailed] = useState<string | null>(null);
  const [reviewed, setReviewed] = useState<Set<string>>(new Set());
  const [reload, setReload] = useState(0);
  const [profile, setProfile] = useState("");
  const active = useRef(true);
  const inFlight = useRef(false);

  useEffect(() => {
    active.current = true;
    let current = true;
    void commands
      .teamAssets(team.id)
      .then(async (result) => {
        if (!current) return;
        if (result.status === "error") {
          setFailed(result.error);
          return;
        }
        const view = result.data;
        const captured = {
          origin: view.origin,
          accountId: view.accountId,
          organizationId: view.organizationId,
          deviceId: view.deviceId,
        };
        setSource(captured);
        const pending = await commands.teamSshOperations(captured);
        if (!current) return;
        if (pending.status === "error") {
          setLoaded(false);
          setFailed(pending.error);
          return;
        }
        setOperations(pending.data);
        setLoaded(true);
        const resultCa = await commands.teamUserCa(captured);
        if (!current) return;
        if (resultCa.status === "error") {
          setCa(null);
          setFailed(resultCa.error);
          return;
        }
        setCa(resultCa.data);
        setFailed(null);
        if (reload > 0)
          setReviewed(
            new Set(
              pending.data
                .filter((operation) => operation.phase === "expired")
                .map((operation) => operation.operationId),
            ),
          );
      })
      .catch(() => {
        if (current) {
          setFailed("storage");
          setLoaded(false);
        }
      })
      .finally(() => {
        if (current) setBusy(false);
      });
    return () => {
      current = false;
      active.current = false;
    };
  }, [commands, team.id, reload]);

  const readOperations = async (captured: TeamSshSource) => {
    const result = await commands.teamSshOperations(captured);
    if (!active.current) return;
    if (result.status === "ok") {
      setOperations(result.data);
      setLoaded(true);
    } else {
      setLoaded(false);
      setFailed(result.error);
    }
  };
  const run = async (action: (captured: TeamSshSource) => Promise<void>) => {
    if (!source || inFlight.current || busy) return;
    inFlight.current = true;
    setBusy(true);
    setFailed(null);
    try {
      await action(source);
    } catch {
      if (active.current) {
        setFailed("caUnknown");
        await readOperations(source).catch(() => {
          if (active.current) setLoaded(false);
        });
      }
    } finally {
      inFlight.current = false;
      if (active.current) setBusy(false);
    }
  };
  const confirm = async (captured: TeamSshSource, operation: TeamSshOperationView) => {
    const result = await commands.confirmTeamSshOperation(captured, operation.kind, operation.operationId);
    if (!active.current) return;
    if (result.status === "error") {
      setFailed(result.error);
      await readOperations(captured);
      return;
    }
    await readOperations(captured);
    if (operation.kind === "userCa" && result.data.phase === "confirmed") {
      const resultCa = await commands.teamUserCa(captured);
      if (!active.current) return;
      if (resultCa.status === "ok") setCa(resultCa.data);
      else setFailed(resultCa.error);
    }
  };
  const create = () =>
    void run(async (captured) => {
      if (!loaded || ca || operations.some((operation) => operation.kind === "userCa")) return;
      const result = await commands.prepareTeamUserCa(captured);
      if (!active.current) return;
      if (result.status === "error") {
        setFailed(result.error);
        await readOperations(captured);
        return;
      }
      setOperations((old) => [...old.filter((operation) => operation.kind !== "userCa"), result.data]);
      await confirm(captured, result.data);
    });
  const discard = (operation: TeamSshOperationView) =>
    void run(async (captured) => {
      if (operation.phase === "unknown" || (operation.phase === "expired" && !reviewed.has(operation.operationId)))
        return;
      const result = await commands.discardTeamSshOperation(captured, operation.kind, operation.operationId);
      if (!active.current) return;
      if (result.status === "error") setFailed(result.error);
      else await readOperations(captured);
    });
  const error =
    failed === "permissionDenied"
      ? "teams.error.accessDenied"
      : failed === "authenticationRequired" || failed === "membershipScopeRequired"
        ? "teams.error.authentication"
        : failed === "invalidSource"
          ? "teams.ssh.sourceChanged"
          : failed === "caUnknown" || failed === "issuanceUnknown" || failed === "preparationPending"
            ? "teams.ssh.pending"
            : failed === "viewRequired" || failed === "authorityChanged"
              ? "teams.assets.stale"
              : failed === "operationExpired"
                ? "teams.ssh.expired"
                : "teams.ssh.failed";
  const caPending = operations.some((operation) => operation.kind === "userCa");
  const setup = ca?.setups.find((item) => item.profileId === profile) ?? ca?.setups[0];

  return (
    <Dialog
      open
      title={t("teams.ssh.title", { name: team.name })}
      description={t("teams.ssh.body")}
      closeLabel={t("teams.ssh.close")}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      footer={
        <>
          <Button
            variant="secondary"
            disabled={busy}
            onClick={() => {
              setBusy(true);
              setFailed(null);
              setLoaded(false);
              setReviewed(new Set());
              setReload((value) => value + 1);
            }}
          >
            {t("teams.authoring.refresh")}
          </Button>
          <Button variant="ghost" onClick={onClose}>
            {t("teams.ssh.close")}
          </Button>
        </>
      }
    >
      <section className="min-w-0 space-y-4" aria-busy={busy}>
        {source ? <p className="break-all text-xs text-muted-foreground select-text">{source.origin}</p> : null}
        {busy ? (
          <p role="status" className="text-sm text-muted-foreground">
            {t("teams.ssh.loading")}
          </p>
        ) : null}
        {failed ? (
          <p role="alert" className="text-sm text-attention">
            {t(error)}
          </p>
        ) : null}
        {operations.map((operation) => (
          <section key={operation.operationId} className="space-y-3 border-y border-border py-4">
            <h3 className="text-sm font-medium">
              {t(operation.kind === "userCa" ? "teams.ssh.caOperation" : "teams.ssh.certificateOperation")}
            </h3>
            <p role="status" className="text-sm">
              {t(
                operation.phase === "confirmed"
                  ? "teams.ssh.confirmed"
                  : operation.phase === "expired"
                    ? "teams.ssh.expired"
                    : operation.phase === "prepared"
                      ? "teams.authoring.prepared"
                      : "teams.ssh.pending",
              )}
            </p>
            {operation.hostId ? (
              <p className="break-all text-xs select-text">
                {operation.hostId} · {operation.remoteUser}
              </p>
            ) : null}
            <div className="flex flex-wrap gap-2">
              {operation.phase === "prepared" || operation.phase === "unknown" ? (
                <Button
                  variant="primary"
                  disabled={busy}
                  onClick={() => void run((captured) => confirm(captured, operation))}
                >
                  {t(operation.phase === "unknown" ? "teams.authoring.confirm" : "teams.authoring.send")}
                </Button>
              ) : null}
              {operation.phase !== "unknown" ? (
                <Button
                  variant="secondary"
                  disabled={busy || (operation.phase === "expired" && !reviewed.has(operation.operationId))}
                  onClick={() => discard(operation)}
                >
                  {t(
                    operation.phase === "confirmed"
                      ? "teams.authoring.done"
                      : operation.phase === "expired"
                        ? "teams.authoring.archive"
                        : "teams.authoring.discard",
                  )}
                </Button>
              ) : null}
            </div>
          </section>
        ))}
        {ca ? (
          <>
            <h3 className="text-sm font-medium">{t("teams.ssh.publicCa")}</h3>
            <TextAreaField
              label={t("teams.ssh.publicKey")}
              value={ca.publicKey}
              readOnly
              rows={3}
              className="break-all font-mono"
            />
            <p className="break-all text-xs select-text">
              <span className="font-medium">{t("teams.authoring.fingerprint")}: </span>
              {ca.fingerprint}
            </p>
            <p className="break-all text-xs text-muted-foreground select-text">
              {t("teams.ssh.caId")}: {ca.id}
            </p>
            <p className="text-sm text-muted-foreground">{t("teams.ssh.manual")}</p>
            {setup ? (
              <section className="min-w-0 space-y-4 border-t border-border pt-4">
                <TeamSelect
                  label={t("teams.ssh.selectedLogin")}
                  value={setup.profileId}
                  onChange={setProfile}
                  options={ca.setups.map((item) => ({
                    value: item.profileId,
                    label: `${item.remoteUser} · ${item.hostId}`,
                  }))}
                  disabled={busy}
                />
                <dl className="space-y-2 break-all text-xs select-text">
                  <div>
                    <dt className="font-medium">{t("teams.authoring.host")}</dt>
                    <dd className="m-0">{setup.hostId}</dd>
                  </div>
                  <div>
                    <dt className="font-medium">{t("teams.assets.kind.login")}</dt>
                    <dd className="m-0">{setup.profileId}</dd>
                  </div>
                  <div>
                    <dt className="font-medium">{t("teams.authoring.username")}</dt>
                    <dd className="m-0">{setup.remoteUser}</dd>
                  </div>
                  <div>
                    <dt className="font-medium">{t("teams.ssh.caFile")}</dt>
                    <dd className="m-0">{setup.caFile}</dd>
                  </div>
                  <div>
                    <dt className="font-medium">{t("teams.ssh.principalsFile")}</dt>
                    <dd className="m-0">{setup.principalsFile}</dd>
                  </div>
                </dl>
                <p className="text-sm text-muted-foreground">{t("teams.ssh.principalsNotice")}</p>
                <TextAreaField
                  label={t("teams.ssh.principal")}
                  value={setup.principal}
                  readOnly
                  rows={3}
                  className="font-mono"
                />
                <TextAreaField
                  label={t("teams.ssh.sshdConfig")}
                  value={setup.sshdConfig}
                  readOnly
                  rows={3}
                  className="font-mono"
                />
              </section>
            ) : (
              <p className="text-sm text-muted-foreground">{t("teams.ssh.noLogin")}</p>
            )}
            <Button
              variant="secondary"
              disabled={busy}
              onClick={() =>
                void run(async (captured) => {
                  const result = await commands.refreshTeamAssets(team.id);
                  if (!active.current) return;
                  if (result.status === "error") {
                    setFailed(result.error);
                    return;
                  }
                  const updated = await commands.teamUserCa(captured);
                  if (!active.current) return;
                  if (updated.status === "error") {
                    setCa(null);
                    setFailed(updated.error);
                  } else setCa(updated.data);
                })
              }
            >
              {t("teams.assets.refresh")}
            </Button>
          </>
        ) : loaded && !busy && !failed ? (
          <>
            <p className="text-sm text-muted-foreground">{t("teams.ssh.missing")}</p>
            {!caPending ? (
              <Button variant="primary" onClick={create}>
                {t("teams.ssh.create")}
              </Button>
            ) : null}
          </>
        ) : null}
      </section>
    </Dialog>
  );
}
