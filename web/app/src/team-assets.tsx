// SPDX-License-Identifier: Apache-2.0
import { Button, Dialog } from "@scoplen/ui";
import { useEffect, useRef, useState } from "react";
import { useProfileCommands } from "./account-profiles";
import { useI18n } from "./i18n";
import type { TeamAssetsView, TeamSummary } from "./ipc/bindings";

export function TeamAssets({ team, onClose }: { team: TeamSummary; onClose: () => void }) {
  const commands = useProfileCommands();
  const { t } = useI18n();
  const [view, setView] = useState<TeamAssetsView | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);
  const [reload, setReload] = useState(0);
  const inFlight = useRef(false);

  useEffect(() => {
    let active = true;
    let reading = false;
    inFlight.current = true;
    void commands
      .refreshTeamAssets(team.id)
      .then(
        (result) => {
          if (!active) return;
          if (result.status === "ok") setView(result.data);
          else setFailed(result.error);
        },
        () => {
          if (active) setFailed("network");
        },
      )
      .finally(() => {
        if (!active) return;
        inFlight.current = false;
        setBusy(false);
      });
    const timer = setInterval(() => {
      if (reading || inFlight.current) return;
      reading = true;
      void commands
        .teamAssets(team.id)
        .then(
          (result) => {
            if (!active) return;
            if (result.status === "ok") {
              setView(result.data);
              if (result.data.phase === "ready" && result.data.acknowledged) setFailed(null);
            } else {
              setView(null);
              setFailed(result.error);
            }
          },
          () => {
            if (active) {
              setView(null);
              setFailed("storage");
            }
          },
        )
        .finally(() => {
          reading = false;
        });
    }, 2000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [commands, team.id, reload]);

  const refresh = () => {
    if (inFlight.current) return;
    setView(null);
    setFailed(null);
    setBusy(true);
    setReload((value) => value + 1);
  };
  const phase = view?.phase ?? "notLoaded";
  const errorKey =
    failed === "teamNotFound"
      ? "teams.assets.unavailable"
      : failed === "assetsChanged"
        ? "teams.assets.stale"
        : failed === "assetsLimit"
          ? "teams.assets.limit"
          : failed === "assetsAcknowledgementUnknown"
            ? "teams.assets.acknowledgement"
            : failed === "permissionDenied"
              ? "teams.error.permission"
              : failed === "authenticationRequired" || failed === "membershipScopeRequired"
                ? "teams.error.authentication"
                : "teams.assets.failed";
  const kind = (value: string) => {
    const keys = {
      Host: "host",
      AccessProfile: "login",
      HostGroup: "group",
      Route: "route",
      TrustRecord: "trust",
      Snippet: "snippet",
      GatewayNetwork: "gateway",
    } as const;
    return value in keys ? t(`teams.assets.kind.${keys[value as keyof typeof keys]}`) : value;
  };

  return (
    <Dialog
      open
      title={t("teams.assets.title", { name: team.name })}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      closeLabel={t("teams.assets.close")}
      footer={
        <>
          <Button variant="secondary" disabled={busy || phase === "updating"} onClick={refresh}>
            {t("teams.assets.refresh")}
          </Button>
          <Button variant="ghost" onClick={onClose}>
            {t("teams.assets.close")}
          </Button>
        </>
      }
    >
      <section aria-busy={busy || phase === "updating"}>
        <p className="text-sm text-muted-foreground">{t("teams.assets.body")}</p>
        {view ? <p className="mt-2 break-all text-xs text-muted-foreground select-text">{view.origin}</p> : null}
        {busy || phase === "updating" ? (
          <p role="status" className="mt-4 text-sm">
            {t("teams.assets.loading")}
          </p>
        ) : null}
        {failed ? (
          <p role="alert" className="mt-4 text-sm text-attention">
            {t(errorKey)}
          </p>
        ) : null}
        {!busy && !failed && phase !== "ready" && phase !== "updating" ? (
          <p role="status" className="mt-4 text-sm text-muted-foreground">
            {t(
              phase === "unavailable"
                ? "teams.assets.unavailable"
                : phase === "stale"
                  ? "teams.assets.stale"
                  : "teams.assets.failed",
            )}
          </p>
        ) : null}
        {!busy && view?.phase === "ready" ? (
          <>
            {!view.acknowledged ? (
              <p role="status" className="mt-4 text-sm text-muted-foreground">
                {t("teams.assets.acknowledgement")}
              </p>
            ) : null}
            {view.assets.length ? (
              <ul aria-label={t("teams.assets.list")} className="mt-4 list-none divide-y divide-border p-0">
                {view.assets.map((asset) => (
                  <li key={asset.id} className="py-3">
                    <p className="break-words text-sm font-medium [overflow-wrap:anywhere]">{asset.name ?? asset.id}</p>
                    <p className="mt-1 break-words text-sm text-muted-foreground [overflow-wrap:anywhere]">
                      {kind(asset.kind)}
                    </p>
                    {asset.address ? (
                      <p className="mt-1 break-all select-text font-mono text-sm">{asset.address}</p>
                    ) : null}
                  </li>
                ))}
              </ul>
            ) : (
              <p role="status" className="mt-4 text-sm text-muted-foreground">
                {t("teams.assets.empty")}
              </p>
            )}
          </>
        ) : null}
      </section>
    </Dialog>
  );
}
