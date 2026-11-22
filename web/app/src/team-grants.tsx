// SPDX-License-Identifier: Apache-2.0
import { Button, Dialog } from "@scoplen/ui";
import { useCallback, useEffect, useRef, useState } from "react";
import { useProfileCommands } from "./account-profiles";
import { useI18n } from "./i18n";
import type { TeamGrantPageView, TeamGrantView } from "./ipc/bindings";

type Props = {
  organizationId: string;
  name: string;
  onClose: () => void;
};

/** Current Host Grant administration. The server remains the authority for every action. */
export function TeamGrants(props: Props) {
  return <Grants key={props.organizationId} {...props} />;
}

function Grants({ organizationId, name, onClose }: Props) {
  const commands = useProfileCommands();
  const { t } = useI18n();
  const [page, setPage] = useState<TeamGrantPageView | null>(null);
  const [selected, setSelected] = useState<TeamGrantView | null>(null);
  const [busy, setBusy] = useState(false);
  const [issue, setIssue] = useState<string | null>(null);
  const mounted = useRef(true);
  const generation = useRef(0);
  const flight = useRef<symbol | null>(null);

  const run = useCallback(async (action: (current: () => boolean) => Promise<void>) => {
    if (!mounted.current || flight.current) return;
    const owner = generation.current;
    const token = Symbol();
    const current = () => mounted.current && generation.current === owner;
    flight.current = token;
    setBusy(true);
    setIssue(null);
    try {
      await action(current);
    } catch {
      if (current()) setIssue("storage");
    } finally {
      if (flight.current === token) flight.current = null;
      if (current()) setBusy(false);
    }
  }, []);

  const loadPage = useCallback(
    async (cursor: string | null, current: () => boolean) => {
      const result = await commands.teamGrantsPage(organizationId, cursor);
      if (!current()) return false;
      if (result.status === "error") {
        setPage(null);
        setSelected(null);
        setIssue(result.error);
        return false;
      }
      setPage((previous) => ({
        ...result.data,
        items: cursor ? [...(previous?.items ?? []), ...result.data.items] : result.data.items,
      }));
      setSelected(null);
      return true;
    },
    [commands, organizationId],
  );
  const readPage = useCallback(
    (cursor: string | null) =>
      run(async (current) => {
        await loadPage(cursor, current);
      }),
    [loadPage, run],
  );

  useEffect(() => {
    mounted.current = true;
    void readPage(null);
    return () => {
      mounted.current = false;
      generation.current += 1;
      flight.current = null;
    };
  }, [readPage]);

  const withdraw = () => {
    if (!selected || !page) return;
    const captured = selected;
    void run(async (current) => {
      const result = await commands.withdrawTeamGrant(organizationId, captured.id, captured.etag);
      if (!current()) return;
      if (result.status === "error") {
        setIssue(result.error);
      } else {
        await loadPage(null, current);
      }
    });
  };

  const errorKey =
    issue === "permissionDenied"
      ? "teams.grants.error.denied"
      : issue === "authenticationRequired" || issue === "authentication"
        ? "teams.error.authentication"
        : issue === "authoringConflict"
          ? "teams.grants.error.stale"
          : issue === "authoringUnknown" || issue === "connectionBeforeRequest"
            ? "teams.grants.error.unknown"
            : "teams.grants.error.failed";

  return (
    <Dialog
      open
      title={t("teams.grants.title")}
      description={name}
      closeLabel={t("teams.grants.close")}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      footer={<Button onClick={onClose}>{t("teams.grants.close")}</Button>}
    >
      <div className="flex min-w-0 flex-col gap-4" aria-busy={busy}>
        {busy ? (
          <p role="status" className="text-sm text-muted-foreground">
            {t("teams.grants.loading")}
          </p>
        ) : null}
        {issue ? (
          <p role="alert" className="text-sm text-attention">
            {t(errorKey)}
          </p>
        ) : null}
        <p className="text-sm text-muted-foreground">{t("teams.grants.body")}</p>
        {page?.items.length === 0 ? (
          <p role="status" className="text-sm text-muted-foreground">
            {t("teams.grants.empty")}
          </p>
        ) : null}
        {page?.items.length ? (
          <ul aria-label={t("teams.grants.list")} className="list-none divide-y divide-border p-0">
            {page.items.map((grant) => (
              <li key={grant.id} className="min-w-0 py-3">
                <p className="break-all font-mono text-xs select-text">{grant.id}</p>
                <p className="mt-1 text-sm">
                  {grant.remoteUser} · {t(`teams.grants.status.${grant.status}`)}
                </p>
                <dl className="my-2 flex min-w-0 flex-col gap-2">
                  <Detail label={t("teams.grants.membership")} value={grant.membershipId} />
                  <Detail label={t("teams.grants.host")} value={grant.hostId} />
                  <Detail label={t("teams.grants.validFrom")} value={grant.validFrom} />
                  <Detail label={t("teams.grants.validUntil")} value={grant.validUntil ?? t("teams.grants.never")} />
                </dl>
                <Button variant="secondary" disabled={busy} onClick={() => setSelected(grant)}>
                  {t("teams.grants.withdraw")}
                </Button>
              </li>
            ))}
          </ul>
        ) : null}
        {page?.nextCursor ? (
          <Button variant="secondary" disabled={busy} onClick={() => void readPage(page.nextCursor)}>
            {t("teams.more")}
          </Button>
        ) : null}
        <Button variant="secondary" disabled={busy} onClick={() => void readPage(null)}>
          {t("teams.grants.refresh")}
        </Button>
      </div>
      <Dialog
        open={selected !== null}
        title={t("teams.grants.withdrawTitle")}
        description={t("teams.grants.withdrawBody")}
        closeLabel={t("teams.grants.cancel")}
        onOpenChange={(open) => {
          if (!open && !busy) setSelected(null);
        }}
        footer={
          <>
            <Button variant="secondary" disabled={busy} onClick={() => setSelected(null)}>
              {t("teams.grants.cancel")}
            </Button>
            <Button variant="primary" disabled={busy || selected === null} onClick={withdraw}>
              {t("teams.grants.confirmWithdraw")}
            </Button>
          </>
        }
      >
        {selected ? <p className="break-all font-mono text-xs select-text">{selected.id}</p> : null}
      </Dialog>
    </Dialog>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="m-0 break-all text-sm font-mono select-text">{value}</dd>
    </div>
  );
}
