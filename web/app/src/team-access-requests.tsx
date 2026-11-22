// SPDX-License-Identifier: Apache-2.0
import { Button, Dialog, Field, Select, TextAreaField } from "@scoplen/ui";
import { useCallback, useEffect, useRef, useState } from "react";
import { useProfileCommands } from "./account-profiles";
import { useI18n } from "./i18n";
import type {
  SessionTarget,
  TeamAccessRequestAction,
  TeamAccessRequestCheckView,
  TeamAccessRequestFields,
  TeamAccessRequestList,
  TeamAccessRequestLogin,
  TeamAccessRequestOperationView,
  TeamAccessRequestPageView,
  TeamAccessRequestResourceView,
  TeamAccessRequestReviewView,
  TeamSshPolicyDenial,
} from "./ipc/bindings";

type Props = {
  organizationId: string;
  name: string;
  denial?: { sessionId: string; target: TeamSshPolicyDenial };
  onClose: () => void;
  onConnect?: (target: SessionTarget) => void;
};

/** Remounts all read and review state when the concrete team or denied session changes. */
export function TeamAccessRequests(props: Props) {
  return <Requests key={`${props.organizationId}:${props.denial?.sessionId ?? ""}`} {...props} />;
}

function Requests({ organizationId, name, denial, onClose, onConnect }: Props) {
  const commands = useProfileCommands();
  const { t } = useI18n();
  const [view, setView] = useState<TeamAccessRequestList>("mine");
  const [page, setPage] = useState<TeamAccessRequestPageView | null>(null);
  const [review, setReview] = useState<TeamAccessRequestReviewView | null>(null);
  const [logins, setLogins] = useState<TeamAccessRequestLogin[]>([]);
  const [login, setLogin] = useState("");
  const [operation, setOperation] = useState<TeamAccessRequestOperationView | null>(null);
  const [pendingLoaded, setPendingLoaded] = useState(false);
  const [expiredReviewed, setExpiredReviewed] = useState<string | null>(null);
  const pendingState = useRef<TeamAccessRequestOperationView | null>(null);
  const [busy, setBusy] = useState(false);
  const [issue, setIssue] = useState<string | null>(null);
  const [duration, setDuration] = useState("3600");
  const [reason, setReason] = useState("");
  const [check, setCheck] = useState<TeamAccessRequestCheckView | null>(null);
  const mounted = useRef(true);
  const generation = useRef(0);
  const flight = useRef<symbol | null>(null);
  const inputRevision = useRef(0);

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

  const readPending = useCallback(
    async (current: () => boolean) => {
      const result = await commands.pendingTeamAccessRequest(organizationId);
      if (!current()) return;
      if (result.status === "error") {
        setPendingLoaded(false);
        setIssue(result.error);
      } else {
        pendingState.current = result.data;
        setOperation(result.data);
        setPendingLoaded(true);
      }
    },
    [commands, organizationId],
  );

  const readPage = useCallback(
    async (cursor: string | null, manual: boolean, current: () => boolean) => {
      const result = await commands.teamAccessRequestPage(organizationId, view, cursor);
      if (!current()) return;
      if (result.status === "error") {
        // Keep the last confirmed page visible so a transient refresh or an
        // explicitly requested next-page failure does not erase reviewable
        // requests. The failed read remains visible for an explicit retry.
        setReview(null);
        setLogins([]);
        setIssue(result.error);
        return;
      }
      setPage((previous) => ({
        ...result.data,
        items: cursor ? [...(previous?.items ?? []), ...result.data.items] : result.data.items,
      }));
      setReview(null);
      setLogins([]);
      if (manual)
        setExpiredReviewed(pendingState.current?.phase === "expired" ? pendingState.current.operationId : null);
    },
    [commands, organizationId, view],
  );

  useEffect(() => {
    mounted.current = true;
    const owner = generation.current;
    void run(async (current) => {
      await readPending(current);
      if (current()) await readPage(null, false, current);
    });
    const timer = setInterval(() => {
      void run(async (current) => {
        await readPending(current);
        if (current()) await readPage(null, false, current);
      });
    }, 60_000);
    return () => {
      clearInterval(timer);
      mounted.current = false;
      generation.current = owner + 1;
      flight.current = null;
    };
  }, [readPage, readPending, run]);

  const submit = async (original: TeamAccessRequestOperationView, current: () => boolean) => {
    const result = await commands.submitTeamAccessRequest(organizationId, original.operationId).catch(() => null);
    if (!current()) return;
    setCheck(null);
    setReview(null);
    setLogins([]);
    if (!result || result.status === "error") {
      await readPending(current);
      if (current()) setIssue(result?.error ?? "outcomeUnknown");
    } else {
      setOperation(result.data);
      if (result.data.phase === "confirmed") await readPage(null, false, current);
    }
  };

  const inspect = (id: string) =>
    void run(async (current) => {
      setReview(null);
      setLogins([]);
      setLogin("");
      const result = await commands.reviewTeamAccessRequest(organizationId, id);
      if (!current()) return;
      if (result.status === "error") setIssue(result.error);
      else {
        setReview(result.data);
        if (result.data.resource.canConnect && onConnect) {
          const choices = await commands.teamAccessRequestLogins(result.data.intentId);
          if (!current()) return;
          if (choices.status === "error") setIssue(choices.error);
          else {
            setLogins(choices.data);
            setLogin(choices.data[0]?.target.profileId ?? "");
            if (choices.data.length === 0) setIssue("loginRequired");
          }
        }
      }
    });

  const decide = (action: TeamAccessRequestAction) => {
    if (!review || operation || !pendingLoaded) return;
    const original = review;
    void run(async (current) => {
      const result = await commands.prepareTeamAccessRequestAction(original.intentId, action);
      if (!current()) return;
      setReview(null);
      setLogins([]);
      if (result.status === "error") setIssue(result.error);
      else {
        setOperation(result.data);
        setExpiredReviewed(null);
        await submit(result.data, current);
      }
    });
  };

  const checkInput = () => {
    if (!denial || operation || !pendingLoaded) return;
    const revision = inputRevision.current;
    setCheck(null);
    void run(async (current) => {
      const result = await commands.checkTeamAccessRequest(denial.sessionId, {
        durationSeconds: Number(duration),
        reason,
      });
      if (!current() || revision !== inputRevision.current) return;
      if (result.status === "error") setIssue(result.error);
      else setCheck(result.data);
    });
  };
  const create = () => {
    if (!check?.allowed || !check.checkId || operation || !pendingLoaded) return;
    const checked = check.checkId;
    void run(async (current) => {
      const result = await commands.prepareTeamAccessRequest(checked);
      if (!current()) return;
      setCheck(null);
      if (result.status === "error") setIssue(result.error);
      else {
        setOperation(result.data);
        setExpiredReviewed(null);
        await submit(result.data, current);
      }
    });
  };
  const discard = () => {
    if (
      !operation ||
      operation.phase === "unknown" ||
      (operation.phase === "expired" && expiredReviewed !== operation.operationId)
    )
      return;
    const original = operation;
    void run(async (current) => {
      const result = await commands.discardTeamAccessRequest(organizationId, original.operationId);
      if (!current()) return;
      if (result.status === "error") setIssue(result.error);
      else {
        setOperation(null);
        setCheck(null);
        setExpiredReviewed(null);
      }
    });
  };
  const errorKey =
    issue === "outcomeUnknown" || issue === "operationPending"
      ? "teams.requests.error.unknown"
      : issue === "staleVersion" || issue === "reviewRequired" || issue === "checkRequired"
        ? "teams.requests.error.stale"
        : issue === "invalidInput"
          ? "teams.requests.error.input"
          : issue === "permissionDenied" || issue === "policyDenied"
            ? "teams.requests.error.denied"
            : issue === "authenticationRequired" || issue === "authentication"
              ? "teams.error.authentication"
              : issue === "loginRequired"
                ? "teams.requests.error.login"
                : issue === "operationExpired"
                  ? "teams.requests.operation.expired"
                  : "teams.requests.error.failed";

  return (
    <Dialog
      open
      title={t(denial ? "teams.requests.reviewAccess" : "teams.requests.title")}
      description={name}
      closeLabel={t("teams.requests.close")}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      footer={<Button onClick={onClose}>{t("teams.requests.close")}</Button>}
    >
      <div className="flex min-w-0 flex-col gap-4" aria-busy={busy}>
        {busy ? (
          <p role="status" className="text-sm text-muted-foreground">
            {t("teams.working")}
          </p>
        ) : null}
        {issue ? (
          <p role="alert" className="text-sm text-attention">
            {t(errorKey)}
          </p>
        ) : null}
        {operation ? (
          <section aria-label={t("teams.requests.operation.title")} className="min-w-0 border-b border-border pb-4">
            <h3 className="text-sm font-medium">{t("teams.requests.operation.title")}</h3>
            <p className="text-sm">{t(`teams.requests.${operation.action}`)}</p>
            <p className="break-all font-mono text-xs select-text">{operation.requestId}</p>
            <p role="status" className="text-sm text-muted-foreground">
              {t(`teams.requests.operation.${operation.phase}`)}
            </p>
            <RequestFields fields={operation.fields} />
            <div className="mt-3 flex flex-wrap gap-2">
              {operation.phase === "unknown" || operation.phase === "prepared" ? (
                <Button disabled={busy} onClick={() => void run((current) => submit(operation, current))}>
                  {t(operation.phase === "unknown" ? "teams.requests.confirm" : "teams.requests.sendOriginal")}
                </Button>
              ) : null}
              {operation.phase !== "unknown" ? (
                <Button
                  variant="secondary"
                  disabled={busy || (operation.phase === "expired" && expiredReviewed !== operation.operationId)}
                  onClick={discard}
                >
                  {t(operation.phase === "expired" ? "teams.requests.archive" : "teams.requests.finish")}
                </Button>
              ) : null}
            </div>
          </section>
        ) : denial && pendingLoaded ? (
          <section
            aria-label={t("teams.requests.reviewAccess")}
            className="flex min-w-0 flex-col gap-3 border-b border-border pb-4"
          >
            <RequestFields
              fields={{
                hostId: denial.target.hostId,
                remoteUser: denial.target.remoteUser,
                durationSeconds: Number(duration),
                reason: "",
              }}
              compact
            />
            <Field
              label={t("teams.requests.duration")}
              type="number"
              min={1}
              max={86400}
              step={1}
              value={duration}
              disabled={busy}
              onChange={(event) => {
                inputRevision.current++;
                setDuration(event.target.value);
                setCheck(null);
              }}
            />
            <TextAreaField
              label={t("teams.requests.reason")}
              value={reason}
              disabled={busy}
              maxLength={2048}
              onChange={(event) => {
                inputRevision.current++;
                setReason(event.target.value);
                setCheck(null);
              }}
            />
            <p className="text-sm text-muted-foreground">{t("teams.requests.checkNotice")}</p>
            {check ? (
              <p role="status" className="text-sm">
                {t(check.allowed ? "teams.requests.eligible" : "teams.requests.ineligible")}
              </p>
            ) : null}
            <div className="flex flex-wrap gap-2">
              <Button
                variant="secondary"
                disabled={
                  busy ||
                  !reason ||
                  !Number.isInteger(Number(duration)) ||
                  Number(duration) < 1 ||
                  Number(duration) > 86400
                }
                onClick={checkInput}
              >
                {t("teams.requests.check")}
              </Button>
              {check?.allowed && check.checkId ? (
                <Button variant="primary" disabled={busy} onClick={create}>
                  {t("teams.requests.create")}
                </Button>
              ) : null}
            </div>
          </section>
        ) : null}
        <div className="flex flex-wrap items-end gap-2">
          <Select
            label={t("teams.requests.view")}
            value={view}
            options={[
              { value: "mine", label: t("teams.requests.mine") },
              { value: "approvals", label: t("teams.requests.approvals") },
            ]}
            disabled={busy}
            onValueChange={(next) => {
              setPage(null);
              setReview(null);
              setLogins([]);
              setCheck(null);
              setView(next);
            }}
          />
          <Button
            variant="secondary"
            disabled={busy}
            onClick={() =>
              void run(async (current) => {
                await readPending(current);
                if (current()) await readPage(null, true, current);
              })
            }
          >
            {t("teams.requests.refresh")}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">{t("teams.requests.refreshNotice")}</p>
        {page?.items.length === 0 ? (
          <p role="status" className="text-sm text-muted-foreground">
            {t(view === "mine" ? "teams.requests.emptyMine" : "teams.requests.emptyApprovals")}
          </p>
        ) : null}
        {page?.items.length ? (
          <ul
            aria-label={t(view === "mine" ? "teams.requests.mine" : "teams.requests.approvals")}
            className="list-none divide-y divide-border p-0"
          >
            {page.items.map((item) => (
              <li key={item.id} className="min-w-0 py-3">
                <p className="m-0 break-all font-mono text-xs select-text">{item.id}</p>
                <p className="mt-1 text-sm">{requestStatus(item, t)}</p>
                <p className="text-sm break-all">
                  {item.fields.remoteUser} · {item.fields.hostId}
                </p>
                <Button variant="secondary" disabled={busy} onClick={() => inspect(item.id)}>
                  {t("teams.requests.review")}
                </Button>
              </li>
            ))}
          </ul>
        ) : null}
        {page?.nextCursor ? (
          <Button
            variant="secondary"
            disabled={busy}
            onClick={() => void run((current) => readPage(page.nextCursor, false, current))}
          >
            {t("teams.more")}
          </Button>
        ) : null}
        {review ? (
          <section aria-label={t("teams.requests.details")} className="min-w-0 border-t border-border pt-4">
            <h3 className="text-sm font-medium">{t("teams.requests.details")}</h3>
            <RequestDetails resource={review.resource} />
            <div className="mt-4 flex flex-wrap gap-2">
              {review.resource.canDecide ? (
                <>
                  <Button
                    variant="primary"
                    disabled={busy || !!operation || !pendingLoaded}
                    onClick={() => decide("approve")}
                  >
                    {t("teams.requests.approve")}
                  </Button>
                  <Button
                    variant="secondary"
                    disabled={busy || !!operation || !pendingLoaded}
                    onClick={() => decide("deny")}
                  >
                    {t("teams.requests.deny")}
                  </Button>
                </>
              ) : null}
              {review.resource.canCancel ? (
                <Button
                  variant="secondary"
                  disabled={busy || !!operation || !pendingLoaded}
                  onClick={() => decide("cancel")}
                >
                  {t("teams.requests.cancel")}
                </Button>
              ) : null}
            </div>
            {review.resource.canConnect && onConnect && logins.length ? (
              <div className="mt-4 flex flex-col gap-3">
                <p className="text-sm text-muted-foreground">{t("teams.requests.connectNotice")}</p>
                <Select
                  label={t("teams.requests.login")}
                  value={login}
                  options={logins.map((item) => ({ value: item.target.profileId, label: item.name }))}
                  onValueChange={setLogin}
                  disabled={busy}
                />
                <Button
                  variant="primary"
                  disabled={busy || !login}
                  onClick={() => {
                    const selected = logins.find((item) => item.target.profileId === login);
                    if (selected) {
                      onClose();
                      onConnect(selected.target);
                    }
                  }}
                >
                  {t("teams.requests.connect")}
                </Button>
              </div>
            ) : null}
          </section>
        ) : null}
      </div>
    </Dialog>
  );
}

type Translate = ReturnType<typeof useI18n>["t"];
function requestStatus(resource: TeamAccessRequestResourceView, t: Translate) {
  const status = resource.status === "pending" && resource.deadlinePassed ? "deadline" : resource.status;
  switch (status) {
    case "pending":
    case "approved":
    case "denied":
    case "expired":
    case "cancelled":
    case "deadline":
      return t(`teams.requests.status.${status}`);
    default:
      return t("teams.requests.status.unknown", { status });
  }
}
function Detail({ label, value, literal = false }: { label: string; value: string; literal?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd
        className={`m-0 mt-1 whitespace-pre-wrap break-words text-sm select-text [overflow-wrap:anywhere] ${literal ? "font-mono" : ""}`}
      >
        {value}
      </dd>
    </div>
  );
}
function RequestFields({ fields, compact = false }: { fields: TeamAccessRequestFields; compact?: boolean }) {
  const { t } = useI18n();
  return (
    <dl className="my-3 flex min-w-0 flex-col gap-3">
      <Detail label={t("teams.requests.host")} value={fields.hostId} literal />
      <Detail label={t("teams.requests.user")} value={fields.remoteUser} literal />
      {!compact ? (
        <>
          <Detail label={t("teams.requests.duration")} value={String(fields.durationSeconds)} />
          <Detail label={t("teams.requests.reason")} value={fields.reason} />
        </>
      ) : null}
    </dl>
  );
}
function RequestDetails({ resource }: { resource: TeamAccessRequestResourceView }) {
  const { t } = useI18n();
  return (
    <>
      <p className="text-sm">{requestStatus(resource, t)}</p>
      <dl className="my-3 flex min-w-0 flex-col gap-3">
        <Detail label={t("teams.requests.requester")} value={resource.requesterAccountId} literal />
        <Detail label={t("teams.requests.membership")} value={resource.requesterMembershipId} literal />
        <Detail label={t("teams.requests.deadline")} value={resource.expiresAt} literal />
      </dl>
      <RequestFields fields={resource.fields} />
      {resource.decision ? (
        <dl className="my-3 flex min-w-0 flex-col gap-3">
          <Detail label={t("teams.requests.actor")} value={resource.decision.actorAccountId} literal />
          <Detail label={t("teams.requests.decidedAt")} value={resource.decision.decidedAt} literal />
        </dl>
      ) : null}
      {resource.grant ? (
        <>
          <p className="text-sm text-muted-foreground">{t("teams.requests.historyNotice")}</p>
          <dl className="my-3 flex min-w-0 flex-col gap-3">
            <Detail label={t("teams.requests.grant")} value={resource.grant.id} literal />
            <Detail label={t("teams.requests.validFrom")} value={resource.grant.validFrom} literal />
            <Detail label={t("teams.requests.validUntil")} value={resource.grant.validUntil} literal />
          </dl>
        </>
      ) : null}
    </>
  );
}
