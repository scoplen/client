// SPDX-License-Identifier: Apache-2.0
import { Button, ChoiceList, Dialog, Field, Mark, Segmented, TextAreaField, type MarkMood } from "@scoplen/ui";
import { ChevronRight, FileKey } from "lucide-react";
import { useState, type FocusEvent, type FormEvent } from "react";
import { useI18n } from "../i18n";
import { useInventory, type AddHostError, type HostDetails, type SignIn } from "./api";

type Method = "password" | "key" | "agent" | "keyboardInteractive";
type KeySource = "file" | "paste" | "generate";
type Problem = { field: "address" | "port" | "username" | "password" | "key" | "form"; message: string };

/**
 * Where the dialog's mark looks while each field has focus. It watches what
 * is typed, except a secret: for a password or a key it shuts its eyes and
 * turns away.
 */
const watching: Record<string, { mood: MarkMood; look?: { x: number; y: number }; tilt?: number }> = {
  address: { mood: "awake", look: { x: 0.2, y: 1 } },
  username: { mood: "awake", look: { x: 0.1, y: 1 } },
  secret: { mood: "closed", tilt: -14 },
  name: { mood: "awake", look: { x: 0.5, y: 1 } },
  port: { mood: "awake", look: { x: 1, y: 1 } },
};

/**
 * Adding a host asks only what the first connection needs: where the host
 * is, who to sign in as, and how (`01-product-definition.md` §7.6, tier 0).
 * The login, the key or password, and the direct route are created with it.
 */
export function AddHostDialog({
  open,
  onOpenChange,
  onAdded,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onAdded: (host: HostDetails) => void;
}) {
  const { t } = useI18n();
  const api = useInventory();
  const [address, setAddress] = useState("");
  const [username, setUsername] = useState("");
  const [method, setMethod] = useState<Method>("password");
  const [password, setPassword] = useState("");
  const [keySource, setKeySource] = useState<KeySource>("file");
  const [keyPath, setKeyPath] = useState<string | null>(null);
  const [keyText, setKeyText] = useState("");
  const [more, setMore] = useState(false);
  const [name, setName] = useState("");
  const [port, setPort] = useState("");
  const [problem, setProblem] = useState<Problem | null>(null);
  const [busy, setBusy] = useState(false);
  const [watched, setWatched] = useState<string | null>(null);
  const onFocusField = (event: FocusEvent<HTMLFormElement>) =>
    setWatched((event.target as HTMLElement).dataset.watch ?? null);
  const face = (watched && watching[watched]) || { mood: "rest" as const };

  const reset = () => {
    setAddress("");
    setUsername("");
    setMethod("password");
    setPassword("");
    setKeySource("file");
    setKeyPath(null);
    setKeyText("");
    setMore(false);
    setName("");
    setPort("");
    setProblem(null);
  };

  const errorFor = (error: AddHostError): Problem => {
    switch (error.kind) {
      case "invalidAddress":
        return { field: "address", message: t("add.error.invalidAddress") };
      case "invalidPort":
        return { field: "port", message: t("add.error.invalidPort") };
      case "emptyUsername":
        return { field: "username", message: t("add.error.emptyUsername") };
      case "emptyPassword":
        return { field: "password", message: t("add.error.emptyPassword") };
      case "keyNotFound":
        return { field: "key", message: t("add.error.keyNotFound") };
      case "keyTooLarge":
        return { field: "key", message: t("add.error.keyTooLarge") };
      case "keyReuseLimit":
        return { field: "form", message: t("add.error.keyReuseLimit") };
      case "notAPrivateKey":
        return { field: "key", message: t("add.error.notAPrivateKey") };
      case "publicKey":
        return { field: "key", message: t("add.error.publicKey") };
      case "puttyKey":
        return { field: "key", message: t("add.error.puttyKey") };
      case "failed":
        return {
          field: "form",
          message: `${t("failed.body")} ${t("startup.error.reference", { reference: error.reference })}`,
        };
    }
  };

  // Checks what can be checked here; the core checks the rest.
  const check = (): { problem: Problem } | { signIn: SignIn; port: number | null } => {
    if (address.trim() === "") return { problem: { field: "address", message: t("add.error.invalidAddress") } };
    if (username.trim() === "") return { problem: { field: "username", message: t("add.error.emptyUsername") } };
    let signIn: SignIn;
    if (method === "password") {
      if (password === "") return { problem: { field: "password", message: t("add.error.emptyPassword") } };
      signIn = { kind: "password", password };
    } else if (method === "keyboardInteractive") {
      signIn = { kind: "keyboardInteractive" };
    } else if (method === "agent") {
      signIn = { kind: "agent" };
    } else if (keySource === "file") {
      if (!keyPath) return { problem: { field: "key", message: t("add.error.noKeyFile") } };
      signIn = { kind: "keyFile", path: keyPath };
    } else if (keySource === "paste") {
      if (keyText.trim() === "") return { problem: { field: "key", message: t("add.error.notAPrivateKey") } };
      signIn = { kind: "keyText", key: keyText };
    } else {
      signIn = { kind: "generateKey" };
    }
    let portNumber: number | null = null;
    if (port.trim() !== "") {
      portNumber = Number(port);
      if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
        setMore(true);
        return { problem: { field: "port", message: t("add.error.invalidPort") } };
      }
    }
    return { signIn, port: portNumber };
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const checked = check();
    if ("problem" in checked) return setProblem(checked.problem);
    setProblem(null);
    setBusy(true);
    try {
      const outcome = await api.addHost({
        name: name.trim() === "" ? null : name.trim(),
        address: address.trim(),
        port: checked.port,
        username: username.trim(),
        signIn: checked.signIn,
      });
      if (outcome.status === "ok") {
        onAdded(outcome.data);
        onOpenChange(false);
        reset();
      } else {
        const next = errorFor(outcome.error);
        if (next.field === "port") setMore(true);
        setProblem(next);
      }
    } catch (thrown) {
      setProblem(errorFor({ kind: "failed", reference: String(thrown) }));
    } finally {
      setBusy(false);
    }
  };

  const error = (field: Problem["field"]) => (problem?.field === field ? problem.message : undefined);

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={t("add.title")}
      description={t("add.description")}
      closeLabel={t("add.close")}
      // A problem makes the mark shake its head once.
      mark={
        <Mark
          size="2.5rem"
          mood={busy ? "awake" : face.mood}
          look={busy ? { x: 0, y: -0.6 } : face.look}
          tilt={face.tilt}
          gesture={{ name: "shake", at: problem }}
        />
      }
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            {t("add.cancel")}
          </Button>
          <Button variant="primary" type="submit" form="add-host" busy={busy}>
            {t("add.submit")}
          </Button>
        </>
      }
    >
      <form
        id="add-host"
        onSubmit={(e) => void submit(e)}
        onFocus={onFocusField}
        onBlur={() => setWatched(null)}
        noValidate
        className="flex flex-col gap-5"
      >
        <Field
          label={t("add.address")}
          hint={t("add.address.hint")}
          value={address}
          onChange={(e) => setAddress(e.target.value)}
          error={error("address")}
          data-watch="address"
          autoFocus
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
          className="[&_input]:font-mono"
        />
        <Field
          label={t("add.username")}
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          error={error("username")}
          data-watch="username"
          autoComplete="username"
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
          className="[&_input]:font-mono"
        />

        <Segmented<Method>
          legend={t("add.signIn")}
          value={method}
          onChange={(next) => {
            setMethod(next);
            setProblem(null);
          }}
          options={[
            { value: "password", label: t("add.signIn.password") },
            { value: "key", label: t("add.signIn.key") },
            { value: "agent", label: t("add.signIn.agent") },
            { value: "keyboardInteractive", label: t("add.signIn.keyboardInteractive") },
          ]}
        />

        {method === "keyboardInteractive" ? (
          <p className="m-0 text-sm text-muted-foreground">{t("add.interactive.hint")}</p>
        ) : null}
        {method === "password" ? (
          <Field
            label={t("add.password")}
            hint={t("add.password.hint")}
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            error={error("password")}
            data-watch="secret"
          />
        ) : null}

        {method === "key" ? (
          <div className="flex flex-col gap-4">
            <ChoiceList<KeySource>
              legend={t("add.key.source")}
              value={keySource}
              onChange={(next) => {
                setKeySource(next);
                setProblem(null);
              }}
              choices={[
                { value: "file", label: t("add.key.file"), description: t("add.key.file.description") },
                { value: "paste", label: t("add.key.paste"), description: t("add.key.paste.description") },
                { value: "generate", label: t("add.key.generate"), description: t("add.key.generate.description") },
              ]}
            />
            {keySource === "file" ? (
              <div className="flex flex-col gap-1.5">
                <div className="flex items-center gap-3">
                  <Button
                    onClick={() =>
                      void api.chooseKeyFile().then((path) => {
                        if (path) {
                          setKeyPath(path);
                          setProblem(null);
                        }
                      })
                    }
                    className="gap-1.5 pl-3"
                  >
                    <FileKey aria-hidden="true" className="size-4" />
                    {t("add.key.choose")}
                  </Button>
                  {keyPath ? (
                    <span className="min-w-0 truncate font-mono text-xs text-muted-foreground">{keyPath}</span>
                  ) : null}
                </div>
                {error("key") ? (
                  <p role="alert" className="m-0 text-sm text-attention">
                    {error("key")}
                  </p>
                ) : null}
              </div>
            ) : null}
            {keySource === "paste" ? (
              <TextAreaField
                label={t("add.key.text")}
                hint={t("add.key.text.hint")}
                value={keyText}
                onChange={(e) => setKeyText(e.target.value)}
                error={error("key")}
                data-watch="secret"
                spellCheck={false}
                autoCapitalize="off"
                autoCorrect="off"
              />
            ) : null}
            {keySource === "generate" ? (
              <p className="m-0 text-sm text-muted-foreground">{t("add.key.generate.hint")}</p>
            ) : null}
          </div>
        ) : null}

        {method === "agent" ? <p className="m-0 text-sm text-muted-foreground">{t("add.agent.hint")}</p> : null}

        <div>
          <button
            type="button"
            aria-expanded={more}
            onClick={() => setMore(!more)}
            className="-ml-1 flex items-center gap-1 rounded px-1 py-0.5 text-sm text-muted-foreground hover:text-foreground"
          >
            <ChevronRight
              aria-hidden="true"
              className={`size-4 transition-transform duration-(--duration-micro) ${more ? "rotate-90" : ""}`}
            />
            {t("add.more")}
          </button>
          {more ? (
            <div className="mt-4 grid grid-cols-[minmax(0,1fr)_7rem] gap-4">
              <Field
                label={t("add.name")}
                hint={t("add.name.hint")}
                value={name}
                onChange={(e) => setName(e.target.value)}
                data-watch="name"
              />
              <Field
                label={t("add.port")}
                inputMode="numeric"
                placeholder="22"
                value={port}
                onChange={(e) => setPort(e.target.value)}
                data-watch="port"
                error={error("port")}
                className="[&_input]:font-mono"
              />
            </div>
          ) : null}
        </div>

        {error("form") ? (
          <p role="alert" className="m-0 text-sm text-attention">
            {error("form")}
          </p>
        ) : null}
      </form>
    </Dialog>
  );
}
