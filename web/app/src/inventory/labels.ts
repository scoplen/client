// SPDX-License-Identifier: Apache-2.0
import type { useI18n } from "../i18n";
import type { CredentialLabel, RouteLabel } from "./api";

type Translate = ReturnType<typeof useI18n>["t"];

const routeKeys = {
  jump: "host.route.jump",
  proxy: "host.route.proxy",
  command: "host.route.command",
  bastion: "host.route.bastion",
} as const;

const credentialKeys = {
  keyboardInteractive: "host.credential.keyboardInteractive",
  password: "host.credential.password",
  agent: "host.credential.agent",
  securityKey: "host.credential.securityKey",
  deviceKey: "host.credential.deviceKey",
  external: "host.credential.external",
  certificate: "host.credential.certificate",
} as const;

/** How the interface names a login's route. */
export function routeText(t: Translate, route: RouteLabel): string {
  return route.kind === "direct" ? t("host.route.direct") : t(routeKeys[route.kind], { name: route.name });
}

/** How the interface names a credential: its name, else what it is. */
export function credentialText(t: Translate, credential: CredentialLabel | null): string {
  if (!credential) return t("host.credential.any");
  if (credential.kind === "key") {
    const label = credential.name ?? credential.comment ?? shortFingerprint(credential.fingerprint);
    return t("host.credential.key", { label });
  }
  return credential.name ?? t(credentialKeys[credential.kind]);
}

/** The first characters of a fingerprint, enough to tell keys apart. */
export function shortFingerprint(fingerprint: string | null): string {
  if (!fingerprint) return "";
  const [algorithm, digest = ""] = fingerprint.split(":");
  return `${algorithm}:${digest.slice(0, 8)}…`;
}
