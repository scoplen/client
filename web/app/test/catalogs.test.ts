// SPDX-License-Identifier: Apache-2.0
import { createTranslator } from "@scoplen/ui";
import { catalogs } from "../src/i18n";
import { en } from "../src/messages/en";
import type { SessionState } from "../src/session";

const sessionStates = {
  verifying: true,
  trusting: true,
  passphrase: true,
  keyboardInteractive: true,
  connecting: true,
  reconnecting: true,
  connected: true,
  closed: true,
  failed: true,
} satisfies Record<SessionState, true>;

/** Sample values for every placeholder used in the catalogs. */
const sample = {
  version: "0.1.0",
  platform: "windows",
  reference: "E-1",
  count: 3,
  capacity: 16,
  bytes: 1024,
  connection: "deploy@fixture.example",
  skipped: 2,
  line: 5,
  directive: "Include",
  name: "prod-db-01",
  roles: "Owner",
  query: "db",
  username: "deploy",
  label: "laptop",
  path: "/home/mia/.ssh/id_ed25519",
  field: "name",
  color: "Red",
  attempt: 2,
  seconds: 2,
  time: "15:30",
  id: "019a0123-4567-7890-8123-456789abcdef",
  downloaded: 2,
  uploaded: 3,
  transferred: "1,024",
  total: "4,096",
  percent: 25,
  sequence: "9007199254740993",
  target: "Deployment host",
  folder: "Services",
  tags: "operations",
  number: 1,
};

describe("message catalogs", () => {
  const source = Object.keys(en).sort();

  it.each(Object.entries(catalogs))("%s has exactly the source keys", (_, catalog) => {
    expect(Object.keys(catalog).sort()).toEqual(source);
  });

  it.each(Object.entries(catalogs))("%s formats every message", (locale, catalog) => {
    const { t } = createTranslator(locale, catalog);
    for (const key of source) expect(t(key as keyof typeof en, sample).length, key).toBeGreaterThan(0);
  });

  it.each(Object.entries(catalogs))("%s names every terminal tab state", (_, catalog) => {
    for (const state of Object.keys(sessionStates)) expect(Object.hasOwn(catalog, `frame.state.${state}`)).toBe(true);
  });

  it("writes Chinese without English quotation marks", () => {
    for (const message of Object.values(catalogs["zh-Hans"])) expect(message).not.toMatch(/[“”"]/);
  });
});
