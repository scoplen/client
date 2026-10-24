// SPDX-License-Identifier: Apache-2.0
import { createTranslator } from "@scoplen/ui";
import { catalogs } from "../src/i18n";
import { en } from "../src/messages/en";

/** Sample values for every placeholder used in the catalogs. */
const sample = {
  version: "0.1.0",
  platform: "windows",
  reference: "E-1",
  count: 3,
  capacity: 16,
  skipped: 2,
  line: 5,
  directive: "Include",
  name: "prod-db-01",
  query: "db",
  username: "deploy",
  label: "laptop",
  path: "/home/mia/.ssh/id_ed25519",
  field: "name",
  color: "Red",
  attempt: 2,
  seconds: 2,
  id: "019a0123-4567-7890-8123-456789abcdef",
  downloaded: 2,
  uploaded: 3,
  transferred: "1,024",
  total: "4,096",
  percent: 25,
  sequence: "9007199254740993",
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

  it("writes Chinese without English quotation marks", () => {
    for (const message of Object.values(catalogs["zh-Hans"])) expect(message).not.toMatch(/[“”"]/);
  });
});
