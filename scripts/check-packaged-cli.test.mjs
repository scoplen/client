// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";
import test from "node:test";
import { URL } from "node:url";
import { runInNewContext } from "node:vm";

const source = readFileSync(new URL("./check-packaged-cli.mjs", import.meta.url), "utf8").replace(
  /^import[\s\S]*?;\r?\n/gm,
  "",
);

for (const failGeneration of [false, true]) {
  test(`macOS fixture prepares the aliased directory and ${failGeneration ? "retains failure evidence" : "cleans successful output"}`, () => {
    const root = mkdtempSync(join(tmpdir(), "scoplen-package-runner-test-"));
    const packageRoot = join(root, "package");
    const helper = join(packageRoot, "release/bundle/macos/Scoplen.app/Contents/MacOS/spl");
    let scratch;
    let generated = false;
    try {
      mkdirSync(join(helper, ".."), { recursive: true });
      writeFileSync(helper, "disposable helper stand-in");
      const invoke = () =>
        runInNewContext(source, {
          assert,
          process: { platform: "darwin", env: {} },
          console: { log() {}, error() {} },
          existsSync,
          mkdirSync,
          mkdtempSync(prefix) {
            scratch = mkdtempSync(prefix);
            return scratch;
          },
          readdirSync,
          rmSync,
          writeFileSync,
          tmpdir: () => root,
          join,
          spawnSync(executable, args) {
            const ok = (stdout = "") => ({ status: 0, stdout, stderr: "" });
            if (executable === "cargo" && args[0] === "metadata") {
              return ok(JSON.stringify({ target_directory: packageRoot }));
            }
            if (executable === "cargo" && args[0] === "build") return ok();
            if (executable === helper && args[0] === "--help") return ok("config");
            if (executable === helper && args[0] === "--version") return ok("spl test");
            if (args[0] === "--packaged-helper") {
              assert.equal(args[1], helper);
              assert.equal(args[2], `${join(scratch, "data")}/.`);
              generated = true;
              // Unix mkdir(data/.) cannot create a missing data component.
              if (!existsSync(args[2])) {
                return {
                  status: 1,
                  stdout: "",
                  stderr:
                    "packaged-helper: phase=fixture\npackaged-helper: step=create-directory\npackaged-helper: error=io-not-found\n",
                };
              }
              if (failGeneration) {
                return { status: 1, stdout: "", stderr: "packaged-helper: phase=helper\nprivate child diagnostic\n" };
              }
              return ok();
            }
            assert.fail("unexpected subprocess in packaged helper runner");
          },
        });
      if (failGeneration) assert.throws(invoke, /generate failed \(exit=1, phase=helper\)/);
      else assert.doesNotThrow(invoke);
      assert.equal(generated, true);
      assert.equal(existsSync(scratch), failGeneration);
      if (failGeneration) assert.ok(existsSync(join(scratch, "generate.stderr")));
    } finally {
      const owned = relative(resolve(tmpdir()), root);
      assert.ok(owned.startsWith("scoplen-package-runner-test-") && !isAbsolute(owned));
      rmSync(root, { recursive: true });
    }
  });
}
