// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

assert(["darwin", "win32"].includes(process.platform), "packaged helper checks require a supported desktop platform");
const scratch = mkdtempSync(join(tmpdir(), "scoplen-cli-package-"));
let passed = false;

function run(executable, args, label, options = {}) {
  const result = spawnSync(executable, args, {
    encoding: "utf8",
    windowsHide: true,
    timeout: 60_000,
    ...options,
  });
  writeFileSync(join(scratch, `${label}.stdout`), result.stdout ?? "");
  writeFileSync(join(scratch, `${label}.stderr`), result.stderr ?? "");
  assert(!result.error && result.status === 0, `${label} failed`);
  return result.stdout;
}

try {
  const target = JSON.parse(
    run("cargo", ["metadata", "--locked", "--no-deps", "--format-version", "1"], "metadata"),
  ).target_directory;
  const suffix = process.platform === "win32" ? ".exe" : "";
  let helper;
  if (process.platform === "darwin") {
    helper = join(target, "release/bundle/macos/Scoplen.app/Contents/MacOS/spl");
  } else {
    const directory = join(target, "release/bundle/nsis");
    const installers = readdirSync(directory).filter((name) => name.endsWith(".exe"));
    assert.equal(installers.length, 1, "expected one freshly built NSIS package");
    const extracted = join(scratch, "extracted");
    // The Windows runner image supplies 7zip; extraction does not run the installer.
    run("7z", ["x", "-y", `-o${extracted}`, join(directory, installers[0])], "extract");
    helper = join(extracted, "spl.exe");
  }
  assert(existsSync(helper), "desktop package omitted the console helper");
  const missing = join(scratch, "missing-store");
  const env = { ...process.env, SPL_DATA_DIR: missing };
  assert(run(helper, ["--help"], "help", { env }).includes("config"));
  assert(run(helper, ["--version"], "version", { env }).trim().startsWith("spl "));
  assert(!existsSync(missing), "help or version created application data");

  run(
    "cargo",
    ["build", "--locked", "--release", "-p", "scoplen-client-core", "--example", "openssh_export_smoke"],
    "build-fixture",
    { timeout: 600_000 },
  );
  run(
    join(target, `release/examples/openssh_export_smoke${suffix}`),
    ["--packaged-helper", helper, join(scratch, "data")],
    "generate",
    { timeout: 120_000 },
  );
  passed = true;
  console.log(
    "Packaged console helper passed help, version, and actual Include generation without opening a desktop window.",
  );
} finally {
  if (passed) rmSync(scratch, { recursive: true });
  else console.error(`Packaged helper diagnostics retained: ${scratch}`);
}
