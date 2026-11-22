// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

assert(["darwin", "win32"].includes(process.platform), "packaged helper checks require a supported desktop platform");
const scratch = mkdtempSync(join(tmpdir(), "scoplen-cli-package-"));
let passed = false;

function generationFailure(fixtureStderr) {
  if (/^Error: Elapsed\(\(\)\)\r?$/m.test(fixtureStderr)) return "helper-timeout";
  // publish_generation retains these two streams locally once the packaged spl process exits.
  try {
    // The CLI writes its fixed refusal last; preceding platform diagnostics stay private.
    const lastLine = readFileSync(join(scratch, "packaged-helper-helper.stderr"), "utf8")
      .trimEnd()
      .split(/\r?\n/)
      .at(-1);
    switch (lastLine) {
      case "The system keychain requires user interaction. Unlock it or authorize this helper in an interactive session.":
        return "keychain-interaction-required";
      case "The saved local key was not found. Check the selected desktop data directory.":
        return "key-not-found";
      case "The data protection Keychain could not authorize this helper to read the saved local key.":
        return "protected-keychain-authorization-failed";
      case "The login Keychain could not authorize this helper to read the saved local key.":
        return "login-keychain-authorization-failed";
      case "The system keystore could not read the saved local key. Check it in the desktop client.":
        return "keystore-read-failed";
      case "The saved local key has an invalid format. Check it in the desktop client.":
        return "malformed-key";
      case "The encrypted store could not be read with the saved key. Check it in the desktop client.":
        return "store-key-rejected";
      case "The local passphrase is not correct. Check the selected passphrase file.":
        return "wrong-passphrase";
      case "The existing local data could not be read. Check it in the desktop client.":
        return "store-read-failed";
      case "the generated OpenSSH selection is invalid":
        return "invalid-selection";
      case "the generated OpenSSH configuration could not be published":
        return "publication-failed";
    }
    const stdout = readFileSync(join(scratch, "packaged-helper-helper.stdout"), "utf8");
    if (/^Published \d+ compatible Logins in \d+ files\.\r?$/m.test(stdout)) return "published-output-check";
    if (fixtureStderr.includes('Error: "actual generated-Include helper failed; private process evidence required"')) {
      return "helper-refused";
    }
    return "helper-result-unconfirmed";
  } catch {
    return "helper-result-unavailable";
  }
}

function run(executable, args, label, options = {}) {
  const result = spawnSync(executable, args, {
    encoding: "utf8",
    windowsHide: true,
    timeout: 60_000,
    ...options,
  });
  writeFileSync(join(scratch, `${label}.stdout`), result.stdout ?? "");
  writeFileSync(join(scratch, `${label}.stderr`), result.stderr ?? "");
  // Only fixed fixture markers may reach CI; raw stderr can contain local paths.
  let phase;
  let step;
  let category;
  let writer;
  for (const line of (result.stderr ?? "").split(/\r?\n/)) {
    const phaseMarker = /^packaged-helper: phase=(fixture|helper|openssh|recheck|cleanup)$/.exec(line);
    const stepMarker =
      /^packaged-helper: step=(create-directory|local-data-start|local-data-status|passphrase-set|passphrase-create|passphrase-write|inventory-open|inventory-preview|resolve-directory)$/.exec(
        line,
      );
    const categoryMarker =
      /^packaged-helper: error=(io-not-found|io-permission-denied|io-other|local-data-wrong-passphrase|local-data-empty-passphrase|local-data-passphrase-required|local-data-invalid-state|local-data-failed|unexpected)$/.exec(
        line,
      );
    if (phaseMarker) {
      phase = phaseMarker[1];
      step = undefined;
      category = undefined;
    }
    if (stepMarker) {
      step = stepMarker[1];
      category = undefined;
    }
    if (categoryMarker) category = categoryMarker[1];
  }
  if (label === "generate" && phase === "helper" && result.status !== 0) {
    category = generationFailure(result.stderr ?? "");
    writer = /^packaged-helper: writer=(reopened|refused|unavailable)\r?$/m.exec(result.stderr ?? "")?.[1];
  }
  const failure = result.error
    ? result.error.code === "ETIMEDOUT"
      ? "timeout"
      : "spawn-error"
    : result.signal
      ? `signal=${result.signal}`
      : `exit=${result.status}`;
  assert(
    !result.error && result.status === 0,
    `${label} failed (${failure}${phase ? `, phase=${phase}` : ""}${step ? `, step=${step}` : ""}${category ? `, category=${category}` : ""}${writer ? `, writer=${writer}` : ""})`,
  );
  return result.stdout;
}

try {
  if (process.platform === "win32") {
    // OpenSSH rejects Include files with broad inherited permissions.
    run(
      "pwsh",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        `$ErrorActionPreference = 'Stop'
$owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($owner)
$acl.SetAccessRuleProtection($true, $false)
$inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
foreach ($sid in @($owner, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', $inherit, 'None', 'Allow'))
}
Set-Acl -LiteralPath $env:SCOPLEN_CLI_PACKAGE_SCRATCH -AclObject $acl`,
      ],
      "fixture-permissions",
      { env: { ...process.env, SCOPLEN_CLI_PACKAGE_SCRATCH: scratch } },
    );
  }
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
  // Unix mkdir(data/.) requires data to exist before testing the noncanonical spelling.
  mkdirSync(join(scratch, "data"));
  run(
    join(target, `release/examples/openssh_export_smoke${suffix}`),
    // Keep a noncanonical spelling to verify the keystore namespace and resolved output separately.
    ["--packaged-helper", helper, `${join(scratch, "data")}/.`],
    "generate",
    { timeout: 120_000 },
  );
  passed = true;
  console.log(
    "Packaged console helper passed help, version, and actual Include generation without opening a desktop window.",
  );
} finally {
  if (passed) rmSync(scratch, { recursive: true });
  else console.error("Packaged helper failed; local process diagnostics retained.");
}
