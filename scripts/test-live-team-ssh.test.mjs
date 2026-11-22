// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { URL, fileURLToPath } from "node:url";
import test from "node:test";

const runner = fileURLToPath(new URL("./test-live-team-ssh.ps1", import.meta.url));

// Execute the public PowerShell runner; only its external Docker/Cargo consumers are stubs.
const wrapper = String.raw`
param([string]$Runner, [string]$Deployment, [string]$Scenario, [string]$Mode)
$ErrorActionPreference = 'Stop'
$script:removed = $false
$script:called = $false
$script:passwordMatches = $false
$script:passwordEnabled = $false
$script:secret = 'private-diagnostic-' + [guid]::NewGuid().ToString('N')
$script:fixture = $null
function docker {
    $global:LASTEXITCODE = 0
    switch ($args[0]) {
        'run' {
            $script:owner = $args[[Array]::IndexOf($args, '--label') + 1].Split('=')[1]
            $script:container = $args[[Array]::IndexOf($args, '--name') + 1]
            $script:passwordEnabled = $args -contains 'PASSWORD_ACCESS=true'
            $script:dockerPassword = @($args | Where-Object { $_.StartsWith('USER_PASSWORD=') })
            return 'stub-container'
        }
        'port' { return "127.0.0.1:$env:SCOPLEN_RUNNER_TEST_PORT" }
        'inspect' { return $script:owner }
        'logs' { return $script:secret }
        'rm' {
            if ($args[2] -ne $script:container) { throw 'Unexpected fixture cleanup' }
            $script:removed = $true
        }
        default { throw 'Unexpected Docker operation' }
    }
}
function cargo {
    $script:called = $true
    $script:testArguments = $args
    $descriptor = Get-Content -LiteralPath $env:SCOPLEN_LIVE_TEAM_SSH_FIXTURE -Raw | ConvertFrom-Json
    if (-not $descriptor.disposable -or $descriptor.owner -ne $script:owner -or
        $descriptor.container -ne $script:container -or $descriptor.port -ne [int]$env:SCOPLEN_RUNNER_TEST_PORT) {
        throw 'Unexpected descriptor'
    }
    if ($env:SCOPLEN_LIVE_ACCOUNT_DEPLOYMENT -ne (Resolve-Path -LiteralPath $Deployment).Path) {
        throw 'Unexpected deployment'
    }
    $script:fixture = Split-Path $env:SCOPLEN_LIVE_TEAM_SSH_FIXTURE
    $script:passwordAbsent = -not $env:SCOPLEN_LIVE_PERSONAL_SSH_PASSWORD_FILE
    if (-not $script:passwordAbsent) {
        $password = Get-Content -LiteralPath $env:SCOPLEN_LIVE_PERSONAL_SSH_PASSWORD_FILE -Raw
        $script:passwordMatches = $script:dockerPassword.Count -eq 1 -and
            $script:dockerPassword[0] -ceq "USER_PASSWORD=$password" -and
            $password.Length -gt 20 -and $password -notmatch '[\r\n]'
        $script:secret = $password
    }
    $global:LASTEXITCODE = if ($Mode -eq 'failure') { 1 } else { 0 }
    if ($Mode -eq 'failure') { return $script:secret }
    if ($Mode -eq 'empty') { return 'test result: ok. 0 passed; 0 failed; 0 ignored;' }
    return 'test result: ok. 1 passed; 0 failed; 0 ignored;'
}
$env:SCOPLEN_LIVE_ACCOUNT_DEPLOYMENT = 'previous-deployment'
$env:SCOPLEN_LIVE_TEAM_SSH_FIXTURE = 'previous-fixture'
$env:SCOPLEN_LIVE_PERSONAL_SSH_PASSWORD_FILE = 'previous-password-file'
$caught = $false
$captured = @(& {
    try {
        if ($Scenario -eq 'Default') { . $Runner -Deployment $Deployment }
        else { . $Runner -Deployment $Deployment -Scenario $Scenario }
    } catch {
        $script:caught = $true
        $_.Exception.Message
    }
} *>&1)
$output = $captured -join "\n"
$retained = $script:fixture -and (Test-Path -LiteralPath $script:fixture)
@{
    caught = $script:caught
    called = $script:called
    test_arguments = @($script:testArguments)
    password_enabled = $script:passwordEnabled
    password_matches = $script:passwordMatches
    password_absent = $script:passwordAbsent
    removed = $script:removed
    retained = [bool]$retained
    retained_log = [bool]($retained -and (Test-Path -LiteralPath (Join-Path $script:fixture 'acceptance.log')))
    retained_ssh_log = [bool]($retained -and (Test-Path -LiteralPath (Join-Path $script:fixture 'openssh.log')))
    secret_exposed = $output.Contains($script:secret)
    restored = $env:SCOPLEN_LIVE_ACCOUNT_DEPLOYMENT -eq 'previous-deployment' -and
        $env:SCOPLEN_LIVE_TEAM_SSH_FIXTURE -eq 'previous-fixture' -and
        $env:SCOPLEN_LIVE_PERSONAL_SSH_PASSWORD_FILE -eq 'previous-password-file'
} | ConvertTo-Json -Compress
`;

async function execute(scenario, mode = "success") {
  const root = await mkdtemp(join(tmpdir(), "scoplen-runner-test-"));
  const server = createServer((socket) => socket.end("SSH-2.0-runner-test\r\n"));
  try {
    const script = join(root, "wrapper.ps1");
    const deployment = join(root, "deployment.json");
    await writeFile(script, wrapper);
    await writeFile(deployment, "{}");
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const child = spawn("pwsh", ["-NoProfile", "-File", script, runner, deployment, scenario, mode], {
      cwd: dirname(runner),
      env: {
        ...process.env,
        TMP: root,
        TEMP: root,
        TMPDIR: root,
        SCOPLEN_RUNNER_TEST_PORT: String(server.address().port),
      },
      windowsHide: true,
      timeout: 20000,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => (stdout += chunk));
    child.stderr.setEncoding("utf8").on("data", (chunk) => (stderr += chunk));
    const [code] = await once(child, "close");
    assert.ok(code === 0 && stderr.length === 0, "PowerShell regression wrapper must complete cleanly");
    // Never include private child output in an assertion failure.
    let result;
    try {
      result = JSON.parse(stdout.trim());
    } catch {
      assert.fail("PowerShell regression wrapper must return a sanitized summary");
    }
    assert.equal(result.secret_exposed, false);
    assert.equal(result.restored, true);
    return result;
  } finally {
    server.close();
    const ownedPath = relative(resolve(tmpdir()), root);
    assert.ok(ownedPath.startsWith("scoplen-runner-test-") && !isAbsolute(ownedPath));
    await rm(root, { recursive: true, force: true });
  }
}

for (const [scenario, selected] of [
  ["Default", "team_ssh::live_team_ssh_and_sftp"],
  ["PersonalGeneratedKey", "personal_inventory_ssh::live_password_device_generated_key_sync_ssh_and_sftp"],
  ["PersonalPassword", "personal_inventory_ssh::live_password_device_password_sync_ssh_and_sftp"],
]) {
  test(`runner executes ${scenario} and removes its owned fixture`, async () => {
    const result = await execute(scenario);
    assert.equal(result.caught, false);
    assert.equal(result.called, true);
    assert.ok(result.test_arguments.includes(`personal_server::live_server::password_entry::${selected}`));
    assert.ok(result.test_arguments.includes("--exact") && result.test_arguments.includes("--test-threads=1"));
    assert.equal(result.password_enabled, scenario === "PersonalPassword");
    assert.equal(result.password_matches, scenario === "PersonalPassword");
    assert.equal(result.password_absent, scenario !== "PersonalPassword");
    assert.equal(result.removed, true);
    assert.equal(result.retained, false);
  });
}

for (const mode of ["failure", "empty"]) {
  test(`runner preserves private diagnostics after ${mode} without printing a password`, async () => {
    const result = await execute("PersonalPassword", mode);
    assert.equal(result.caught, true);
    assert.equal(result.called, true);
    assert.equal(result.password_matches, true);
    assert.equal(result.removed, true);
    assert.equal(result.retained, true);
    assert.equal(result.retained_log, true);
    assert.equal(result.retained_ssh_log, true);
  });
}

test("runner rejects unknown scenarios before invoking consumers", async () => {
  const result = await execute("Unknown");
  assert.equal(result.caught, true);
  assert.equal(result.called, false);
  assert.equal(result.removed, false);
});
