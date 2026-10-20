# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if (-not $IsWindows -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'The native agent fixture runs only on an isolated Windows GitHub Actions runner'
}
if ((Get-Service ssh-agent).Status -ne 'Running') { throw 'The isolated runner ssh-agent must be running' }
$scratchRoot = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')
$scratch = Join-Path $scratchRoot ('scoplen-client-native-agent-' + [guid]::NewGuid().ToString('N'))
$key = Join-Path $scratch 'user'
$other = Join-Path $scratch 'other'
$attempted = @()
$previousSocket = $env:SSH_AUTH_SOCK
$previousLoopback = $env:SCOPLEN_AGENT_LOOPBACK
function Check-LastExit([string]$description) {
    if ($LASTEXITCODE -ne 0) { throw "$description failed (exit $LASTEXITCODE)" }
}
function Run-Case([string]$mode) {
    $start = [Diagnostics.ProcessStartInfo]::new($smoke)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in @($mode, '127.0.0.1', '0', 'smoke', "$key.pub")) {
        $start.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::Start($start)
    try {
        $output = $process.StandardOutput.ReadToEndAsync()
        $errors = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(45000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw "${mode}: client fixture exceeded 45 seconds"
        }
        $text = $output.GetAwaiter().GetResult().Trim()
        $errorText = $errors.GetAwaiter().GetResult().Trim()
        if ($process.ExitCode -ne 0 -or -not $text) {
            throw "${mode}: exit $($process.ExitCode), stdout '$text', stderr '$errorText'"
        }
        Write-Output $text
    } finally {
        $process.Dispose()
    }
}
try {
    New-Item -ItemType Directory -Path $scratch | Out-Null
    foreach ($path in @($other, $key)) {
        & ssh-keygen -q -t ed25519 -N '' -f $path
        Check-LastExit 'generate disposable agent key'
    }
    & cargo build --locked -p scoplen-client-core --example ssh_agent_smoke
    Check-LastExit 'build saved-agent fixture'
    $targetRoot = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path (Get-Location) 'target' }
    $smoke = Join-Path $targetRoot 'debug/examples/ssh_agent_smoke.exe'
    $env:SCOPLEN_AGENT_LOOPBACK = '1'
    $env:SSH_AUTH_SOCK = '\\.\pipe\openssh-ssh-agent'
    foreach ($path in @($other, $key)) {
        $attempted += "$path.pub"
        & ssh-add $path 2>&1 | Out-Null
        Check-LastExit 'load exact disposable key'
    }
    Run-Case success
    Run-Case untrusted
    Run-Case success
    & ssh-add -d "$key.pub" 2>&1 | Out-Null
    Check-LastExit 'remove exact test key'
    Run-Case missing
    & ssh-add $key 2>&1 | Out-Null
    Check-LastExit 'reload exact test key'
    Run-Case success
    foreach ($mode in @('unavailable', 'refused', 'disconnected', 'timeout', 'cancel')) {
        $env:SSH_AUTH_SOCK = '\\.\pipe\scoplen-isolated-' + [guid]::NewGuid().ToString('N')
        Run-Case $mode
        $env:SSH_AUTH_SOCK = '\\.\pipe\openssh-ssh-agent'
        Run-Case success
    }
} finally {
    $env:SSH_AUTH_SOCK = '\\.\pipe\openssh-ssh-agent'
    foreach ($path in $attempted) {
        & ssh-add -d $path 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Warning 'Test-key removal failed; the isolated runner will be discarded' }
    }
    $env:SSH_AUTH_SOCK = $previousSocket
    $env:SCOPLEN_AGENT_LOOPBACK = $previousLoopback
    $resolved = [IO.Path]::GetFullPath($scratch)
    if ([IO.Path]::GetDirectoryName($resolved) -eq $scratchRoot -and
        [IO.Path]::GetFileName($resolved).StartsWith('scoplen-client-native-agent-', [StringComparison]::Ordinal)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction SilentlyContinue
    }
}
