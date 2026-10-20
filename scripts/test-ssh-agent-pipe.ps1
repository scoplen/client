# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'The isolated named-pipe fixture requires Windows' }
$scratchRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/')
$scratch = Join-Path $scratchRoot ("scoplen-agent-pipe-" + [guid]::NewGuid().ToString('N'))
$container = 'scoplen-agent-pipe-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$previousSocket = $env:SSH_AUTH_SOCK
function Check-LastExit([string]$description) {
    if ($LASTEXITCODE -ne 0) { throw "$description failed (exit $LASTEXITCODE)" }
}
try {
    New-Item -ItemType Directory -Path $scratch | Out-Null
    $key = Join-Path $scratch 'user'
    & ssh-keygen -q -t ed25519 -N '' -f $key
    Check-LastExit 'generate disposable key'
    $publicKey = (Get-Content -LiteralPath "$key.pub" -Raw).Trim()
    $buildLog = Join-Path $scratch 'build.log'
    & cargo build --quiet --locked -p scoplen-client-core --example ssh_agent_smoke 2> $buildLog
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath $buildLog | Select-Object -Last 20
        Check-LastExit 'build SSH-agent fixture'
    }
    $targetRoot = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path (Get-Location) 'target' }
    $smoke = Join-Path $targetRoot 'debug/examples/ssh_agent_smoke.exe'
    & docker run --rm -d --name $container -p '127.0.0.1::2222' -e 'USER_NAME=smoke' -e "PUBLIC_KEY=$publicKey" -e 'PASSWORD_ACCESS=false' 'linuxserver/openssh-server@sha256:46f115de7c251558297e7e87566fc3fc08544b63e55502b5cf294454db5d29d1' | Out-Null
    Check-LastExit 'start disposable OpenSSH'
    $binding = & docker port $container '2222/tcp'
    Check-LastExit 'read OpenSSH port'
    if ($binding -notmatch '^127\.0\.0\.1:(\d+)$') { throw "Unexpected OpenSSH binding: $binding" }
    $port = [int]$Matches[1]
    $env:SSH_AUTH_SOCK = '\\.\pipe\scoplen-isolated-' + [guid]::NewGuid().ToString('N')
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        & $smoke untrusted 127.0.0.1 $port smoke "$key.pub" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw 'Disposable OpenSSH did not become ready' }
    # OpenSSH 10 penalizes repeated unauthenticated host-key probes by default.
    # These disposable cases deliberately make many probes from one loopback IP.
    & docker exec $container sh -c 'printf "\nPerSourcePenalties no\n" >> /config/sshd/sshd_config'
    Check-LastExit 'configure disposable probe admission'
    & docker exec $container /usr/sbin/sshd.pam -t -f /config/sshd/sshd_config
    Check-LastExit 'validate disposable sshd configuration'
    & docker exec $container pkill -HUP sshd
    Check-LastExit 'reload disposable sshd'
    foreach ($mode in @('untrusted', 'unavailable', 'refused', 'disconnected', 'timeout', 'cancel')) {
        $env:SSH_AUTH_SOCK = '\\.\pipe\scoplen-isolated-' + [guid]::NewGuid().ToString('N')
        & $smoke $mode 127.0.0.1 $port smoke "$key.pub"
        Check-LastExit "isolated pipe $mode"
    }
} catch {
    & docker logs --tail 25 $container
    throw
} finally {
    $env:SSH_AUTH_SOCK = $previousSocket
    & docker rm -f $container 2>$null | Out-Null
    $resolved = [System.IO.Path]::GetFullPath($scratch)
    if ([System.IO.Path]::GetDirectoryName($resolved) -eq $scratchRoot -and [System.IO.Path]::GetFileName($resolved) -like 'scoplen-agent-pipe-*') {
        Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction SilentlyContinue
    }
}
