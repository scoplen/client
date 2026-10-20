# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$scratchRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/')
$scratch = Join-Path $scratchRoot ("scoplen-proxy-smoke-" + [guid]::NewGuid().ToString('N'))
$container = 'scoplen-proxy-smoke-' + [guid]::NewGuid().ToString('N').Substring(0, 12)

function Check-LastExit([string]$description) {
    if ($LASTEXITCODE -ne 0) { throw "$description failed (exit $LASTEXITCODE)" }
}

try {
    New-Item -ItemType Directory -Path $scratch | Out-Null
    $key = Join-Path $scratch 'id_ed25519'
    & ssh-keygen -q -t ed25519 -N '' -f $key
    Check-LastExit 'generate disposable key'
    $publicKey = (Get-Content -LiteralPath "$key.pub" -Raw).Trim()

    $buildLog = Join-Path $scratch 'build.log'
    & cargo build --quiet --locked -p scoplen-client-core --example ssh_proxy_route_smoke --example ssh_proxy_command_smoke 2> $buildLog
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath $buildLog | Select-Object -Last 40
        Check-LastExit 'build proxy route smoke example'
    }
    $suffix = if ($IsWindows) { '.exe' } else { '' }
    $targetRoot = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path (Get-Location) 'target' }
    $smoke = Join-Path $targetRoot "debug/examples/ssh_proxy_route_smoke$suffix"

    & docker run --rm -d --name $container -p '127.0.0.1::2222' -e 'USER_NAME=smoke' -e "PUBLIC_KEY=$publicKey" -e 'PASSWORD_ACCESS=false' 'linuxserver/openssh-server@sha256:46f115de7c251558297e7e87566fc3fc08544b63e55502b5cf294454db5d29d1' | Out-Null
    Check-LastExit 'start disposable OpenSSH'
    $binding = & docker port $container '2222/tcp'
    Check-LastExit 'read OpenSSH port'
    if ($binding -notmatch '^127\.0\.0\.1:(\d+)$') { throw "Unexpected OpenSSH port binding: $binding" }
    $port = [int]$Matches[1]

    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        & $smoke direct $port smoke $key 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) {
        & docker logs --tail 25 $container
        throw 'OpenSSH fixture did not become ready'
    }

    & $smoke all $port smoke $key
    Check-LastExit 'direct, SOCKS5, and HTTP CONNECT interoperability'
    $commandSmoke = Join-Path $targetRoot "debug/examples/ssh_proxy_command_smoke$suffix"
    & $commandSmoke $port smoke $key
    Check-LastExit 'saved ProxyCommand preparation, SSH, and child cleanup'
} finally {
    & docker rm -f $container 2>$null | Out-Null
    $resolved = [System.IO.Path]::GetFullPath($scratch)
    if ([System.IO.Path]::GetDirectoryName($resolved) -eq $scratchRoot -and [System.IO.Path]::GetFileName($resolved) -like 'scoplen-proxy-smoke-*') {
        Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction SilentlyContinue
    }
}
