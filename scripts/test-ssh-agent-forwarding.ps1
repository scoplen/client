# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$scratchRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$scratch = Join-Path $scratchRoot ('scoplen-agent-forwarding-' + [guid]::NewGuid().ToString('N'))
$container = 'scoplen-agent-forwarding-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$previousSocket = $env:SSH_AUTH_SOCK
$started = $false
$accepted = $false
function Check-LastExit([string]$description) {
    if ($LASTEXITCODE -ne 0) { throw "$description failed (exit $LASTEXITCODE)" }
}
try {
    New-Item -ItemType Directory -Path $scratch | Out-Null
    $selected = Join-Path $scratch 'selected'
    $other = Join-Path $scratch 'other'
    & ssh-keygen -q -t ed25519 -N '' -f $selected
    Check-LastExit 'generate selected fixture identity'
    & ssh-keygen -q -t ed25519 -N '' -f $other
    Check-LastExit 'generate other loaded fixture identity'
    & cargo build --locked -p scoplen-client-core --example ssh_agent_forwarding_smoke *> (Join-Path $scratch 'build.log')
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath (Join-Path $scratch 'build.log') -Tail 35
        throw 'build agent forwarding fixture failed'
    }
    $metadata = & cargo metadata --locked --format-version 1 --no-deps | ConvertFrom-Json
    Check-LastExit 'read configured target directory'
    $suffix = if ($IsWindows) { '.exe' } else { '' }
    $smoke = Join-Path $metadata.target_directory "debug/examples/ssh_agent_forwarding_smoke$suffix"
    & docker run --rm -d --name $container --label "scoplen.fixture.owner=$container" `
        -p '127.0.0.1::2224' -p '127.0.0.1::2302' -e 'USER_NAME=smoke' -e 'PASSWORD_ACCESS=false' `
        -e ('PUBLIC_KEY=' + (Get-Content -LiteralPath "$selected.pub" -Raw).Trim()) `
        'linuxserver/openssh-server@sha256:46f115de7c251558297e7e87566fc3fc08544b63e55502b5cf294454db5d29d1' | Out-Null
    Check-LastExit 'start owned two-hop OpenSSH fixture'
    $started = $true
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        & docker exec $container id smoke 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw 'Fixture user was not prepared' }
    & docker cp "$selected.pub" "${container}:/tmp/scoplen-agent-selected.pub"
    Check-LastExit 'copy selected public fixture identity'
    & docker cp "$other.pub" "${container}:/tmp/scoplen-agent-other.pub"
    Check-LastExit 'copy other public fixture identity'
    $setup = @'
set -eu
command -v python3 >/dev/null || apk add --no-cache python3 > /tmp/scoplen-agent-python.log 2>&1
ssh-keygen -q -t ed25519 -N '' -f /tmp/scoplen-agent-host
cat /tmp/scoplen-agent-selected.pub /tmp/scoplen-agent-other.pub > /tmp/scoplen-agent-first-keys
cat > /tmp/scoplen-agent-first.conf <<'CONF'
Port 2224
ListenAddress 0.0.0.0
HostKey /tmp/scoplen-agent-host
PidFile /tmp/scoplen-agent-first.pid
AuthorizedKeysFile /tmp/scoplen-agent-first-keys
StrictModes no
AllowAgentForwarding yes
AllowTcpForwarding yes
GatewayPorts clientspecified
PermitListen 0.0.0.0:2302
PermitOpen localhost:2300 127.0.0.1:2300
PerSourcePenalties no
UsePAM no
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
Subsystem sftp internal-sftp
LogLevel VERBOSE
CONF
sed -e 's/^Port 2224$/Port 2223/' \
    -e 's@^PidFile .*@PidFile /tmp/scoplen-agent-second.pid@' \
    -e 's@^AuthorizedKeysFile .*@AuthorizedKeysFile /tmp/scoplen-agent-selected.pub@' \
    /tmp/scoplen-agent-first.conf > /tmp/scoplen-agent-second.conf
/usr/sbin/sshd.pam -t -f /tmp/scoplen-agent-first.conf
/usr/sbin/sshd.pam -t -f /tmp/scoplen-agent-second.conf
/usr/sbin/sshd.pam -E /tmp/scoplen-agent-first.log -f /tmp/scoplen-agent-first.conf
/usr/sbin/sshd.pam -E /tmp/scoplen-agent-second.log -f /tmp/scoplen-agent-second.conf
printf '[127.0.0.1]:2223 ' > /tmp/scoplen-agent-known-hosts
cat /tmp/scoplen-agent-host.pub >> /tmp/scoplen-agent-known-hosts
/bin/busybox nc -ll -p 2300 -e /bin/cat > /tmp/scoplen-agent-echo.log 2>&1 &
'@
    & docker exec $container sh -c ($setup.Replace("`r", ''))
    Check-LastExit 'configure owned terminal, second-hop, SFTP and echo services'
    $binding = & docker port $container '2224/tcp'
    Check-LastExit 'read owned first-hop endpoint'
    if ($binding -notmatch '^127\.0\.0\.1:(\d+)$') { throw 'Fixture is not bound to loopback' }
    $port = [int]$Matches[1]
    $remoteBinding = & docker port $container '2302/tcp'
    Check-LastExit 'read owned Remote forwarding endpoint'
    if ($remoteBinding -notmatch '^127\.0\.0\.1:(\d+)$') { throw 'Remote fixture is not bound to loopback' }
    $remotePort = [int]$Matches[1]
    $env:SSH_AUTH_SOCK = if ($IsWindows) {
        '\\.\pipe\scoplen-agent-forwarding-' + [guid]::NewGuid().ToString('N')
    } else {
        Join-Path $scratch 'agent.sock'
    }
    & $smoke '127.0.0.1' $port $selected $other $remotePort
    Check-LastExit 'public desktop-core agent forwarding and real second-hop acceptance'
    $accepted = $true
} finally {
    $env:SSH_AUTH_SOCK = $previousSocket
    if ($started) {
        if (-not $accepted) {
            & docker logs --tail 100 $container *> (Join-Path $scratch 'container.log')
            & docker exec $container sh -c 'cat /tmp/scoplen-agent-first.log /tmp/scoplen-agent-second.log /tmp/scoplen-agent-python.log 2>/dev/null' *> (Join-Path $scratch 'openssh.log')
        }
        $owner = & docker inspect --format '{{index .Config.Labels "scoplen.fixture.owner"}}' $container 2>$null
        if ($LASTEXITCODE -eq 0 -and $owner -eq $container) { & docker rm -f $container 2>$null | Out-Null }
    }
    if ($accepted -and (Test-Path -LiteralPath $scratch)) {
        $resolved = [IO.Path]::GetFullPath($scratch)
        if ([IO.Path]::GetDirectoryName($resolved) -ne $scratchRoot -or [IO.Path]::GetFileName($resolved) -notlike 'scoplen-agent-forwarding-*') {
            throw 'Refusing cleanup outside the owned fixture directory'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
