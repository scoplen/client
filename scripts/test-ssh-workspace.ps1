# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$scratchRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/')
$scratch = Join-Path $scratchRoot ('scoplen-workspace-' + [guid]::NewGuid().ToString('N'))
$container = 'scoplen-workspace-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$started = $false
$accepted = $false
function Check-LastExit([string]$description) {
    if ($LASTEXITCODE -ne 0) { throw "$description failed (exit $LASTEXITCODE)" }
}
try {
    New-Item -ItemType Directory -Path $scratch | Out-Null
    $password = 'disposable-fixture-' + [guid]::NewGuid().ToString('N')
    $passwordFile = Join-Path $scratch 'password'
    Set-Content -LiteralPath $passwordFile -Value $password -NoNewline -Encoding utf8
    & cargo build --locked -p scoplen-client-core --example ssh_workspace_smoke *> (Join-Path $scratch 'build.log')
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath (Join-Path $scratch 'build.log') -Tail 35
        throw 'build workspace fixture failed'
    }
    $metadata = & cargo metadata --locked --format-version 1 --no-deps | ConvertFrom-Json
    Check-LastExit 'read configured target directory'
    $suffix = if ($IsWindows) { '.exe' } else { '' }
    $smoke = Join-Path $metadata.target_directory "debug/examples/ssh_workspace_smoke$suffix"
    & docker run --rm -d --name $container --label "scoplen.fixture.owner=$container" `
        -p '127.0.0.1::2222' -p '127.0.0.1::2223' -p '127.0.0.1::2302' `
        -e 'USER_NAME=smoke' -e "USER_PASSWORD=$password" -e 'PASSWORD_ACCESS=true' `
        'linuxserver/openssh-server@sha256:46f115de7c251558297e7e87566fc3fc08544b63e55502b5cf294454db5d29d1' | Out-Null
    Check-LastExit 'start isolated OpenSSH fixture'
    $started = $true
    $binding = & docker port $container '2222/tcp'
    Check-LastExit 'read OpenSSH port'
    if ($binding -notmatch '^127\.0\.0\.1:(\d+)$') { throw 'Fixture was not bound to loopback' }
    $port = [int]$Matches[1]
    $tunnelBinding = & docker port $container '2223/tcp'
    Check-LastExit 'read tunnel SSH port'
    if ($tunnelBinding -notmatch '^127\.0\.0\.1:(\d+)$') { throw 'Tunnel fixture was not bound to loopback' }
    $tunnelPort = [int]$Matches[1]
    $remoteBinding = & docker port $container '2302/tcp'
    Check-LastExit 'read remote forwarding port'
    if ($remoteBinding -notmatch '^127\.0\.0\.1:(\d+)$') { throw 'Remote fixture was not bound to loopback' }
    $remotePort = [int]$Matches[1]
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $probe = [Net.Sockets.TcpClient]::new()
        try {
            if ($probe.ConnectAsync('127.0.0.1', $port).Wait([TimeSpan]::FromSeconds(1)) -and $probe.Connected) {
                $stream = $probe.GetStream()
                $stream.ReadTimeout = 500
                $banner = [byte[]]::new(256)
                $count = $stream.Read($banner, 0, $banner.Length)
                if ([Text.Encoding]::ASCII.GetString($banner, 0, $count).StartsWith('SSH-')) {
                    $ready = $true
                    break
                }
            }
        } catch {} finally { $probe.Dispose() }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw 'OpenSSH fixture did not become ready' }
    $setup = @'
set -eu
/bin/busybox nc -ll -p 2300 -e /bin/cat >/tmp/scoplen-workspace-echo.log 2>&1 &
ssh-keygen -q -t ed25519 -N '' -f /tmp/scoplen-workspace-host
cat > /tmp/scoplen-workspace-2223.conf <<'CONF'
Port 2223
ListenAddress 0.0.0.0
HostKey /tmp/scoplen-workspace-host
PidFile /tmp/scoplen-workspace-2223.pid
StrictModes no
AllowTcpForwarding yes
GatewayPorts clientspecified
MaxSessions 0
PerSourcePenalties no
UsePAM no
PasswordAuthentication yes
PubkeyAuthentication no
KbdInteractiveAuthentication no
LogLevel VERBOSE
CONF
/usr/sbin/sshd.pam -t -f /tmp/scoplen-workspace-2223.conf
/usr/sbin/sshd.pam -T -f /tmp/scoplen-workspace-2223.conf > /tmp/scoplen-workspace-2223.effective
grep -Fx 'allowtcpforwarding yes' /tmp/scoplen-workspace-2223.effective
grep -Fx 'gatewayports clientspecified' /tmp/scoplen-workspace-2223.effective
grep -Fx 'maxsessions 0' /tmp/scoplen-workspace-2223.effective
/usr/sbin/sshd.pam -E /tmp/scoplen-workspace-2223.log -f /tmp/scoplen-workspace-2223.conf
'@
    & docker exec $container sh -c ($setup.Replace("`r", ''))
    Check-LastExit 'configure isolated forwarding-only SSH and binary echo'
    & $smoke '127.0.0.1' $port $passwordFile $tunnelPort $remotePort
    Check-LastExit 'real SSH saved mixed workspace acceptance'
    & docker exec $container sh -c 'if /bin/busybox netstat -ltn | /bin/busybox grep -q ":2302 "; then exit 1; fi'
    Check-LastExit 'verify owned remote listener released after Stop'
    $accepted = $true
} finally {
    if ($started) {
        if (-not $accepted) {
            & docker logs --tail 100 $container *> (Join-Path $scratch 'container.log')
            & docker exec $container sh -c 'cat /tmp/scoplen-workspace-2223.log /tmp/scoplen-workspace-echo.log 2>/dev/null' *> (Join-Path $scratch 'openssh.log')
        }
        $owner = & docker inspect --format '{{index .Config.Labels "scoplen.fixture.owner"}}' $container 2>$null
        if ($LASTEXITCODE -eq 0 -and $owner -eq $container) { & docker rm -f $container 2>$null | Out-Null }
    }
    if ($accepted -and (Test-Path -LiteralPath $scratch)) {
        $resolvedScratch = [System.IO.Path]::GetFullPath($scratch)
        if (-not $resolvedScratch.StartsWith($scratchRoot + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing cleanup outside temporary directory'
        }
        Remove-Item -LiteralPath $resolvedScratch -Recurse -Force
    }
}
