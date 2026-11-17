# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$scratchRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/')
$scratch = Join-Path $scratchRoot ('scoplen-attached-' + [guid]::NewGuid().ToString('N'))
$container = 'scoplen-attached-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
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
    & cargo build --locked -p scoplen-client-core --example ssh_attached_forwards_smoke *> (Join-Path $scratch 'build.log')
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath (Join-Path $scratch 'build.log') -Tail 35
        throw 'build attached forwarding fixture failed'
    }
    $metadata = & cargo metadata --locked --format-version 1 --no-deps | ConvertFrom-Json
    Check-LastExit 'read configured target directory'
    $suffix = if ($IsWindows) { '.exe' } else { '' }
    $smoke = Join-Path $metadata.target_directory "debug/examples/ssh_attached_forwards_smoke$suffix"
    & docker run --rm -d --name $container --label "scoplen.fixture.owner=$container" `
        -p '127.0.0.1::2222' -p '127.0.0.1::2223' -p '127.0.0.1::2224' `
        -e 'USER_NAME=smoke' -e "USER_PASSWORD=$password" -e 'PASSWORD_ACCESS=true' `
        'linuxserver/openssh-server@sha256:46f115de7c251558297e7e87566fc3fc08544b63e55502b5cf294454db5d29d1' | Out-Null
    Check-LastExit 'start isolated OpenSSH fixture'
    $started = $true
    $binding = & docker port $container '2222/tcp'
    Check-LastExit 'read OpenSSH port'
    if ($binding -notmatch '^127\.0\.0\.1:(\d+)$') { throw 'Fixture was not bound to loopback' }
    $port = [int]$Matches[1]
    $jumpBinding = & docker port $container '2224/tcp'
    Check-LastExit 'read Jump SSH port'
    if ($jumpBinding -notmatch '^127\.0\.0\.1:(\d+)$') { throw 'Jump fixture was not bound to loopback' }
    $jumpPort = [int]$Matches[1]
    $targetBinding = & docker port $container '2223/tcp'
    Check-LastExit 'read target SSH port'
    if ($targetBinding -notmatch '^127\.0\.0\.1:(\d+)$') { throw 'Target fixture was not bound to loopback' }
    $targetPort = [int]$Matches[1]
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
/bin/busybox nc -ll -p 2300 -e /bin/cat >/tmp/scoplen-attached-echo.log 2>&1 &
ssh-keygen -q -t ed25519 -N '' -f /tmp/scoplen-attached-host
cat > /tmp/scoplen-attached.conf <<'CONF'
Port 2223
ListenAddress 0.0.0.0
HostKey /tmp/scoplen-attached-host
PidFile /tmp/scoplen-attached.pid
StrictModes no
AllowTcpForwarding yes
PermitOpen 127.0.0.1:2300 localhost:2300
PerSourcePenalties no
UsePAM no
PasswordAuthentication yes
PubkeyAuthentication no
KbdInteractiveAuthentication no
Subsystem sftp internal-sftp
LogLevel VERBOSE
CONF
/usr/sbin/sshd.pam -t -f /tmp/scoplen-attached.conf
/usr/sbin/sshd.pam -E /tmp/scoplen-attached-ssh.log -f /tmp/scoplen-attached.conf
sed -e 's/^Port 2223$/Port 2224/' \
    -e 's@^PidFile .*@PidFile /tmp/scoplen-attached-jump.pid@' \
    -e 's/^PermitOpen .*$/PermitOpen 127.0.0.1:2223/' \
    /tmp/scoplen-attached.conf > /tmp/scoplen-attached-jump.conf
/usr/sbin/sshd.pam -t -f /tmp/scoplen-attached-jump.conf
/usr/sbin/sshd.pam -E /tmp/scoplen-attached-jump.log -f /tmp/scoplen-attached-jump.conf
'@
    & docker exec $container sh -c ($setup.Replace("`r", ''))
    Check-LastExit 'configure isolated target shell, SFTP and forwarding'
    & $smoke 'direct' '127.0.0.1' $targetPort $passwordFile
    Check-LastExit 'real Direct SSH Login-attached forwarding and reconnect acceptance'
    & $smoke 'jump' '127.0.0.1' $jumpPort $passwordFile
    Check-LastExit 'real Jump SSH Login-attached forwarding and reconnect acceptance'
    $authentications = & docker exec $container sh -c "grep -c '^Accepted password for smoke ' /tmp/scoplen-attached-ssh.log"
    Check-LastExit 'read owned target authentication count'
    if ([int]$authentications -ne 6) {
        throw 'Expected two independent target authentications and four terminal target authentications including Direct and Jump reconnect'
    }
    $jumpAuthentications = & docker exec $container sh -c "grep -c '^Accepted password for smoke ' /tmp/scoplen-attached-jump.log"
    Check-LastExit 'read owned Jump authentication count'
    if ([int]$jumpAuthentications -ne 3) {
        throw 'Expected one independent and two terminal Jump authentications including reconnect'
    }
    Write-Output 'Target authentication count: exactly 6 (two independent, four terminal transports including Direct and Jump reconnect).'
    Write-Output 'Jump authentication count: exactly 3 (one independent, two terminal transports including reconnect).'
    $accepted = $true
} finally {
    if ($started) {
        if (-not $accepted) {
            & docker logs --tail 100 $container *> (Join-Path $scratch 'container.log')
            & docker exec $container sh -c 'cat /tmp/scoplen-attached-ssh.log /tmp/scoplen-attached-jump.log /tmp/scoplen-attached-echo.log 2>/dev/null' *> (Join-Path $scratch 'openssh.log')
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
