# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if (-not ($IsWindows -or $IsMacOS)) { throw 'This acceptance requires a supported desktop platform keystore' }
$scratchRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$scratch = Join-Path $scratchRoot ('scoplen-device-key-' + [guid]::NewGuid().ToString('N'))
$container = 'scoplen-device-key-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$started = $false
$accepted = $false
function Check-LastExit([string]$description) {
    if ($LASTEXITCODE -ne 0) { throw "$description failed (exit $LASTEXITCODE)" }
}
try {
    New-Item -ItemType Directory -Path $scratch | Out-Null
    & cargo build --locked -p scoplen-client-core --example ssh_device_key_smoke *> (Join-Path $scratch 'build.log')
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath (Join-Path $scratch 'build.log') -Tail 25
        throw 'build device-key fixture failed'
    }
    $metadata = & cargo metadata --locked --format-version 1 --no-deps | ConvertFrom-Json
    Check-LastExit 'read configured target directory'
    $suffix = if ($IsWindows) { '.exe' } else { '' }
    $smoke = Join-Path $metadata.target_directory "debug/examples/ssh_device_key_smoke$suffix"
    $bootstrap = Join-Path $scratch 'bootstrap'
    & ssh-keygen -q -t ed25519 -N '' -f $bootstrap
    Check-LastExit 'generate disposable bootstrap public identity'
    $publicKey = (Get-Content -LiteralPath ($bootstrap + '.pub') -Raw).Trim()
    & docker run --rm -d --name $container --label "scoplen.fixture.owner=$container" `
        -p '127.0.0.1::2222' -p '127.0.0.1::2223' -p '127.0.0.1::2224' `
        -e 'USER_NAME=smoke' -e "PUBLIC_KEY=$publicKey" -e 'PASSWORD_ACCESS=false' `
        'linuxserver/openssh-server@sha256:46f115de7c251558297e7e87566fc3fc08544b63e55502b5cf294454db5d29d1' | Out-Null
    Check-LastExit 'start isolated OpenSSH fixture'
    $started = $true
    $ports = @{}
    foreach ($port in @(2222, 2223, 2224)) {
        $binding = & docker port $container "$port/tcp"
        Check-LastExit 'read owned SSH binding'
        if ($binding -notmatch '^127\.0\.0\.1:(\d+)$') { throw 'SSH fixture was not bound to loopback' }
        $ports[$port] = [int]$Matches[1]
    }
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $probe = [Net.Sockets.TcpClient]::new()
        try {
            if ($probe.ConnectAsync('127.0.0.1', $ports[2222]).Wait([TimeSpan]::FromSeconds(1)) -and $probe.Connected) {
                $stream = $probe.GetStream(); $stream.ReadTimeout = 500
                $banner = [byte[]]::new(256)
                $count = $stream.Read($banner, 0, $banner.Length)
                if ([Text.Encoding]::ASCII.GetString($banner, 0, $count).StartsWith('SSH-')) { $ready = $true; break }
            }
        } catch {} finally { $probe.Dispose() }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw 'OpenSSH fixture did not become ready' }
    $store = Join-Path $scratch 'inventory.db'
    $keys = @(& $smoke create $store $ports[2223] $ports[2224] 2223)
    Check-LastExit 'create device Credentials and saved Direct/Jump Logins'
    if ($keys.Count -ne 2 -or @($keys | Where-Object { $_ -notmatch '^ecdsa-sha2-nistp256 [A-Za-z0-9+/=]+$' }).Count -ne 0) { throw 'Unexpected device public identities' }
    $setup = @'
set -eu
printf '%s\n' "$1" > /tmp/scoplen-device-target.pub
printf '%s\n' "$2" > /tmp/scoplen-device-jump.pub
chmod 644 /tmp/scoplen-device-target.pub /tmp/scoplen-device-jump.pub
ssh-keygen -q -t ed25519 -N '' -f /tmp/scoplen-device-host
ssh-keygen -q -t ed25519 -N '' -f /tmp/scoplen-device-jump-host
cat > /tmp/scoplen-device-target.conf <<'CONF'
Port 2223
ListenAddress 0.0.0.0
HostKey /tmp/scoplen-device-host
PidFile /tmp/scoplen-device-target.pid
AuthorizedKeysFile /tmp/scoplen-device-target.pub
StrictModes no
AllowTcpForwarding yes
PermitOpen 127.0.0.1:2223
PerSourcePenalties no
UsePAM no
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
Subsystem sftp internal-sftp
LogLevel VERBOSE
CONF
/usr/sbin/sshd.pam -t -f /tmp/scoplen-device-target.conf
/usr/sbin/sshd.pam -E /tmp/scoplen-device-target.log -f /tmp/scoplen-device-target.conf
sed -e 's/^Port 2223$/Port 2224/' -e 's@^AuthorizedKeysFile .*@AuthorizedKeysFile /tmp/scoplen-device-jump.pub@' -e 's@^HostKey .*@HostKey /tmp/scoplen-device-jump-host@' -e 's@^PidFile .*@PidFile /tmp/scoplen-device-jump.pid@' /tmp/scoplen-device-target.conf > /tmp/scoplen-device-jump.conf
/usr/sbin/sshd.pam -t -f /tmp/scoplen-device-jump.conf
/usr/sbin/sshd.pam -E /tmp/scoplen-device-jump.log -f /tmp/scoplen-device-jump.conf
'@
    & docker exec $container sh -c ($setup.Replace("`r", '')) sh $keys[0] $keys[1]
    Check-LastExit 'install exact device public keys on independent target and Jump servers'
    foreach ($mode in @('refuse', 'direct', 'jump')) {
        & $smoke $mode $store
        Check-LastExit "device key $mode"
    }
    & docker exec $container sh -c 'cp /tmp/scoplen-device-target.pub /tmp/scoplen-device-target.saved; cp /tmp/scoplen-device-jump.pub /tmp/scoplen-device-target.pub'
    Check-LastExit 'deny the target device identity'
    & $smoke rejected $store
    Check-LastExit 'reject unauthorized device identity without fallback'
    & docker exec $container sh -c 'mv /tmp/scoplen-device-target.saved /tmp/scoplen-device-target.pub'
    Check-LastExit 'restore target public identity'
    & $smoke missing $store
    Check-LastExit 'reject an unavailable platform slot after reopen'
    $targetCount = & docker exec $container sh -c "grep -c '^Accepted publickey for smoke ' /tmp/scoplen-device-target.log"
    Check-LastExit 'read target authentication count'
    $jumpCount = & docker exec $container sh -c "grep -c '^Accepted publickey for smoke ' /tmp/scoplen-device-jump.log"
    Check-LastExit 'read Jump authentication count'
    if ([int]$targetCount -ne 4 -or [int]$jumpCount -ne 2) { throw 'Unexpected device-key authentication count' }
    & $smoke cleanup $store
    Check-LastExit 'remove owned platform device key slots'
    Write-Output 'Device-key acceptance passed: target 4 and Jump 2 successful authentications; refusals, binary SFTP and reopened inventory passed.'
    $accepted = $true
} finally {
    if ($started) {
        if (-not $accepted) {
            & docker logs --tail 100 $container *> (Join-Path $scratch 'container.log')
            & docker exec $container sh -c 'cat /tmp/scoplen-device-target.log /tmp/scoplen-device-jump.log 2>/dev/null' *> (Join-Path $scratch 'openssh.log')
        }
        $owner = & docker inspect --format '{{index .Config.Labels "scoplen.fixture.owner"}}' $container 2>$null
        if ($LASTEXITCODE -eq 0 -and $owner -eq $container) { & docker rm -f $container 2>$null | Out-Null }
    }
    if ($accepted -and (Test-Path -LiteralPath $scratch)) {
        $resolved = [IO.Path]::GetFullPath($scratch)
        if ([IO.Path]::GetDirectoryName($resolved) -ne $scratchRoot -or [IO.Path]::GetFileName($resolved) -notlike 'scoplen-device-key-*') { throw 'Refusing cleanup outside owned fixture' }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
