# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$scratchRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$scratch = Join-Path $scratchRoot ('scoplen-command-private-key-' + [guid]::NewGuid().ToString('N'))
$container = 'scoplen-command-private-key-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$started = $false
$accepted = $false
function Check-LastExit([string]$description) {
    if ($LASTEXITCODE -ne 0) { throw "$description failed (exit $LASTEXITCODE)" }
}
try {
    New-Item -ItemType Directory -Path $scratch | Out-Null
    $keys = @(
        @{ Name = 'ed25519'; Type = 'ed25519'; Bits = $null },
        @{ Name = 'p256'; Type = 'ecdsa'; Bits = '256' },
        @{ Name = 'p384'; Type = 'ecdsa'; Bits = '384' },
        @{ Name = 'p521'; Type = 'ecdsa'; Bits = '521' },
        @{ Name = 'rsa'; Type = 'rsa'; Bits = '3072' },
        @{ Name = 'wrong-ed25519'; Type = 'ed25519'; Bits = $null }
    )
    foreach ($entry in $keys) {
        $keyArgs = @('-q', '-t', $entry.Type, '-N', '', '-f', (Join-Path $scratch $entry.Name))
        if ($entry.Bits) { $keyArgs += @('-b', $entry.Bits) }
        & ssh-keygen @keyArgs
        Check-LastExit 'generate disposable provider key'
    }
    $encrypted = Join-Path $scratch 'encrypted-ed25519'
    Copy-Item -LiteralPath (Join-Path $scratch 'ed25519') -Destination $encrypted
    if ($IsWindows) { Set-Acl -LiteralPath $encrypted -AclObject (Get-Acl -LiteralPath (Join-Path $scratch 'ed25519')) } else { & chmod 600 $encrypted; Check-LastExit 'restrict copied provider key' }
    & ssh-keygen -q -p -P '' -N 'disposable-test-passphrase' -a 1 -f $encrypted | Out-Null
    Check-LastExit 'encrypt disposable provider key'
    $publicKeys = ($keys | Where-Object Name -NE 'wrong-ed25519' | ForEach-Object { (Get-Content -LiteralPath (Join-Path $scratch ($_.Name + '.pub')) -Raw).Trim() }) -join "`n"
    $jumpKey = (Get-Content -LiteralPath (Join-Path $scratch 'p256.pub') -Raw).Trim()
    & cargo build --locked -p scoplen-client-core --example ssh_command_private_key_smoke *> (Join-Path $scratch 'build.log')
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath (Join-Path $scratch 'build.log') -Tail 25
        throw 'build command-private-key fixture failed'
    }
    $metadata = & cargo metadata --locked --format-version 1 --no-deps | ConvertFrom-Json
    Check-LastExit 'read configured target directory'
    $suffix = if ($IsWindows) { '.exe' } else { '' }
    $smoke = Join-Path $metadata.target_directory "debug/examples/ssh_command_private_key_smoke$suffix"
    & docker run --rm -d --name $container --label "scoplen.fixture.owner=$container" `
        -p '127.0.0.1::2222' -p '127.0.0.1::2223' -p '127.0.0.1::2224' `
        -e 'USER_NAME=smoke' -e "PUBLIC_KEY=$publicKeys" -e 'PASSWORD_ACCESS=false' `
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
    $setup = @'
set -eu
printf '%s\n' "$1" > /tmp/scoplen-command-jump.pub
chmod 644 /tmp/scoplen-command-jump.pub
ssh-keygen -q -t ed25519 -N '' -f /tmp/scoplen-command-key-host
cat > /tmp/scoplen-command-key-target.conf <<'CONF'
Port 2223
ListenAddress 0.0.0.0
HostKey /tmp/scoplen-command-key-host
PidFile /tmp/scoplen-command-key-target.pid
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
/usr/sbin/sshd.pam -t -f /tmp/scoplen-command-key-target.conf
/usr/sbin/sshd.pam -E /tmp/scoplen-command-key-target.log -f /tmp/scoplen-command-key-target.conf
sed -e 's/^Port 2223$/Port 2224/' -e '$a AuthorizedKeysFile /tmp/scoplen-command-jump.pub' -e 's@^PidFile .*@PidFile /tmp/scoplen-command-key-jump.pid@' /tmp/scoplen-command-key-target.conf > /tmp/scoplen-command-key-jump.conf
/usr/sbin/sshd.pam -t -f /tmp/scoplen-command-key-jump.conf
/usr/sbin/sshd.pam -E /tmp/scoplen-command-key-jump.log -f /tmp/scoplen-command-key-jump.conf
'@
    & docker exec $container sh -c ($setup.Replace("`r", '')) sh $jumpKey
    Check-LastExit 'configure independent private-key SSH servers'
    & $smoke $ports[2223] $ports[2224] 2223 $scratch
    Check-LastExit 'command private-key Direct, Jump, failures, cleanup and reconnect'
    $targetCount = & docker exec $container sh -c "grep -c '^Accepted publickey for smoke ' /tmp/scoplen-command-key-target.log"
    Check-LastExit 'read target authentication count'
    $jumpCount = & docker exec $container sh -c "grep -c '^Accepted publickey for smoke ' /tmp/scoplen-command-key-jump.log"
    Check-LastExit 'read Jump authentication count'
    if ([int]$targetCount -ne 11 -or [int]$jumpCount -ne 4) { throw 'Unexpected public-key authentication count' }
    Write-Output 'Exact successful authentication counts: target 11, Jump 4. All failure controls kept their original result.'
    $accepted = $true
} finally {
    if ($started) {
        if (-not $accepted) {
            & docker logs --tail 100 $container *> (Join-Path $scratch 'container.log')
            & docker exec $container sh -c 'cat /tmp/scoplen-command-key-target.log /tmp/scoplen-command-key-jump.log 2>/dev/null' *> (Join-Path $scratch 'openssh.log')
        }
        $owner = & docker inspect --format '{{index .Config.Labels "scoplen.fixture.owner"}}' $container 2>$null
        if ($LASTEXITCODE -eq 0 -and $owner -eq $container) { & docker rm -f $container 2>$null | Out-Null }
    }
    if ($accepted -and (Test-Path -LiteralPath $scratch)) {
        $resolved = [IO.Path]::GetFullPath($scratch)
        if ([IO.Path]::GetDirectoryName($resolved) -ne $scratchRoot -or [IO.Path]::GetFileName($resolved) -notlike 'scoplen-command-private-key-*') { throw 'Refusing cleanup outside owned fixture' }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
