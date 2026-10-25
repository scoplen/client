# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$scratchRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$scratchName = 'scoplen-dynamic-forward-' + [guid]::NewGuid().ToString('N')
$scratch = Join-Path $scratchRoot $scratchName
$container = 'scoplen-dynamic-forward-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$started = $false
$containerAttempted = $false
$success = $false

function Check-LastExit([string]$description) {
    if ($LASTEXITCODE -ne 0) { throw "$description failed (exit $LASTEXITCODE)" }
}

function Wait-Ssh([int]$port) {
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $probe = [Net.Sockets.TcpClient]::new()
        try {
            if ($probe.ConnectAsync('127.0.0.1', $port).Wait([TimeSpan]::FromSeconds(1)) -and $probe.Connected) {
                $stream = $probe.GetStream()
                $stream.ReadTimeout = 500
                $banner = [byte[]]::new(256)
                $count = $stream.Read($banner, 0, $banner.Length)
                if ([Text.Encoding]::ASCII.GetString($banner, 0, $count).StartsWith('SSH-')) { return }
            }
        } catch {} finally { $probe.Dispose() }
        Start-Sleep -Milliseconds 500
    }
    throw 'Disposable OpenSSH listener did not become ready'
}

try {
    New-Item -ItemType Directory -Path $scratch | Out-Null
    if ($IsWindows) {
        $user = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $directoryAcl = [Security.AccessControl.DirectorySecurity]::new()
        $directoryAcl.SetAccessRuleProtection($true, $false)
        $directoryAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $user,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        ))
        Set-Acl -LiteralPath $scratch -AclObject $directoryAcl
    } else {
        & chmod 700 $scratch
        Check-LastExit 'restrict fixture directory'
    }
    $password = 'disposable-fixture-' + [guid]::NewGuid().ToString('N')
    $passwordFile = Join-Path $scratch 'password'
    $passphraseFile = Join-Path $scratch 'passphrase'
    $keyFile = Join-Path $scratch 'encrypted-key'
    Set-Content -LiteralPath $passwordFile -Value $password -NoNewline -Encoding utf8
    Set-Content -LiteralPath $passphraseFile -Value 'disposable-key-passphrase' -NoNewline -Encoding utf8
    & ssh-keygen -q -t ed25519 -N 'disposable-key-passphrase' -f $keyFile
    Check-LastExit 'generate disposable encrypted forwarding key'
    if ($IsWindows) {
        foreach ($secretFile in @($passwordFile, $passphraseFile)) {
            Set-Acl -LiteralPath $secretFile -AclObject (Get-Acl -LiteralPath $keyFile)
        }
    }
    $publicKey = Get-Content -LiteralPath "$keyFile.pub" -Raw
    $buildLog = Join-Path $scratch 'build.log'
    & cargo build --locked --manifest-path (Join-Path $repository 'Cargo.toml') -p scoplen-client-core --example ssh_dynamic_forward_smoke *> $buildLog
    if ($LASTEXITCODE -ne 0) {
        throw 'Build standalone Dynamic SOCKS fixture failed'
    }
    $metadata = & cargo metadata --locked --no-deps --format-version 1 --manifest-path (Join-Path $repository 'Cargo.toml') | ConvertFrom-Json
    Check-LastExit 'read managed Cargo target directory'
    $suffix = if ($IsWindows) { '.exe' } else { '' }
    $smoke = Join-Path $metadata.target_directory "debug/examples/ssh_dynamic_forward_smoke$suffix"

    $containerAttempted = $true
    & docker run -d --stop-timeout 5 --name $container --label "scoplen.fixture.owner=$container" `
        -p '127.0.0.1::2222' -p '127.0.0.1::2223' -p '127.0.0.1::2224' `
        --add-host 'scoplen-dynamic-target.invalid:127.0.0.1' `
        -e 'USER_NAME=smoke' -e "USER_PASSWORD=$password" -e 'PASSWORD_ACCESS=true' `
        -e "PUBLIC_KEY=$publicKey" `
        'linuxserver/openssh-server@sha256:46f115de7c251558297e7e87566fc3fc08544b63e55502b5cf294454db5d29d1' | Out-Null
    Check-LastExit 'start isolated pinned OpenSSH fixture'
    $started = $true
    $ports = @()
    foreach ($internalPort in @(2222, 2223, 2224)) {
        $binding = & docker port $container "$internalPort/tcp"
        Check-LastExit 'read disposable OpenSSH loopback port'
        if ($binding -notmatch '^127\.0\.0\.1:(\d+)$') { throw 'OpenSSH fixture was not published on loopback' }
        $ports += [int]$Matches[1]
    }
    Wait-Ssh $ports[0]
    $setup = @'
set -eu
test -x /usr/sbin/sshd.pam
test -x /bin/busybox
cat > /tmp/scoplen-dynamic-echo <<'ECHO'
#!/bin/sh
cat
printf SCOPLEN-FORWARD-EOF
ECHO
chmod 755 /tmp/scoplen-dynamic-echo
/bin/busybox nc -ll -s 127.0.0.1 -p 2300 -e /tmp/scoplen-dynamic-echo >/tmp/scoplen-dynamic-echo.log 2>&1 &
echo "$!" > /tmp/scoplen-dynamic-echo.pid
cat > /etc/pam.d/sshd <<'PAM'
auth required pam_unix.so
account required pam_unix.so
session required pam_unix.so
PAM
for port in 2223 2224; do
  ssh-keygen -q -t ed25519 -N '' -f "/tmp/scoplen-dynamic-host-$port"
  cat > "/tmp/scoplen-dynamic-$port.conf" <<CONF
Port $port
ListenAddress 0.0.0.0
HostKey /tmp/scoplen-dynamic-host-$port
PidFile /tmp/scoplen-dynamic-$port.pid
AuthorizedKeysFile /config/.ssh/authorized_keys
StrictModes no
AllowTcpForwarding yes
PermitOpen scoplen-dynamic-target.invalid:2300 scoplen-dynamic-target.invalid:2301 127.0.0.1:2300 localhost:2223
MaxSessions 0
PerSourcePenalties no
LogLevel DEBUG1
CONF
done
cat >> /tmp/scoplen-dynamic-2223.conf <<'CONF'
UsePAM no
PasswordAuthentication yes
PubkeyAuthentication yes
KbdInteractiveAuthentication no
CONF
cat >> /tmp/scoplen-dynamic-2224.conf <<'CONF'
UsePAM yes
PasswordAuthentication no
PubkeyAuthentication no
KbdInteractiveAuthentication yes
AuthenticationMethods keyboard-interactive
CONF
for port in 2223 2224; do
  /usr/sbin/sshd.pam -t -f "/tmp/scoplen-dynamic-$port.conf"
  /usr/sbin/sshd.pam -T -f "/tmp/scoplen-dynamic-$port.conf" > "/tmp/scoplen-dynamic-$port.effective"
  grep -Fx 'maxsessions 0' "/tmp/scoplen-dynamic-$port.effective"
  grep -Fx 'allowtcpforwarding yes' "/tmp/scoplen-dynamic-$port.effective"
  /usr/sbin/sshd.pam -E "/tmp/scoplen-dynamic-$port.log" -f "/tmp/scoplen-dynamic-$port.conf"
done
grep -Fx 'usepam yes' /tmp/scoplen-dynamic-2224.effective
grep -Fx 'authenticationmethods keyboard-interactive' /tmp/scoplen-dynamic-2224.effective
kill -0 "$(cat /tmp/scoplen-dynamic-echo.pid)"
/bin/busybox netstat -ltn | grep -Eq '[[:space:]]127\.0\.0\.1:2300[[:space:]]'
'@
    & docker exec $container sh -c ($setup.Replace("`r", ''))
    Check-LastExit 'configure no-session forwarding and PAM listeners with binary EOF echo'
    Wait-Ssh $ports[1]
    Wait-Ssh $ports[2]
    $smokeLog = Join-Path $scratch 'smoke.log'
    & $smoke $ports[0] $ports[1] $ports[2] $passwordFile $keyFile $passphraseFile *> $smokeLog
    Check-LastExit 'real standalone saved Dynamic SOCKS forwarding acceptance'
    Get-Content -LiteralPath $smokeLog
    $evidence = @'
set -eu
for port in 2223 2224; do
  grep -Fq 'target scoplen-dynamic-target.invalid port 2300' "/tmp/scoplen-dynamic-$port.log"
  if grep -q 'Starting session:' "/tmp/scoplen-dynamic-$port.log"; then
    printf 'A no-session forwarding connection opened a session channel\n' >&2
    exit 1
  fi
done
printf 'OpenSSH MaxSessions 0 accepted standalone forwarding without a session channel\n'
printf 'OpenSSH received the literal SOCKS domain for container-only target resolution\n'
'@
    & docker exec $container sh -c ($evidence.Replace("`r", ''))
    Check-LastExit 'verify no forwarding SSH session channel'
    $success = $true
} catch {
    if (Test-Path -LiteralPath $scratch) {
        Set-Content -LiteralPath (Join-Path $scratch 'failure.txt') -Value $_.Exception.Message
    }
    if ($started) {
        & docker logs --tail 100 $container *> (Join-Path $scratch 'container.log')
        & docker exec $container sh -c 'cat /tmp/scoplen-dynamic-2223.log /tmp/scoplen-dynamic-2224.log /tmp/scoplen-dynamic-echo.log /tmp/scoplen-dynamic-2223.effective /tmp/scoplen-dynamic-2224.effective 2>/dev/null' *> (Join-Path $scratch 'openssh.log')
    }
    throw
} finally {
    if ($containerAttempted) {
        $owner = & docker inspect --format '{{index .Config.Labels "scoplen.fixture.owner"}}' $container 2>$null
        if ($LASTEXITCODE -eq 0 -and $owner -eq $container) {
            if ($success) {
                & docker rm -f $container 2>$null | Out-Null
                Check-LastExit 'remove successful owned Dynamic fixture'
            } else {
                & docker stop --time 5 $container 2>$null | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    Write-Warning "Stopped owned fixture $container; retained for failure diagnosis"
                } else {
                    Write-Warning "Could not confirm stop of owned fixture $container; inspect it before cleanup"
                }
            }
        } elseif ($success) {
            throw 'Could not verify ownership for successful Dynamic fixture cleanup'
        }
    }
    if ($success -and (Test-Path -LiteralPath $scratch)) {
        $resolvedScratch = (Resolve-Path -LiteralPath $scratch).Path
        $expectedScratch = [IO.Path]::GetFullPath((Join-Path $scratchRoot $scratchName))
        if ($resolvedScratch -ne $expectedScratch -or [IO.Path]::GetFileName($resolvedScratch) -ne $scratchName -or [IO.Path]::GetDirectoryName($resolvedScratch) -ne $scratchRoot) {
            throw "Refusing cleanup outside the owned fixture directory: $resolvedScratch"
        }
        Remove-Item -LiteralPath $resolvedScratch -Recurse -Force
    } elseif (Test-Path -LiteralPath $scratch) {
        Write-Warning "Dynamic SOCKS fixture failed; private diagnostics retained at $scratch"
    }
}
