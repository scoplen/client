# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$scratchRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$scratchName = 'scoplen-local-forward-' + [guid]::NewGuid().ToString('N')
$scratch = Join-Path $scratchRoot $scratchName
$container = 'scoplen-local-forward-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$started = $false
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
    & cargo build --locked --manifest-path (Join-Path $repository 'Cargo.toml') -p scoplen-client-core --example ssh_local_forward_smoke *> $buildLog
    if ($LASTEXITCODE -ne 0) {
        throw 'Build standalone local TCP fixture failed'
    }
    $metadata = & cargo metadata --locked --no-deps --format-version 1 --manifest-path (Join-Path $repository 'Cargo.toml') | ConvertFrom-Json
    Check-LastExit 'read managed Cargo target directory'
    $suffix = if ($IsWindows) { '.exe' } else { '' }
    $smoke = Join-Path $metadata.target_directory "debug/examples/ssh_local_forward_smoke$suffix"

    & docker run --rm -d --name $container --label "scoplen.fixture.owner=$container" `
        -p '127.0.0.1::2222' -p '127.0.0.1::2223' -p '127.0.0.1::2224' `
        --add-host 'scoplen-forward-target.invalid:127.0.0.1' `
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
cat > /tmp/scoplen-forward-echo <<'ECHO'
#!/bin/sh
cat
printf SCOPLEN-FORWARD-EOF
ECHO
chmod 755 /tmp/scoplen-forward-echo
/bin/busybox nc -ll -p 2300 -e /tmp/scoplen-forward-echo >/tmp/scoplen-forward-echo.log 2>&1 &
echo "$!" > /tmp/scoplen-forward-echo.pid
cat > /etc/pam.d/sshd <<'PAM'
auth required pam_unix.so
account required pam_unix.so
session required pam_unix.so
PAM
for port in 2223 2224; do
  ssh-keygen -q -t ed25519 -N '' -f "/tmp/scoplen-forward-host-$port"
  cat > "/tmp/scoplen-forward-$port.conf" <<CONF
Port $port
ListenAddress 0.0.0.0
HostKey /tmp/scoplen-forward-host-$port
PidFile /tmp/scoplen-forward-$port.pid
AuthorizedKeysFile /config/.ssh/authorized_keys
StrictModes no
AllowTcpForwarding yes
MaxSessions 0
PerSourcePenalties no
LogLevel VERBOSE
CONF
done
cat >> /tmp/scoplen-forward-2223.conf <<'CONF'
UsePAM no
PasswordAuthentication yes
PubkeyAuthentication yes
KbdInteractiveAuthentication no
CONF
cat >> /tmp/scoplen-forward-2224.conf <<'CONF'
UsePAM yes
PasswordAuthentication no
PubkeyAuthentication no
KbdInteractiveAuthentication yes
AuthenticationMethods keyboard-interactive
CONF
for port in 2223 2224; do
  /usr/sbin/sshd.pam -t -f "/tmp/scoplen-forward-$port.conf"
  /usr/sbin/sshd.pam -T -f "/tmp/scoplen-forward-$port.conf" > "/tmp/scoplen-forward-$port.effective"
  grep -Fx 'maxsessions 0' "/tmp/scoplen-forward-$port.effective"
  grep -Fx 'allowtcpforwarding yes' "/tmp/scoplen-forward-$port.effective"
  /usr/sbin/sshd.pam -E "/tmp/scoplen-forward-$port.log" -f "/tmp/scoplen-forward-$port.conf"
done
grep -Fx 'usepam yes' /tmp/scoplen-forward-2224.effective
grep -Fx 'authenticationmethods keyboard-interactive' /tmp/scoplen-forward-2224.effective
kill -0 "$(cat /tmp/scoplen-forward-echo.pid)"
'@
    & docker exec $container sh -c ($setup.Replace("`r", ''))
    Check-LastExit 'configure no-session forwarding and PAM listeners with binary EOF echo'
    Wait-Ssh $ports[1]
    Wait-Ssh $ports[2]
    $smokeLog = Join-Path $scratch 'smoke.log'
    & $smoke $ports[0] $ports[1] $ports[2] $passwordFile $keyFile $passphraseFile *> $smokeLog
    Check-LastExit 'real standalone saved local TCP forwarding acceptance'
    Get-Content -LiteralPath $smokeLog
    $evidence = @'
set -eu
for port in 2223 2224; do
  if grep -q 'Starting session:' "/tmp/scoplen-forward-$port.log"; then
    printf 'A no-session forwarding connection opened a session channel\n' >&2
    exit 1
  fi
done
printf 'OpenSSH MaxSessions 0 accepted standalone forwarding without a session channel\n'
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
        & docker exec $container sh -c 'cat /tmp/scoplen-forward-2223.log /tmp/scoplen-forward-2224.log /tmp/scoplen-forward-echo.log /tmp/scoplen-forward-2223.effective /tmp/scoplen-forward-2224.effective 2>/dev/null' *> (Join-Path $scratch 'openssh.log')
    }
    throw
} finally {
    if ($started) {
        $owner = & docker inspect --format '{{index .Config.Labels "scoplen.fixture.owner"}}' $container 2>$null
        if ($LASTEXITCODE -eq 0 -and $owner -eq $container) { & docker rm -f $container 2>$null | Out-Null }
    }
    if ($success -and (Test-Path -LiteralPath $scratch)) {
        $resolvedScratch = (Resolve-Path -LiteralPath $scratch).Path
        $expectedScratch = [IO.Path]::GetFullPath((Join-Path $scratchRoot $scratchName))
        if ($resolvedScratch -ne $expectedScratch -or [IO.Path]::GetFileName($resolvedScratch) -ne $scratchName -or [IO.Path]::GetDirectoryName($resolvedScratch) -ne $scratchRoot) {
            throw "Refusing cleanup outside the owned fixture directory: $resolvedScratch"
        }
        Remove-Item -LiteralPath $resolvedScratch -Recurse -Force
    } elseif (Test-Path -LiteralPath $scratch) {
        Write-Warning "Forwarding fixture failed; private diagnostics retained at $scratch"
    }
}
