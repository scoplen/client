# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$scratchRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/')
$scratch = Join-Path $scratchRoot ('scoplen-client-pam-' + [guid]::NewGuid().ToString('N'))
$container = 'scoplen-client-pam-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$savedHostKey = $env:SCOPLEN_INTERACTIVE_HOST_KEY
$savedAgentSocket = $env:SSH_AUTH_SOCK
$started = $false
function Check-LastExit([string]$description) {
    if ($LASTEXITCODE -ne 0) { throw "$description failed (exit $LASTEXITCODE)" }
}
try {
    New-Item -ItemType Directory -Path $scratch | Out-Null
    $buildLog = Join-Path $scratch 'build.log'
    & cargo build --quiet --locked --manifest-path (Join-Path $repository 'Cargo.toml') -p scoplen-client-core --example ssh_keyboard_interactive_smoke *> $buildLog
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath $buildLog -Tail 35
        throw 'Build keyboard-interactive client fixture failed'
    }
    $metadata = (& cargo metadata --no-deps --format-version 1 --manifest-path (Join-Path $repository 'Cargo.toml')) | ConvertFrom-Json
    Check-LastExit 'locate configured client target'
    $suffix = if ($IsWindows) { '.exe' } else { '' }
    $smoke = Join-Path $metadata.target_directory "debug/examples/ssh_keyboard_interactive_smoke$suffix"
    $setup = @'
set -eu
apk add --no-cache openssh-server-pam=9.9_p2-r0 linux-pam=1.6.1-r1 >/dev/null
apk info -v | grep -Fx 'openssh-server-pam-9.9_p2-r0'
apk info -v | grep -Fx 'linux-pam-1.6.1-r1'
adduser -D scoplen
printf 'scoplen:fixture-interactive-password\n' | chpasswd
ssh-keygen -q -t ed25519 -N '' -f /tmp/host_key
ssh-keygen -q -t ed25519 -N '' -f /tmp/client_key
ssh-keygen -q -t ed25519 -N '' -f /tmp/wrong_key
mkdir -p /run/sshd /home/scoplen/.ssh
cp /tmp/client_key.pub /home/scoplen/.ssh/authorized_keys
chown -R scoplen:scoplen /home/scoplen/.ssh
chmod 700 /home/scoplen/.ssh
chmod 600 /home/scoplen/.ssh/authorized_keys
cat > /etc/pam.d/sshd <<'PAM'
auth required pam_unix.so
account required pam_unix.so
session required pam_unix.so
PAM
cat > /tmp/common.conf <<'SSHD'
ListenAddress 0.0.0.0
HostKey /tmp/host_key
UsePAM yes
KbdInteractiveAuthentication yes
PermitEmptyPasswords no
PerSourcePenalties no
AllowTcpForwarding yes
SSHD
cp /tmp/common.conf /tmp/interactive.conf
cat >> /tmp/interactive.conf <<'SSHD'
Port 2222
PasswordAuthentication no
PubkeyAuthentication no
AuthenticationMethods keyboard-interactive
SSHD
cp /tmp/common.conf /tmp/key.conf
cat >> /tmp/key.conf <<'SSHD'
Port 2223
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
SSHD
cp /tmp/common.conf /tmp/password.conf
cat >> /tmp/password.conf <<'SSHD'
Port 2224
PasswordAuthentication yes
PubkeyAuthentication no
AuthenticationMethods password,keyboard-interactive
SSHD
for mode in interactive key password; do
  /usr/sbin/sshd.pam -t -f /tmp/$mode.conf
  /usr/sbin/sshd.pam -T -f /tmp/$mode.conf > /tmp/$mode.effective
  grep -Fx 'usepam yes' /tmp/$mode.effective
  grep -Fx 'kbdinteractiveauthentication yes' /tmp/$mode.effective
done
grep -Fx 'passwordauthentication no' /tmp/interactive.effective
grep -Fx 'pubkeyauthentication no' /tmp/interactive.effective
grep -Fx 'authenticationmethods keyboard-interactive' /tmp/interactive.effective
grep -Fx 'passwordauthentication no' /tmp/key.effective
grep -Fx 'pubkeyauthentication yes' /tmp/key.effective
grep -Fx 'authenticationmethods publickey,keyboard-interactive' /tmp/key.effective
grep -Fx 'passwordauthentication yes' /tmp/password.effective
grep -Fx 'pubkeyauthentication no' /tmp/password.effective
grep -Fx 'authenticationmethods password,keyboard-interactive' /tmp/password.effective
/usr/sbin/sshd.pam -D -e -f /tmp/interactive.conf &
/usr/sbin/sshd.pam -D -e -f /tmp/key.conf &
exec /usr/sbin/sshd.pam -D -e -f /tmp/password.conf
'@
    & docker run -d --name $container --label "scoplen.fixture.owner=$container" `
        -p '127.0.0.1::2222' -p '127.0.0.1::2223' -p '127.0.0.1::2224' `
        alpine:3.21 sh -c ($setup.Replace("`r", '')) | Out-Null
    Check-LastExit 'start disposable pinned OpenSSH/PAM listeners'
    $started = $true
    $ports = @()
    foreach ($internalPort in @(2222, 2223, 2224)) {
        $binding = & docker port $container "$internalPort/tcp"
        Check-LastExit 'read OpenSSH/PAM loopback port'
        if ($binding -notmatch '^127\.0\.0\.1:(\d+)$') { throw 'OpenSSH/PAM port was not bound to loopback' }
        $ports += [int]$Matches[1]
    }
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $state = & docker inspect --format '{{.State.Status}}' $container
        if ($state -in @('exited', 'dead')) { throw 'OpenSSH/PAM exited before readiness' }
        $ready = $true
        foreach ($port in $ports) {
            $socket = [System.Net.Sockets.TcpClient]::new()
            try {
                $socket.Connect('127.0.0.1', $port)
                $socket.GetStream().ReadTimeout = 1000
                $reader = [System.IO.StreamReader]::new($socket.GetStream())
                if ($reader.ReadLine() -ne 'SSH-2.0-OpenSSH_9.9') { $ready = $false }
            } catch { $ready = $false } finally { $socket.Dispose() }
        }
        if ($ready) { break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw 'Pinned OpenSSH/PAM listeners did not become ready within 60 seconds' }
    $env:SCOPLEN_INTERACTIVE_HOST_KEY = & docker exec $container cat /tmp/host_key.pub
    Check-LastExit 'read public fixture host key'
    $passwordFile = Join-Path $scratch 'password'
    Set-Content -LiteralPath $passwordFile -Value 'fixture-interactive-password' -NoNewline -Encoding utf8
    $keyFile = Join-Path $scratch 'client-key'
    $wrongKeyFile = Join-Path $scratch 'wrong-key'
    & docker cp "${container}:/tmp/client_key" $keyFile
    Check-LastExit 'copy disposable client fixture key'
    & docker cp "${container}:/tmp/wrong_key" $wrongKeyFile
    Check-LastExit 'copy disposable refusal fixture key'
    $env:SSH_AUTH_SOCK = if ($IsWindows) { "\\.\pipe\$container-agent" } else { Join-Path $scratch 'agent.sock' }
    & $smoke $ports[0] $ports[1] $ports[2] $passwordFile $keyFile $wrongKeyFile
    Check-LastExit 'client saved keyboard-interactive OpenSSH/PAM acceptance'
} catch {
    if ($started) { & docker logs --tail 35 $container 2>&1 | Write-Warning }
    throw
} finally {
    $env:SCOPLEN_INTERACTIVE_HOST_KEY = $savedHostKey
    $env:SSH_AUTH_SOCK = $savedAgentSocket
    if ($started) {
        $owner = & docker inspect --format '{{index .Config.Labels "scoplen.fixture.owner"}}' $container 2>$null
        if ($LASTEXITCODE -eq 0 -and $owner -eq $container) { & docker rm -f $container 2>$null | Out-Null }
    }
    if (Test-Path -LiteralPath $scratch) {
        $resolvedScratch = [System.IO.Path]::GetFullPath($scratch)
        if (-not $resolvedScratch.StartsWith($scratchRoot + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing cleanup outside temporary directory: $resolvedScratch"
        }
        Remove-Item -LiteralPath $resolvedScratch -Recurse -Force
    }
}
