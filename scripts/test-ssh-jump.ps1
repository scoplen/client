# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$scratchRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/')
$scratch = Join-Path $scratchRoot ('scoplen-jump-' + [guid]::NewGuid().ToString('N'))
$container = 'scoplen-jump-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$previousSocket = $env:SSH_AUTH_SOCK
$stall = $null
function Check-LastExit([string]$description) {
    if ($LASTEXITCODE -ne 0) { throw "$description failed (exit $LASTEXITCODE)" }
}
try {
    New-Item -ItemType Directory -Path $scratch | Out-Null
    $key = Join-Path $scratch 'user'
    $agentKey = Join-Path $scratch 'agent'
    & ssh-keygen -q -t ed25519 -N 'disposable-key-passphrase' -f $key
    Check-LastExit 'generate encrypted disposable key'
    & ssh-keygen -q -t ed25519 -N '' -f $agentKey
    Check-LastExit 'generate disposable agent key'
    $password = 'disposable-fixture-' + [guid]::NewGuid().ToString('N')
    $passwordFile = Join-Path $scratch 'password'
    $passphraseFile = Join-Path $scratch 'passphrase'
    Set-Content -LiteralPath $passwordFile -Value $password -NoNewline -Encoding utf8
    Set-Content -LiteralPath $passphraseFile -Value 'disposable-key-passphrase' -NoNewline -Encoding utf8
    $publicKeys = ((Get-Content -LiteralPath "$key.pub" -Raw).Trim(), (Get-Content -LiteralPath "$agentKey.pub" -Raw).Trim()) -join "`n"
    & cargo build --locked -p scoplen-client-core --example ssh_jump_smoke *> (Join-Path $scratch 'build.log')
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath (Join-Path $scratch 'build.log') -Tail 35
        throw 'build jump fixture failed'
    }
    $suffix = if ($IsWindows) { '.exe' } else { '' }
    $targetRoot = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path (Get-Location) 'target' }
    $smoke = Join-Path $targetRoot "debug/examples/ssh_jump_smoke$suffix"
    & docker run --rm -d --name $container -p '127.0.0.1::2222' --add-host 'host.docker.internal:host-gateway' `
        -e 'USER_NAME=smoke' -e "USER_PASSWORD=$password" -e 'PASSWORD_ACCESS=true' -e "PUBLIC_KEY=$publicKeys" `
        'linuxserver/openssh-server@sha256:46f115de7c251558297e7e87566fc3fc08544b63e55502b5cf294454db5d29d1' | Out-Null
    Check-LastExit 'start isolated OpenSSH fixture'
    $binding = & docker port $container '2222/tcp'
    Check-LastExit 'read first-hop port'
    if ($binding -notmatch '^127\.0\.0\.1:(\d+)$') { throw "Unexpected OpenSSH binding: $binding" }
    $port = [int]$Matches[1]
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        & docker exec $container test -f /config/.ssh/authorized_keys 2>$null
        if ($LASTEXITCODE -eq 0) {
            $probe = [Net.Sockets.TcpClient]::new()
            try {
                if ($probe.ConnectAsync('127.0.0.1', $port).Wait([TimeSpan]::FromSeconds(1)) -and $probe.Connected) {
                    $ready = $true
                    break
                }
            } catch {} finally { $probe.Dispose() }
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw 'OpenSSH fixture did not become ready' }
    $setup = @'
set -eu
sed -i '/^AllowTcpForwarding /d; /^PerSourcePenalties /d' /config/sshd/sshd_config
printf '\nAllowTcpForwarding yes\nPerSourcePenalties no\n' >> /config/sshd/sshd_config
for port in 2223 2224; do
    ssh-keygen -q -t ed25519 -N '' -f "/tmp/host-$port"
    cat > "/tmp/sshd-$port.conf" <<CONF
Port $port
ListenAddress 0.0.0.0
HostKey /tmp/host-$port
PidFile /tmp/sshd-$port.pid
AuthorizedKeysFile /config/.ssh/authorized_keys
StrictModes no
PasswordAuthentication yes
KbdInteractiveAuthentication no
UsePAM no
AllowTcpForwarding yes
PerSourcePenalties no
LogLevel VERBOSE
CONF
    /usr/sbin/sshd.pam -t -f "/tmp/sshd-$port.conf"
    /usr/sbin/sshd.pam -E "/tmp/sshd-$port.log" -f "/tmp/sshd-$port.conf"
done
/usr/sbin/sshd.pam -t -f /config/sshd/sshd_config
pkill -HUP -o sshd
'@
    & docker exec $container sh -c ($setup.Replace("`r", ''))
    Check-LastExit 'start independent second-hop and target SSH servers'
    $arguments = @('127.0.0.1', $port, '127.0.0.1', 2223, '127.0.0.1', 2224, $passwordFile, $key, $passphraseFile, $agentKey)
    foreach ($mode in @('success', 'changed-1', 'changed-2', 'changed-3', 'cancel-1', 'cancel-2', 'cancel-3', 'wrong-password', 'agent-1', 'agent-2', 'agent-3')) {
        $env:SSH_AUTH_SOCK = if ($IsWindows) { '\\.\pipe\scoplen-jump-' + [guid]::NewGuid().ToString('N') } else { Join-Path $scratch ('agent-' + [guid]::NewGuid().ToString('N')) }
        & $smoke $mode @arguments
        Check-LastExit "jump $mode"
    }
    $closedArguments = $arguments.Clone(); $closedArguments[5] = 9
    & $smoke closed @closedArguments
    Check-LastExit 'closed next-hop destination'
    & docker exec $container sh -c 'sed -i "s/^AllowTcpForwarding yes/AllowTcpForwarding no/" /config/sshd/sshd_config; pkill -HUP -o sshd'
    Check-LastExit 'disable forwarding on disposable first hop'
    & $smoke denied @arguments
    Check-LastExit 'denied forwarding'
    & docker exec $container sh -c 'sed -i "s/^AllowTcpForwarding no/AllowTcpForwarding yes/" /config/sshd/sshd_config; pkill -HUP -o sshd'
    Check-LastExit 'restore disposable forwarding'
    $stall = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Any, 0)
    $stall.Start()
    $timeoutArguments = $arguments.Clone(); $timeoutArguments[4] = 'host.docker.internal'; $timeoutArguments[5] = $stall.LocalEndpoint.Port
    & $smoke timeout @timeoutArguments
    Check-LastExit 'bounded forwarded SSH handshake'
    & $smoke cancel-setup @timeoutArguments
    Check-LastExit 'cancel during forwarded SSH handshake'
    & $smoke success @arguments
    Check-LastExit 'fresh successful chain after all failure controls'
} catch {
    & docker logs --tail 15 $container
    throw
} finally {
    if ($stall) { $stall.Stop() }
    $env:SSH_AUTH_SOCK = $previousSocket
    & docker rm -f $container 2>$null | Out-Null
    $resolved = [IO.Path]::GetFullPath($scratch)
    if ([IO.Path]::GetDirectoryName($resolved) -eq $scratchRoot -and [IO.Path]::GetFileName($resolved) -like 'scoplen-jump-*') {
        Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction SilentlyContinue
    }
}
