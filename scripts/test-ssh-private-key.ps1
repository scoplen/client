# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$scratchRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/')
$scratch = Join-Path $scratchRoot ("scoplen-key-smoke-" + [guid]::NewGuid().ToString('N'))
$container = 'scoplen-key-smoke-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$rsaContainer = 'scoplen-rsa-key-smoke-' + [guid]::NewGuid().ToString('N').Substring(0, 12)

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
        @{ Name = 'rsa'; Type = 'rsa'; Bits = '3072' }
    )
    foreach ($entry in $keys) {
        $keyPath = Join-Path $scratch $entry.Name
        $keyArgs = @('-q', '-t', $entry.Type, '-N', '', '-f', $keyPath)
        if ($entry.Bits) { $keyArgs += @('-b', $entry.Bits) }
        & ssh-keygen @keyArgs
        Check-LastExit "generate $($entry.Name) key"
    }
    foreach ($entry in $keys) {
        $wrongKey = Join-Path $scratch "wrong-$($entry.Name)"
        $keyArgs = @('-q', '-t', $entry.Type, '-N', '', '-f', $wrongKey)
        if ($entry.Bits) { $keyArgs += @('-b', $entry.Bits) }
        & ssh-keygen @keyArgs
        Check-LastExit "generate wrong $($entry.Name) key"
    }
    $encryptedKey = Join-Path $scratch 'encrypted'
    & ssh-keygen -q -t ed25519 -N 'disposable-test-passphrase' -f $encryptedKey
    Check-LastExit 'generate encrypted key'
    $invalidKey = Join-Path $scratch 'invalid'
    Set-Content -LiteralPath $invalidKey -Value 'invalid OpenSSH key' -NoNewline
    $buildLog = Join-Path $scratch 'build.log'
    & cargo build --quiet --locked -p scoplen-client-core --example ssh_private_key_smoke 2> $buildLog
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath $buildLog | Select-Object -Last 40
        Check-LastExit 'build SSH smoke example'
    }
    $suffix = if ($IsWindows) { '.exe' } else { '' }
    $targetRoot = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path (Get-Location) 'target' }
    $smoke = Join-Path $targetRoot "debug/examples/ssh_private_key_smoke$suffix"

    foreach ($entry in $keys) {
        $keyPath = Join-Path $scratch $entry.Name
        $wrongKey = Join-Path $scratch "wrong-$($entry.Name)"
        $publicKey = (Get-Content -LiteralPath "$keyPath.pub" -Raw).Trim()
        & docker run --rm -d --name $container -p '127.0.0.1::2222' -e 'USER_NAME=smoke' -e "PUBLIC_KEY=$publicKey" -e 'PASSWORD_ACCESS=false' 'linuxserver/openssh-server@sha256:46f115de7c251558297e7e87566fc3fc08544b63e55502b5cf294454db5d29d1' | Out-Null
        Check-LastExit 'start OpenSSH fixture'
        try {
            $binding = & docker port $container '2222/tcp'
            Check-LastExit 'read OpenSSH port'
            $port = [int](($binding | Select-Object -First 1) -split ':')[-1]
            $ready = $false
            for ($attempt = 0; $attempt -lt 60; $attempt++) {
                $probe = & $smoke untrusted 127.0.0.1 $port smoke $keyPath 2>&1
                if ($LASTEXITCODE -eq 0 -and $probe -match 'untrusted host rejected') {
                    $ready = $true
                    break
                }
                Start-Sleep -Milliseconds 500
            }
            if (-not $ready) {
                & docker logs --tail 25 $container
                throw 'OpenSSH fixture did not become ready'
            }

            & $smoke success 127.0.0.1 $port smoke $keyPath
            Check-LastExit "$($entry.Name) authentication"
            $wrongMode = if ($entry.Name -eq 'rsa') { 'wrong-rsa-key' } else { 'wrong-key' }
            & $smoke $wrongMode 127.0.0.1 $port smoke $wrongKey
            Check-LastExit "$($entry.Name) wrong-key rejection"
            & $smoke untrusted 127.0.0.1 $port smoke $keyPath
            Check-LastExit "$($entry.Name) untrusted-host rejection"
            & $smoke invalid 127.0.0.1 $port smoke $invalidKey
            Check-LastExit "$($entry.Name) malformed-key rejection"
            & $smoke encrypted 127.0.0.1 $port smoke $encryptedKey
            Check-LastExit "$($entry.Name) encrypted-key rejection"
        } finally {
            & docker rm -f $container | Out-Null
        }
    }

    $rsaKey = Join-Path $scratch 'rsa'
    $wrongRsaKey = Join-Path $scratch 'wrong-rsa'
    $rsaPublicKey = (Get-Content -LiteralPath "$rsaKey.pub" -Raw).Trim()
    $setup = @'
set -eu
apk add --no-cache openssh-server
adduser -D smoke
printf 'smoke:disposable-test-password\n' | chpasswd
ssh-keygen -q -t ed25519 -N '' -f /tmp/host_key
mkdir -p /home/smoke/.ssh /run/sshd
printf '%s\n' "$PUBLIC_KEY" > /home/smoke/.ssh/authorized_keys
chown -R smoke:smoke /home/smoke/.ssh
chmod 700 /home/smoke/.ssh
chmod 600 /home/smoke/.ssh/authorized_keys
for mode in sha256 sha512 sha1; do
    case "$mode" in
        sha256) port=2222; algorithm='rsa-sha2-256' ;;
        sha512) port=2223; algorithm='rsa-sha2-512' ;;
        sha1) port=2224; algorithm='ssh-rsa' ;;
    esac
    cat > "/tmp/$mode.conf" <<SSHD
Port $port
ListenAddress 0.0.0.0
HostKey /tmp/host_key
PubkeyAuthentication yes
PubkeyAcceptedAlgorithms $algorithm
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
LogLevel VERBOSE
SSHD
    /usr/sbin/sshd -t -f "/tmp/$mode.conf"
done
/usr/sbin/sshd -D -e -f /tmp/sha256.conf &
/usr/sbin/sshd -D -e -f /tmp/sha512.conf &
exec /usr/sbin/sshd -D -e -f /tmp/sha1.conf
'@
    & docker run --rm -d --name $rsaContainer -p '127.0.0.1::2222' -p '127.0.0.1::2223' -p '127.0.0.1::2224' -e "PUBLIC_KEY=$rsaPublicKey" alpine:3.21 sh -c ($setup.Replace("`r", '')) | Out-Null
    Check-LastExit 'start constrained RSA OpenSSH fixture'
    try {
        foreach ($mode in @(
            @{ Name = 'sha256'; Port = 2222; Smoke = 'success' },
            @{ Name = 'sha512'; Port = 2223; Smoke = 'success' },
            @{ Name = 'sha1'; Port = 2224; Smoke = 'sha1-only' }
        )) {
            $binding = & docker port $rsaContainer "$($mode.Port)/tcp"
            Check-LastExit "read $($mode.Name) OpenSSH port"
            if ($binding -notmatch '^127\.0\.0\.1:(\d+)$') { throw "Unexpected $($mode.Name) port binding: $binding" }
            $port = [int]$Matches[1]
            $ready = $false
            for ($attempt = 0; $attempt -lt 60; $attempt++) {
                $probe = & $smoke untrusted 127.0.0.1 $port smoke $rsaKey 2>&1
                if ($LASTEXITCODE -eq 0 -and $probe -match 'untrusted host rejected') {
                    $ready = $true
                    break
                }
                Start-Sleep -Milliseconds 500
            }
            if (-not $ready) {
                & docker logs --tail 25 $rsaContainer
                throw "$($mode.Name) OpenSSH fixture did not become ready"
            }
            & $smoke $mode.Smoke 127.0.0.1 $port smoke $rsaKey
            Check-LastExit "$($mode.Name) RSA authentication policy"
            if ($mode.Name -ne 'sha1') {
                & $smoke wrong-rsa-key 127.0.0.1 $port smoke $wrongRsaKey
                Check-LastExit "$($mode.Name) wrong RSA key rejection"
            }
        }
    } finally {
        & docker rm -f $rsaContainer | Out-Null
    }
} finally {
    & docker rm -f $container 2>$null | Out-Null
    & docker rm -f $rsaContainer 2>$null | Out-Null
    $resolved = [System.IO.Path]::GetFullPath($scratch)
    $parent = [System.IO.Path]::GetDirectoryName($resolved)
    if ($parent -eq $scratchRoot -and [System.IO.Path]::GetFileName($resolved) -like 'scoplen-key-smoke-*') {
        Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction SilentlyContinue
    }
}
