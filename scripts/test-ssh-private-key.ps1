# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$scratchRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/')
$scratch = Join-Path $scratchRoot ("scoplen-key-smoke-" + [guid]::NewGuid().ToString('N'))
$container = 'scoplen-key-smoke-' + [guid]::NewGuid().ToString('N').Substring(0, 12)

function Check-LastExit([string]$description) {
    if ($LASTEXITCODE -ne 0) { throw "$description failed (exit $LASTEXITCODE)" }
}

try {
    New-Item -ItemType Directory -Path $scratch | Out-Null
    $keys = @(
        @{ Name = 'ed25519'; Type = 'ed25519'; Bits = $null },
        @{ Name = 'p256'; Type = 'ecdsa'; Bits = '256' },
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
    $unsupportedKeys = @()
    foreach ($bits in @(384, 521)) {
        $keyPath = Join-Path $scratch "ecdsa-$bits"
        & ssh-keygen -q -t ecdsa -b $bits -N '' -f $keyPath
        Check-LastExit "generate ECDSA $bits key"
        $unsupportedKeys += $keyPath
    }
    $buildLog = Join-Path $scratch 'build.log'
    & cargo build --quiet -p scoplen-client-core --example ssh_private_key_smoke 2> $buildLog
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath $buildLog | Select-Object -Last 40
        Check-LastExit 'build SSH smoke example'
    }
    $suffix = if ($IsWindows) { '.exe' } else { '' }
    $smoke = Join-Path (Get-Location) "target/debug/examples/ssh_private_key_smoke$suffix"

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
            if ($entry.Name -eq 'ed25519') {
                foreach ($unsupportedKey in $unsupportedKeys) {
                    & $smoke unsupported 127.0.0.1 $port smoke $unsupportedKey
                    Check-LastExit 'unsupported ECDSA curve rejection'
                }
            }
        } finally {
            & docker rm -f $container | Out-Null
        }
    }
} finally {
    & docker rm -f $container 2>$null | Out-Null
    $resolved = [System.IO.Path]::GetFullPath($scratch)
    $parent = [System.IO.Path]::GetDirectoryName($resolved)
    if ($parent -eq $scratchRoot -and [System.IO.Path]::GetFileName($resolved) -like 'scoplen-key-smoke-*') {
        Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction SilentlyContinue
    }
}
