# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$scratchRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$scratch = Join-Path $scratchRoot ('scoplen-export-' + [guid]::NewGuid().ToString('N'))
$container = 'scoplen-export-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$previousSocket = $env:SSH_AUTH_SOCK
$passed = $false

function Check-LastExit([string]$description) {
    if ($LASTEXITCODE -ne 0) { throw "$description failed (exit $LASTEXITCODE)" }
}

try {
    New-Item -ItemType Directory -Path $scratch | Out-Null
    if ($IsWindows) {
        $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetOwner($owner)
        $acl.SetAccessRuleProtection($true, $false)
        $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
        foreach ($identitySid in @($owner, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $identitySid, 'FullControl', $inherit, 'None', 'Allow'))
        }
        Set-Acl -LiteralPath $scratch -AclObject $acl
    }
    $identity = Join-Path $scratch 'encrypted source identity'
    $passphrase = Join-Path $scratch 'key-passphrase'
    $password = Join-Path $scratch 'password'
    Set-Content -LiteralPath $passphrase -Value 'disposable-export-passphrase' -NoNewline -Encoding utf8
    Set-Content -LiteralPath $password -Value 'disposable-export-password' -NoNewline -Encoding utf8
    & ssh-keygen -q -t ed25519 -N 'disposable-export-passphrase' -C 'scoplen-export-fixture' -f $identity
    Check-LastExit 'generate disposable encrypted identity'
    & cargo build --locked -p scoplen-client-core --example openssh_export_smoke *> (Join-Path $scratch 'build.log')
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath (Join-Path $scratch 'build.log') -Tail 35
        throw 'build OpenSSH export fixture failed'
    }
    $metadata = & cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json
    Check-LastExit 'read managed Cargo target directory'
    $suffix = if ($IsWindows) { '.exe' } else { '' }
    $smoke = Join-Path $metadata.target_directory "debug/examples/openssh_export_smoke$suffix"
    $public = (Get-Content -LiteralPath "$identity.pub" -Raw).Trim()
    & docker run --rm -d --name $container -p '127.0.0.1::2222' `
        -e 'USER_NAME=smoke' -e "PUBLIC_KEY=$public" -e 'PASSWORD_ACCESS=true' `
        -e 'USER_PASSWORD=disposable-export-password' `
        'linuxserver/openssh-server@sha256:46f115de7c251558297e7e87566fc3fc08544b63e55502b5cf294454db5d29d1' | Out-Null
    Check-LastExit 'start isolated OpenSSH export fixture'
    $binding = & docker port $container '2222/tcp'
    Check-LastExit 'read OpenSSH export port'
    if ($binding -notmatch '^127\.0\.0\.1:(\d+)$') { throw 'Unexpected OpenSSH export binding' }
    $port = [int]$Matches[1]
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
    if (-not $ready) { throw 'OpenSSH export fixture did not become ready' }
    $setup = @'
set -eu
sed -i '/^AllowTcpForwarding /d; /^PerSourcePenalties /d' /config/sshd/sshd_config
printf '\nAllowTcpForwarding yes\nPerSourcePenalties no\n' >> /config/sshd/sshd_config
/usr/sbin/sshd.pam -t -f /config/sshd/sshd_config
pkill -HUP -o sshd
'@
    & docker exec $container sh -c ($setup.Replace("`r", ''))
    Check-LastExit 'enable forwarding only on the owned Jump fixture'
    $hostKeys = & docker exec $container sh -c 'cat /config/ssh_host_keys/*.pub'
    Check-LastExit 'read owned fixture host public keys'
    $known = Join-Path $scratch 'known_hosts'
    Set-Content -LiteralPath $known -Value ($hostKeys | ForEach-Object { "[127.0.0.1]:$port $_" }) -Encoding ascii
    $env:SSH_AUTH_SOCK = if ($IsWindows) { "\\.\pipe\$container-agent" } else { Join-Path $scratch 'agent.sock' }
    & $smoke $port $identity $passphrase $password $known $scratch
    Check-LastExit 'standard OpenSSH authentication and import round-trip'
    $passed = $true
} finally {
    $env:SSH_AUTH_SOCK = $previousSocket
    if (-not $passed -and (Test-Path -LiteralPath $scratch)) {
        & docker logs --tail 80 $container *> (Join-Path $scratch 'server.log')
    }
    & docker rm -f $container 2>$null | Out-Null
    if ($passed -and (Test-Path -LiteralPath $scratch)) {
        $resolved = [IO.Path]::GetFullPath($scratch)
        if (-not $resolved.StartsWith($scratchRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing cleanup outside the owned temporary directory'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    } elseif (Test-Path -LiteralPath $scratch) {
        Write-Output 'OpenSSH export fixture failed; private diagnostics retained locally.'
    }
}
