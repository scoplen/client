# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$scratchRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$scratch = Join-Path $scratchRoot ('scoplen-import-' + [guid]::NewGuid().ToString('N'))
$container = 'scoplen-import-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
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
    $identity = Join-Path $scratch 'identity key'
    & ssh-keygen -q -t ed25519 -N '' -C 'scoplen-import-fixture' -f $identity
    Check-LastExit 'generate disposable migration identity'
    & cargo build --locked -p scoplen-client-core --example openssh_import_smoke *> (Join-Path $scratch 'build.log')
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath (Join-Path $scratch 'build.log') -Tail 35
        throw 'build OpenSSH import fixture failed'
    }
    $metadata = & cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json
    Check-LastExit 'read managed Cargo target directory'
    $suffix = if ($IsWindows) { '.exe' } else { '' }
    $smoke = Join-Path $metadata.target_directory "debug/examples/openssh_import_smoke$suffix"
    $public = (Get-Content -LiteralPath "$identity.pub" -Raw).Trim()
    & docker run --rm -d --name $container -p '127.0.0.1::2222' `
        -e 'USER_NAME=smoke' -e "PUBLIC_KEY=$public" -e 'PASSWORD_ACCESS=false' `
        'linuxserver/openssh-server@sha256:46f115de7c251558297e7e87566fc3fc08544b63e55502b5cf294454db5d29d1' | Out-Null
    Check-LastExit 'start isolated OpenSSH import fixture'
    $binding = & docker port $container '2222/tcp'
    Check-LastExit 'read OpenSSH import port'
    if ($binding -notmatch '^127\.0\.0\.1:(\d+)$') { throw 'Unexpected OpenSSH import binding' }
    $port = [int]$Matches[1]
    $known = Join-Path $scratch 'known_hosts'
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
    if (-not $ready) { throw 'OpenSSH import fixture did not become ready' }
    $hostKeys = & docker exec $container sh -c 'cat /config/ssh_host_keys/*.pub'
    Check-LastExit 'read the owned fixture host public keys'
    if (-not $hostKeys) { throw 'The owned fixture has no host public keys' }
    $knownLines = $hostKeys | ForEach-Object { "[127.0.0.1]:$port $_" }
    Set-Content -LiteralPath $known -Value $knownLines -Encoding ascii
    & $smoke $port $identity $known $scratch
    Check-LastExit 'OpenSSH migration to a real SSH and SFTP session'
    $passed = $true
} finally {
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
        Write-Output 'OpenSSH import fixture failed; private diagnostics retained locally.'
    }
}
