# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$scratchRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/')
$scratch = Join-Path $scratchRoot ('scoplen-files-' + [guid]::NewGuid().ToString('N'))
$container = 'scoplen-files-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
function Check-LastExit([string]$description) {
    if ($LASTEXITCODE -ne 0) { throw "$description failed (exit $LASTEXITCODE)" }
}
try {
    New-Item -ItemType Directory -Path $scratch | Out-Null
    $password = 'disposable-fixture-' + [guid]::NewGuid().ToString('N')
    $passwordFile = Join-Path $scratch 'password'
    Set-Content -LiteralPath $passwordFile -Value $password -NoNewline -Encoding utf8
    & cargo build --locked -p scoplen-client-core --example ssh_session_files_smoke *> (Join-Path $scratch 'build.log')
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath (Join-Path $scratch 'build.log') -Tail 35
        throw 'build file-session fixture failed'
    }
    $suffix = if ($IsWindows) { '.exe' } else { '' }
    $metadata = & cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json
    Check-LastExit 'read managed Cargo target directory'
    $targetRoot = $metadata.target_directory
    $smoke = Join-Path $targetRoot "debug/examples/ssh_session_files_smoke$suffix"
    & docker run --rm -d --name $container -p '127.0.0.1::2222' `
        -e 'USER_NAME=smoke' -e "USER_PASSWORD=$password" -e 'PASSWORD_ACCESS=true' `
        'linuxserver/openssh-server@sha256:46f115de7c251558297e7e87566fc3fc08544b63e55502b5cf294454db5d29d1' | Out-Null
    Check-LastExit 'start isolated OpenSSH fixture'
    $binding = & docker port $container '2222/tcp'
    Check-LastExit 'read OpenSSH port'
    if ($binding -notmatch '^127\.0\.0\.1:(\d+)$') { throw "Unexpected OpenSSH binding: $binding" }
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
    if (-not $ready) { throw 'OpenSSH fixture did not become ready' }
    $captureSftp = @'
set -eu
test -x /usr/lib/ssh/sftp-server
printf '#!/bin/sh\nexec /usr/lib/ssh/sftp-server -e -l DEBUG3 2>>/tmp/scoplen-files-sftp.log\n' > /tmp/scoplen-files-sftp
chmod 755 /tmp/scoplen-files-sftp
sed -i 's|^Subsystem[[:space:]]\+sftp.*|Subsystem sftp /tmp/scoplen-files-sftp|' /config/sshd/sshd_config
/usr/sbin/sshd.pam -t -f /config/sshd/sshd_config
pkill -HUP -o sshd
'@
    & docker exec $container sh -c $captureSftp
    Check-LastExit 'enable disposable SFTP offset evidence'
    & $smoke '127.0.0.1' $port $passwordFile
    Check-LastExit 'real SSH terminal and SFTP file session'
    $sftpLog = (& docker exec $container cat /tmp/scoplen-files-sftp.log) -join "`n"
    Check-LastExit 'read disposable SFTP offset evidence'
    if ($sftpLog -notmatch '(?s)SCOPLEN-UPLOAD-RESUME (\d+)\r?\n(.*)') {
        throw 'upload continuation marker was not captured'
    }
    $confirmedOffset = [uint64]$Matches[1]
    $resumedLog = $Matches[2]
    if ($confirmedOffset -eq 0 -or $resumedLog -notmatch 'write .* off (\d+) len (\d+)') {
        throw 'no actual resumed SFTP WRITE offset was captured'
    }
    if ([uint64]$Matches[1] -ne $confirmedOffset) {
        throw 'first resumed SFTP WRITE did not continue from the confirmed offset'
    }
    Write-Output "OpenSSH upload continuation WRITE starts at confirmed nonzero offset $confirmedOffset"
} finally {
    & docker rm -f $container 2>$null | Out-Null
    if (Test-Path -LiteralPath $scratch) {
        $resolvedScratch = [System.IO.Path]::GetFullPath($scratch)
        if (-not $resolvedScratch.StartsWith($scratchRoot + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing cleanup outside temporary directory: $resolvedScratch"
        }
        Remove-Item -LiteralPath $resolvedScratch -Recurse -Force
    }
}
