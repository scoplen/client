# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$scratchRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/')
$runId = [guid]::NewGuid().ToString('N')
$scratch = Join-Path $scratchRoot ('scoplen-files-' + $runId)
$container = 'scoplen-files-' + $runId.Substring(0, 12)
$completed = $false
function Check-LastExit([string]$description) {
    if ($LASTEXITCODE -ne 0) { throw "$description failed (exit $LASTEXITCODE)" }
}
function Test-OwnedContainer {
    $owner = & docker inspect --format '{{ index .Config.Labels "com.scoplen.session-files-check" }}' $container 2>$null
    if ($LASTEXITCODE -ne 0) { return $false }
    if ($owner -ne $runId) { throw 'Refusing to change a container with another fixture owner' }
    return $true
}
try {
    New-Item -ItemType Directory -Path $scratch | Out-Null
    if (-not $IsWindows) {
        [IO.File]::SetUnixFileMode($scratch, [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute)
    }
    Write-Output "Private OpenSSH fixture: $scratch"
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
    & docker run -d --name $container --label "com.scoplen.session-files-check=$runId" -p '127.0.0.1::2222' `
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
    & $smoke '127.0.0.1' $port $passwordFile 2>&1 | Tee-Object -FilePath (Join-Path $scratch 'ordinary.log')
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
    # Ordinary journeys keep the direct subsystem; only this connection loses a mkdir reply.
    $relay = @'
#!/bin/sh
set -eu
work=$(mktemp -d /tmp/scoplen-sync-relay.XXXXXX)
server= sender=
cleanup() {
    test -z "$sender" || kill "$sender" 2>/dev/null || true
    test -z "$server" || kill "$server" 2>/dev/null || true
    case "$work" in /tmp/scoplen-sync-relay.*) rm -rf "$work" ;; esac
}
trap cleanup EXIT HUP INT TERM
mkfifo "$work/request" "$work/response"
/usr/lib/ssh/sftp-server -e -l DEBUG3 < "$work/request" > "$work/response" 2>>/tmp/scoplen-files-sftp.log &
server=$!
exec 3>"$work/request" 4<"$work/response" 5<&0
frame() {
    dd bs=4 count=1 iflag=fullblock of="$1" 2>/dev/null
    test "$(wc -c < "$1")" -eq 4 || return 1
    set -- "$1" "$2" $(od -An -tu1 "$1")
    length=$(($3 * 16777216 + $4 * 65536 + $5 * 256 + $6))
    test "$length" -gt 0 && test "$length" -le 16384 || return 1
    dd bs="$length" count=1 iflag=fullblock of="$2" 2>/dev/null
    test "$(wc -c < "$2")" -eq "$length"
}
requests() {
    while frame "$work/request-header" "$work/request-body"; do
        set -- $(od -An -tu1 -N5 "$work/request-body")
        if test "$1" -eq 14; then
            mkdirs=$(($(cat /tmp/scoplen-sync-mkdir-count) + 1))
            test "$mkdirs" -le 2 || return 1
            printf '%s\n' "$mkdirs" > /tmp/scoplen-sync-mkdir-count
            if test "$mkdirs" -eq 2; then
                printf '%s\n' "$(($2 * 16777216 + $3 * 65536 + $4 * 256 + $5))" > "$work/withhold"
            fi
        fi
        cat "$work/request-header" "$work/request-body" >&3
    done
    kill "$server" 2>/dev/null || true
}
requests <&5 &
sender=$!
while frame "$work/response-header" "$work/response-body" <&4; do
    set -- $(od -An -tu1 -N9 "$work/response-body")
    if test "$1" -eq 101 && test -f "$work/withhold"; then
        id=$(($2 * 16777216 + $3 * 65536 + $4 * 256 + $5))
        if test "$id" -eq "$(cat "$work/withhold")" && test "$6$7$8$9" = 0000; then
            printf 'SCOPLEN-SYNC-MKDIR-STATUS-WITHHELD id=%s status=0\n' "$id" > /tmp/scoplen-sync-withheld
            exit 0
        fi
    fi
    cat "$work/response-header" "$work/response-body"
done
'@
    $relayPath = Join-Path $scratch 'sync-mkdir-relay.sh'
    [IO.File]::WriteAllText($relayPath, $relay.Replace([string][char]13, ''), [Text.UTF8Encoding]::new($false))
    & docker cp $relayPath ('{0}:/tmp/scoplen-sync-mkdir-relay' -f $container)
    Check-LastExit 'copy owned two-mkdir acknowledgement fault'
    & docker exec $container sh -c "set -e; chmod 755 /tmp/scoplen-sync-mkdir-relay; sh -n /tmp/scoplen-sync-mkdir-relay; printf 0 > /tmp/scoplen-sync-mkdir-count; chmod 600 /tmp/scoplen-sync-mkdir-count; chown smoke /tmp/scoplen-sync-mkdir-count; printf '#!/bin/sh\nexec /tmp/scoplen-sync-mkdir-relay\n' > /tmp/scoplen-files-sftp"
    Check-LastExit 'enable separate two-mkdir acknowledgement fault'
    & $smoke '127.0.0.1' $port $passwordFile '--unknown' 2>&1 | Tee-Object -FilePath (Join-Path $scratch 'unknown.log')
    Check-LastExit 'real OpenSSH directory partial and unknown result'
    $withheld = & docker exec $container cat /tmp/scoplen-sync-withheld
    Check-LastExit 'read actual successful mkdir acknowledgement evidence'
    if ($withheld -notmatch '^SCOPLEN-SYNC-MKDIR-STATUS-WITHHELD id=\d+ status=0$') {
        throw 'actual successful second mkdir STATUS was not withheld'
    }
    Write-Output $withheld
    $completed = $true
} catch {
    if (Test-OwnedContainer) {
        & docker logs $container *> (Join-Path $scratch 'container.log')
        & docker exec $container cat /tmp/scoplen-files-sftp.log *> (Join-Path $scratch 'sftp.log')
        & docker exec $container cat /tmp/scoplen-sync-withheld *> (Join-Path $scratch 'mkdir-acknowledgement.log')
        & docker stop $container *> (Join-Path $scratch 'stop.log')
    }
    Write-Warning "Failed private OpenSSH evidence retained at $scratch; owned container: $container"
    throw
} finally {
    if ($completed) {
        if (Test-OwnedContainer) {
            & docker rm -f -v $container 2>$null | Out-Null
            Check-LastExit 'remove owned successful OpenSSH fixture'
        }
        if (Test-Path -LiteralPath $scratch) {
            $resolvedScratch = [System.IO.Path]::GetFullPath($scratch)
            if (-not $resolvedScratch.StartsWith($scratchRoot + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing cleanup outside temporary directory: $resolvedScratch"
            }
            Remove-Item -LiteralPath $resolvedScratch -Recurse -Force
        }
        Write-Output 'OpenSSH Files acceptance passed; owned successful fixture removed'
    }
}
