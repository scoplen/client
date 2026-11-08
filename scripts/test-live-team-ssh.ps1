# SPDX-License-Identifier: Apache-2.0

param([Parameter(Mandatory)][string]$Deployment)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$deploymentPath = (Resolve-Path -LiteralPath $Deployment).Path
$scratchRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$scratch = Join-Path $scratchRoot ('scoplen-team-ssh-' + [guid]::NewGuid().ToString('N'))
$container = 'scoplen-team-ssh-' + [guid]::NewGuid().ToString('N')
$owner = [guid]::NewGuid().ToString()
$previousDeployment = $env:SCOPLEN_LIVE_ACCOUNT_DEPLOYMENT
$previousSshFixture = $env:SCOPLEN_LIVE_TEAM_SSH_FIXTURE
$successful = $false

function Check-LastExit([string]$operation) {
    if ($LASTEXITCODE -ne 0) { throw "$operation failed (exit $LASTEXITCODE)" }
}

try {
    New-Item -ItemType Directory -Path $scratch | Out-Null
    Set-Content -LiteralPath (Join-Path $scratch 'owner') -Value $owner -NoNewline
    & docker run --rm -d --name $container --label "com.scoplen.fixture=$owner" `
        -p '127.0.0.1::2222' -e 'USER_NAME=smoke' -e 'PASSWORD_ACCESS=false' `
        'linuxserver/openssh-server@sha256:46f115de7c251558297e7e87566fc3fc08544b63e55502b5cf294454db5d29d1' | Out-Null
    Check-LastExit 'start the owned OpenSSH fixture'
    $binding = (& docker port $container '2222/tcp') -join "`n"
    Check-LastExit 'read the OpenSSH loopback binding'
    if ($binding -notmatch '^127\.0\.0\.1:(\d+)$') { throw 'Unexpected OpenSSH loopback binding' }
    $port = [int]$Matches[1]
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $probe = [Net.Sockets.TcpClient]::new()
        try {
            if ($probe.ConnectAsync('127.0.0.1', $port).Wait([TimeSpan]::FromSeconds(1))) {
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
    if (-not $ready) { throw 'The owned OpenSSH fixture did not become ready' }
    $descriptor = Join-Path $scratch 'descriptor.json'
    @{ disposable = $true; container = $container; owner = $owner; port = $port } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $descriptor -Encoding utf8NoBOM
    $env:SCOPLEN_LIVE_ACCOUNT_DEPLOYMENT = $deploymentPath
    $env:SCOPLEN_LIVE_TEAM_SSH_FIXTURE = $descriptor
    $log = Join-Path $scratch 'acceptance.log'
    & cargo test --locked -p scoplen-client-core --features live-server-integration --lib `
        'personal_server::live_server::password_entry::team_ssh::live_team_ssh_and_sftp' `
        -- --exact --nocapture *> $log
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath $log -Tail 45
        throw "Real team SSH acceptance failed; private evidence retained in $scratch"
    }
    if (-not (Select-String -LiteralPath $log -Pattern 'test result: ok\. 1 passed; 0 failed;' -Quiet)) {
        throw 'The real team SSH acceptance did not execute exactly one test'
    }
    $successful = $true
    Write-Output 'Real team SSH terminal, binary SFTP roundtrip and access withdrawal passed.'
} finally {
    $env:SCOPLEN_LIVE_ACCOUNT_DEPLOYMENT = $previousDeployment
    $env:SCOPLEN_LIVE_TEAM_SSH_FIXTURE = $previousSshFixture
    $label = (& docker inspect --format '{{index .Config.Labels "com.scoplen.fixture"}}' $container 2>$null) -join ''
    if ($LASTEXITCODE -eq 0 -and $label -eq $owner) {
        if (-not $successful) { & docker logs $container *> (Join-Path $scratch 'openssh.log') }
        & docker rm -f $container | Out-Null
        Check-LastExit 'remove the owned OpenSSH fixture'
    }
    if ($successful -and (Test-Path -LiteralPath $scratch)) {
        $resolved = (Get-Item -LiteralPath $scratch).FullName
        if (-not $resolved.StartsWith($scratchRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) `
            -or (Get-Content -LiteralPath (Join-Path $resolved 'owner') -Raw) -ne $owner) {
            throw 'Refusing cleanup outside the owned fixture directory'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
