# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$container = 'scoplen-client-unix-agent-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
try {
    & docker run --rm --name $container `
        --mount "type=bind,source=$repository,target=/repo,readonly" `
        --env RUSTUP_TOOLCHAIN=1.99.0 `
        --workdir /repo rust:1.99.0-bookworm bash scripts/test-ssh-agent-unix.sh
    if ($LASTEXITCODE -ne 0) { throw "Unix agent login fixture failed (exit $LASTEXITCODE)" }
} finally {
    & docker rm -f $container 2>$null | Out-Null
}
