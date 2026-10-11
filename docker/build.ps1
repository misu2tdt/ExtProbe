<#
build.ps1 -- build extprobe-sandbox:v2, :v3 and :v3.1-probe from this repository (see docker/README.md).

  powershell -ExecutionPolicy Bypass -File docker/build.ps1

Prints the image ids; compare them with PROVENANCE.md (local ids differ between builds; the recorded ones identify the images that were
used for the evaluations).
#>
$ErrorActionPreference = 'Stop'
$Repo = Split-Path -Parent $PSScriptRoot
Set-Location $Repo
$builds = @(
    @{ Tag = 'extprobe-sandbox:v2';         File = 'docker/Dockerfile.base';  Context = 'sandbox/base' },
    @{ Tag = 'extprobe-sandbox:v3';         File = 'docker/Dockerfile.v3';    Context = 'sandbox/v3' },
    @{ Tag = 'extprobe-sandbox:v3.1-probe'; File = 'docker/Dockerfile.probe'; Context = 'sandbox/probe' }
)
foreach ($b in $builds) {
    & docker build -f $b.File -t $b.Tag $b.Context
    if ($LASTEXITCODE -ne 0) { throw "docker build failed for $($b.Tag)" }
    $id = (& docker image inspect $b.Tag --format '{{.Id}}' | Out-String).Trim()
    Write-Host "$($b.Tag) = $id"
}
