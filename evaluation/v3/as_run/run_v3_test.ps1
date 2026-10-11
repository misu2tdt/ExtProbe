<#
run_v3_test.ps1 -- the held-out benign test set, run ONCE on the frozen v3 configuration
(eval/v3/FREEZE_v3.md, eval/v3/TEST_SET_CRITERIA.md). Windows PowerShell 5.1+.

  powershell -ExecutionPolicy Bypass -File run_v3_test.ps1           # run everything
  powershell -ExecutionPolicy Bypass -File run_v3_test.ps1 -DryRun   # checks, counts, estimate; no sandbox

200 extensions of samples\benign_test, two profiles, 2 workers each, one after the other:
  (a) v3  : eval/v3/run_v3.py            image extprobe-sandbox:v3   -> eval\v3\test\traces_v3
  (b) v2  : eval/batch_run.py --profile v2   image extanalyze-sandbox:v2 -> eval\v3\test\traces_v2
Then eval/v3/test_analysis.py -> eval\v3\test\results.md (FPR v2 vs v3).
Log (appended): eval\v3\test\runner.log; batch output: eval\v3\test\<batch>.log.

Refuses to start unless ALL hold (every check is evaluated and logged; any failure aborts):
  - HEAD is exactly the tag v3.0-freeze (create it only when FREEZE_v3.md is committed);
  - the working tree is clean (untracked outputs under eval\v3\dev and eval\v3\test are ignored);
  - every file listed in FREEZE_v3.md has the recorded git blob / tree id at HEAD, and the v2 paths
    (worker, sandbox, the eval scripts of the v2 run) are unchanged since v2.0-freeze;
  - the images have the recorded ids: extprobe-sandbox:v3 (eval\v3\IMAGE.md), extanalyze-sandbox:v2 and
    extprobe-sandbox:v2 (FREEZE.md);
  - eval/verify_samples.py --benign-test passes (samples\benign_test: 200 .crx, SHA-256 match the manifest).
Before every batch attempt it waits (60 s steps, logged) until Docker answers. Each batch runs at most 3 times;
the runners skip samples already done, and samples left incomplete by a Docker failure (no trace, docker
exit != 0, or no run status) are moved to eval\v3\test\_incomplete\ before the next attempt. The PC is kept
awake. No absolute path or IP address is written to the log. The test set is run once: a finished profile
(all 200 complete) is not run again by this script.
#>
param([switch]$DryRun)

$ErrorActionPreference = 'Continue'
$Repo = $PSScriptRoot
Set-Location $Repo
$Tag = 'v3.0-freeze'
$V2Tag = 'v2.0-freeze'
$Out = Join-Path $Repo 'eval\v3\test'
$RunnerLog = Join-Path $Out 'runner.log'
$MaxAttempts = 3
$Workers = 2
$Expected = 200
$Samples = 'samples\benign_test'
$V2Frozen = @('worker', 'sandbox', 'eval/batch_run.py', 'eval/rescore.py',
              'eval/apply_verified_labels.py', 'eval/save_metrics.py', 'pytest.ini')
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONUNBUFFERED = '1'

$Batches = @(
    @{ Name = 'TEST_v3'; Results = 'eval\v3\test\traces_v3'
       Args = @('eval\v3\run_v3.py', '--out', 'eval\v3\test\traces_v3', '--workers', "$Workers", '--label', 'benign', '--samples', $Samples) },
    @{ Name = 'TEST_v2'; Results = 'eval\v3\test\traces_v2'
       Args = @('eval\batch_run.py', '--profile', 'v2', '--workers', "$Workers", '--samples', $Samples,
                '--label', 'benign', '--results', 'eval\v3\test\traces_v2') }
)
$Final = @(, @('eval\v3\test_analysis.py'))

function Log([string]$msg) {
    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
    Write-Host $line
    if (-not $DryRun) { Add-Content -Path $RunnerLog -Value $line -Encoding utf8 }
}

function Docker-Version {
    $v = (& docker info --format '{{.ServerVersion}}' 2>$null | Out-String).Trim()
    if ($v -match '^\d+\.\d+') { return $v } else { return $null }
}

function Wait-Docker {
    $started = $false
    while (-not (Docker-Version)) {
        if (-not $started) {
            $dd = 'C:\Program Files\Docker\Docker\Docker Desktop.exe'
            if (Test-Path $dd) { Log 'docker not reachable: starting Docker Desktop'; Start-Process $dd }
            $started = $true
        }
        Log 'docker not reachable: waiting 60 s'
        Start-Sleep -Seconds 60
    }
}

function Image-Id([string]$name) { return (& docker image inspect $name --format '{{.Id}}' 2>$null | Out-String).Trim() }

function Recorded-V3-Image-Id {
    $line = Select-String -Path (Join-Path $Repo 'eval\v3\IMAGE.md') -Pattern 'local image id' | Select-Object -First 1
    if (-not $line) { return $null }
    $m = [regex]::Match($line.Line, 'sha256:[0-9a-f]{64}')
    if ($m.Success) { return $m.Value } else { return $null }
}

function Frozen-V2-Image-Id {
    $line = Select-String -Path (Join-Path $Repo 'FREEZE.md') -Pattern 'local image id at freeze' | Select-Object -First 1
    $ids = [regex]::Matches($line.Line, 'sha256:[0-9a-f]{64}') | ForEach-Object { $_.Value }
    return $ids[1]
}

function Count-Crx([string]$dir) {
    $p = Join-Path $Repo $dir
    if (-not (Test-Path $p)) { return 0 }
    return @(Get-ChildItem $p -Filter *.crx -File).Count
}

function Mean-Duration([string[]]$dirs) {
    $durs = @()
    foreach ($d in $dirs) {
        $p = Join-Path $Repo $d
        if (-not (Test-Path $p)) { continue }
        foreach ($x in Get-ChildItem $p -Directory) {
            $mp = Join-Path $x.FullName 'meta.json'
            if (Test-Path $mp) {
                $m = Get-Content $mp -Raw -Encoding utf8 | ConvertFrom-Json
                if ($m.duration_s) { $durs += [double]$m.duration_s }
            }
        }
    }
    if ($durs.Count -eq 0) { return $null }
    return @{ Mean = [math]::Round(($durs | Measure-Object -Average).Average, 1); N = $durs.Count }
}

function Check-Inputs {
    $ok = $true
    # --- the tag
    $exact = (& git describe --tags --exact-match HEAD 2>$null | Out-String).Trim()
    if ($exact -eq $Tag) { Log "check: HEAD is tag $Tag" }
    else {
        $have = (& git tag --list $Tag | Out-String).Trim()
        if ($have) { Log "CHECK FAIL: HEAD is not $Tag (the tag points elsewhere)" }
        else { Log "CHECK FAIL: tag $Tag does not exist. Commit eval/v3/FREEZE_v3.md, then: git tag $Tag" }
        $ok = $false
    }
    # --- working tree
    $dirty = (& git status --porcelain | Out-String).Split("`n") |
        Where-Object { $_.Trim() -and $_ -notmatch '^\?\? eval/v3/(dev|test)/' }
    if ($dirty) { Log ("CHECK FAIL: working tree not clean:`n" + ($dirty -join "`n")); $ok = $false } else { Log 'check: working tree clean' }
    # --- frozen files (git blob / tree ids recorded in FREEZE_v3.md)
    $fz = Join-Path $Repo 'eval\v3\FREEZE_v3.md'
    if (-not (Test-Path $fz)) { Log 'CHECK FAIL: eval/v3/FREEZE_v3.md missing'; $ok = $false }
    else {
        $n = 0; $bad = 0
        foreach ($line in Get-Content $fz -Encoding utf8) {
            $m = [regex]::Match($line, '^\|\s*`([^`]+)`\s*\|\s*`([0-9a-f]{40})`\s*\|')
            if (-not $m.Success) { continue }
            $n++
            $got = (& git rev-parse "HEAD:$($m.Groups[1].Value)" 2>$null | Out-String).Trim()
            if ($got -ne $m.Groups[2].Value) { Log ("CHECK FAIL: {0} is {1}, FREEZE_v3.md says {2}" -f $m.Groups[1].Value, $got, $m.Groups[2].Value); $bad++ }
        }
        if ($n -eq 0) { Log 'CHECK FAIL: FREEZE_v3.md lists no file ids'; $ok = $false }
        elseif ($bad -eq 0) { Log "check: $n frozen files/trees match FREEZE_v3.md" }
        else { $ok = $false }
    }
    & git merge-base --is-ancestor $V2Tag HEAD 2>$null
    $isDesc = ($LASTEXITCODE -eq 0)
    & git diff --quiet $V2Tag HEAD -- $V2Frozen
    $same = ($LASTEXITCODE -eq 0)
    if ($isDesc -and $same) { Log "check: v2 paths unchanged since $V2Tag" }
    else { Log "CHECK FAIL: v2 paths changed since $V2Tag (descendant=$isDesc, unchanged=$same)"; $ok = $false }
    # --- docker + images
    $v = Docker-Version
    if (-not $v) {
        if ($DryRun) { Log 'CHECK FAIL: docker not reachable (a real run would wait for it)'; $ok = $false }
        else { Wait-Docker; $v = Docker-Version }
    }
    if ($v) {
        Log "check: docker engine $v"
        $want3 = Recorded-V3-Image-Id
        $got3 = Image-Id 'extprobe-sandbox:v3'
        if ($want3 -and $got3 -eq $want3) { Log "check: image extprobe-sandbox:v3 = $got3 (eval/v3/IMAGE.md)" }
        else { Log "CHECK FAIL: image extprobe-sandbox:v3 is '$got3', eval/v3/IMAGE.md says '$want3'"; $ok = $false }
        $want2 = Frozen-V2-Image-Id
        foreach ($name in 'extanalyze-sandbox:v2', 'extprobe-sandbox:v2') {
            $got = Image-Id $name
            if ($got -eq $want2) { Log "check: image $name = $got (FREEZE.md)" }
            else { Log "CHECK FAIL: image $name is '$got', FREEZE.md says $want2"; $ok = $false }
        }
    }
    # --- samples
    $vs = & py eval\verify_samples.py --benign-test 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { Log 'check: samples verified (--benign-test, checksums OK)' }
    else { Log "CHECK FAIL: eval/verify_samples.py --benign-test`n$vs"; $ok = $false }
    $c = Count-Crx $Samples
    if ($c -eq $Expected) { Log ("check: {0} {1} .crx" -f $Samples, $c) }
    else { Log ("CHECK FAIL: {0} has {1} .crx, expected {2}" -f $Samples, $c, $Expected); $ok = $false }
    return $ok
}

function Incomplete-Runs([string]$results) {
    $dir = Join-Path $Repo $results
    if (-not (Test-Path $dir)) { return @() }
    $bad = @()
    foreach ($d in Get-ChildItem $dir -Directory) {
        $metaPath = Join-Path $d.FullName 'meta.json'
        if (-not (Test-Path $metaPath)) { continue }
        $m = Get-Content $metaPath -Raw -Encoding utf8 | ConvertFrom-Json
        $hasEvents = Test-Path (Join-Path $d.FullName 'output\events.json')
        if (-not $hasEvents -or $m.docker_exit -ne 0 -or @('unknown', 'unreadable_events') -contains $m.run_status) { $bad += $d }
    }
    return $bad
}

function Done-Count([string]$results) {
    $dir = Join-Path $Repo $results
    if (-not (Test-Path $dir)) { return 0 }
    return @(Get-ChildItem $dir -Directory | Where-Object {
        $mp = Join-Path $_.FullName 'meta.json'
        (Test-Path $mp) -and ((Get-Content $mp -Raw -Encoding utf8 | ConvertFrom-Json).run_status -eq 'complete') }).Count
}

# ---------------------------------------------------------------------------------------
if ($DryRun) { Write-Host '=== DRY RUN: checks and commands only; nothing is executed ===' }
else {
    New-Item -ItemType Directory -Force $Out | Out-Null
    Add-Type -Namespace Win32 -Name Power -MemberDefinition '[DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint esFlags);'
    [void][Win32.Power]::SetThreadExecutionState([uint32]'0x80000001')
}
Log "=== run_v3_test.ps1 start (DryRun=$DryRun) ==="
if (-not (Check-Inputs)) { Log 'ABORT: input checks failed; nothing was run'; exit 1 }

Log ("samples: {0} extensions, 2 profiles" -f $Expected)
$e3 = Mean-Duration @('eval\v3\dev\traces')
$e2 = Mean-Duration @('eval\expanded\V2')
if ($e3 -and $e2) {
    $m3 = [math]::Round($Expected * $e3.Mean / $Workers / 60, 0)
    $m2 = [math]::Round($Expected * $e2.Mean / $Workers / 60, 0)
    Log ("estimate: v3 {0} x {1} s (mean of {2} dev traces) / {3} workers = about {4} min; v2 {0} x {5} s (mean of {6} traces of the v2 run) / {3} = about {7} min; total about {8} min ({9:N1} h)" -f $Expected, $e3.Mean, $e3.N, $Workers, $m3, $e2.Mean, $e2.N, $m2, ($m3 + $m2), (($m3 + $m2) / 60))
} else { Log 'estimate: no earlier traces to estimate from' }

foreach ($b in $Batches) {
    $log = Join-Path $Out ($b.Name + '.log')
    if ($DryRun) { Write-Host ("[{0}] py {1}  >> eval\v3\test\{0}.log  (up to {2} attempts)" -f $b.Name, ($b.Args -join ' '), $MaxAttempts); continue }
    if ((Done-Count $b.Results) -ge $Expected) { Log ("SKIP {0}: all {1} traces already complete" -f $b.Name, $Expected); continue }
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        Wait-Docker
        $t0 = Get-Date
        Log ("START {0} attempt {1}/{2}: py {3}" -f $b.Name, $attempt, $MaxAttempts, ($b.Args -join ' '))
        Add-Content -Path $log -Value ("===== {0} attempt {1} {2} =====" -f $b.Name, $attempt, (Get-Date -Format s)) -Encoding utf8
        & py @($b.Args) 2>&1 | Out-File -FilePath $log -Append -Encoding utf8
        $code = $LASTEXITCODE
        $mins = [math]::Round(((Get-Date) - $t0).TotalMinutes, 1)
        $bad = @(Incomplete-Runs $b.Results)
        Log ("END   {0} attempt {1}: exit {2}, {3} min, incomplete samples: {4}" -f $b.Name, $attempt, $code, $mins, $bad.Count)
        if ($code -eq 0 -and $bad.Count -eq 0) { break }
        if ($attempt -lt $MaxAttempts) {
            $keep = Join-Path $Out ("_incomplete\{0}_try{1}" -f $b.Name, $attempt)
            New-Item -ItemType Directory -Force $keep | Out-Null
            foreach ($d in $bad) { Move-Item $d.FullName (Join-Path $keep $d.Name) -Force }
            Log ("RETRY {0}: {1} incomplete sample(s) will be re-run (partial traces kept in {2})" -f $b.Name, $bad.Count, ($keep.Substring($Repo.Length + 1)))
        } else {
            Log ("GIVE UP {0} after {1} attempts: {2} sample(s) still incomplete: {3}" -f $b.Name, $MaxAttempts, $bad.Count, (($bad | ForEach-Object { $_.Name }) -join ', '))
        }
    }
}

foreach ($f in $Final) {
    if ($DryRun) { Write-Host ("[final] py {0}" -f ($f -join ' ')); continue }
    $t0 = Get-Date
    Log ("START py {0}" -f ($f -join ' '))
    & py @f 2>&1 | Out-File -FilePath (Join-Path $Out 'final.log') -Append -Encoding utf8
    Log ("END   py {0}: exit {1}, {2} min" -f ($f -join ' '), $LASTEXITCODE, [math]::Round(((Get-Date) - $t0).TotalMinutes, 1))
}
if ($DryRun) { Write-Host '=== DRY RUN complete: checks passed; nothing was executed ==='; exit 0 }
Log 'ALL DONE (see eval\v3\test\results.md)'
