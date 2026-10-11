<#
run_v3_dev.ps1 -- v3 dev run on the 610 samples (eval/v3/DESIGN_v3.md, eval/v3/SCORING_v3.md).
Windows PowerShell 5.1+.

  powershell -ExecutionPolicy Bypass -File run_v3_dev.ps1           # run everything
  powershell -ExecutionPolicy Bypass -File run_v3_dev.ps1 -DryRun   # checks, counts, estimate; no sandbox

One profile (v3, image extprobe-sandbox:v3), one run per sample, 610 samples in 4 folders,
2 workers (eval/v3/run_v3.py): the canary and malicious (samples\malware), then the benign
folders (samples\benign, ..\sample\cws_benign_crx, samples\benign_ext). Traces:
eval\v3\dev\traces. Then eval/v3/dev_analysis.py scores them with eval/v3/score_v3.py (the
rules committed in SCORING_v3.md) -> eval\v3\dev\results.md (format of eval\expanded\results.md,
plus a comparison with the v2 run).
Log (appended): eval\v3\dev\runner.log; batch output: eval\v3\dev\<batch>.log.

Refuses to start unless:
  - the current branch is v3-dev and the working tree is clean;
  - HEAD descends from tag v2.0-freeze without changing any frozen v2 path (v2 reproducible);
  - the image extprobe-sandbox:v3 has the id recorded in eval\v3\IMAGE.md;
  - eval/verify_samples.py --extra --benign-ext passes (313 + 30 + 11 + 256, checksums);
  - the sample counts are 313 / 30 / 11 / 256.
Before every batch attempt it waits (60 s steps, logged, never exits) until Docker answers.
Each batch runs at most 3 times; run_v3.py skips samples already done, and samples left
incomplete by a Docker failure (no trace, docker exit != 0, or no run status) are moved to
eval\v3\dev\_incomplete\ before the next attempt so they are re-run. The PC is kept awake.
No absolute path or IP address is written to the log.
#>
param([switch]$DryRun)

$ErrorActionPreference = 'Continue'
$Repo = $PSScriptRoot
Set-Location $Repo
$Branch = 'v3-dev'
$Tag = 'v2.0-freeze'
$Image = 'extprobe-sandbox:v3'
$Out = Join-Path $Repo 'eval\v3\dev'
$Traces = 'eval\v3\dev\traces'
$RunnerLog = Join-Path $Out 'runner.log'
$MaxAttempts = 3
$Workers = 2
$Frozen = @('worker', 'sandbox', 'eval/batch_run.py', 'eval/rescore.py',
            'eval/apply_verified_labels.py', 'eval/save_metrics.py', 'pytest.ini')
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONUNBUFFERED = '1'

$Groups = @(
    @{ Dir = 'samples\malware';          N = 313 },
    @{ Dir = 'samples\benign';           N = 30 },
    @{ Dir = '..\sample\cws_benign_crx'; N = 11 },
    @{ Dir = 'samples\benign_ext';       N = 256 }
)
$Batches = @(
    @{ Name = 'V3_malicious'; Label = 'malicious'; Canary = $true;  Samples = @('samples\malware') },
    @{ Name = 'V3_benign';    Label = 'benign';    Canary = $false
       Samples = @('samples\benign', '..\sample\cws_benign_crx', 'samples\benign_ext') }
)
$Final = @(
    ,@('eval\v3\dev_analysis.py', '--traces', $Traces, '--out', 'eval\v3\dev\results.md')
)

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

function Recorded-V3-Image-Id {
    $line = Select-String -Path (Join-Path $Repo 'eval\v3\IMAGE.md') -Pattern 'local image id' | Select-Object -First 1
    if (-not $line) { return $null }
    $m = [regex]::Match($line.Line, 'sha256:[0-9a-f]{64}')
    if ($m.Success) { return $m.Value } else { return $null }
}

function Count-Crx([string]$dir) {
    $p = Join-Path $Repo $dir
    if (-not (Test-Path $p)) { return 0 }
    return @(Get-ChildItem $p -Filter *.crx -File).Count
}

function Estimate-Minutes {
    # mean duration of the v3 smoke runs on the same image profile, divided by the workers
    $durs = @()
    foreach ($b in 'eval\v3\runs\smoke2', 'eval\v3\runs\smoke3') {
        $p = Join-Path $Repo $b
        if (-not (Test-Path $p)) { continue }
        foreach ($d in Get-ChildItem $p -Directory) {
            $mp = Join-Path $d.FullName 'meta.json'
            if (Test-Path $mp) {
                $m = Get-Content $mp -Raw -Encoding utf8 | ConvertFrom-Json
                if ($m.duration_s) { $durs += [double]$m.duration_s }
            }
        }
    }
    if ($durs.Count -eq 0) { return $null }
    $mean = ($durs | Measure-Object -Average).Average
    $total = ($Groups | ForEach-Object { $_.N } | Measure-Object -Sum).Sum + 1
    return @{ Mean = [math]::Round($mean, 1); Samples = $durs.Count; Minutes = [math]::Round($total * $mean / $Workers / 60, 0) }
}

function Check-Inputs {
    $ok = $true
    $br = (& git rev-parse --abbrev-ref HEAD | Out-String).Trim()
    if ($br -eq $Branch) { Log "check: branch $br" } else { Log "CHECK FAIL: branch is '$br', expected $Branch"; $ok = $false }
    $dirty = (& git status --porcelain | Out-String).Trim()
    if ($dirty) { Log "CHECK FAIL: working tree not clean:`n$dirty"; $ok = $false } else { Log 'check: working tree clean' }
    & git merge-base --is-ancestor $Tag HEAD 2>$null
    $isDesc = ($LASTEXITCODE -eq 0)
    & git diff --quiet $Tag HEAD -- $Frozen
    $same = ($LASTEXITCODE -eq 0)
    $head = (& git rev-parse --short HEAD | Out-String).Trim()
    if ($isDesc -and $same) { Log "check: HEAD $head descends from $Tag with no change to frozen v2 paths" }
    else { Log "CHECK FAIL: HEAD $head (descendant of ${Tag}=$isDesc, frozen paths unchanged=$same)"; $ok = $false }
    $v = Docker-Version
    if (-not $v) {
        if ($DryRun) { Log 'CHECK FAIL: docker not reachable (a real run would wait for it)'; $ok = $false }
        else { Wait-Docker; $v = Docker-Version }
    }
    if ($v) {
        Log "check: docker engine $v"
        $want = Recorded-V3-Image-Id
        $got = (& docker image inspect $Image --format '{{.Id}}' 2>$null | Out-String).Trim()
        if ($want -and $got -eq $want) { Log "check: image $Image = $got (eval/v3/IMAGE.md)" }
        else { Log "CHECK FAIL: image $Image is '$got', eval/v3/IMAGE.md says '$want'"; $ok = $false }
    }
    $vs = & py eval\verify_samples.py --extra --benign-ext 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { Log 'check: samples verified (--extra --benign-ext, checksums OK)' }
    else { Log "CHECK FAIL: eval/verify_samples.py --extra --benign-ext`n$vs"; $ok = $false }
    foreach ($g in $Groups) {
        $n = Count-Crx $g.Dir
        if ($n -eq $g.N) { Log ("check: {0,-28} {1} .crx" -f $g.Dir, $n) }
        else { Log ("CHECK FAIL: {0} has {1} .crx, expected {2}" -f $g.Dir, $n, $g.N); $ok = $false }
    }
    return $ok
}

function Incomplete-Runs([string]$label) {
    $dir = Join-Path $Repo $Traces
    if (-not (Test-Path $dir)) { return @() }
    $bad = @()
    foreach ($d in Get-ChildItem $dir -Directory) {
        $metaPath = Join-Path $d.FullName 'meta.json'
        if (-not (Test-Path $metaPath)) { continue }
        $m = Get-Content $metaPath -Raw -Encoding utf8 | ConvertFrom-Json
        if ($m.label -ne $label -and -not ($label -eq 'malicious' -and $d.Name -eq 'canary')) { continue }
        $hasEvents = Test-Path (Join-Path $d.FullName 'output\events.json')
        if (-not $hasEvents -or $m.docker_exit -ne 0 -or @('unknown', 'unreadable_events') -contains $m.run_status) {
            $bad += $d
        }
    }
    return $bad
}

function Batch-Args($b) {
    $a = @('eval\v3\run_v3.py', '--out', $Traces, '--workers', "$Workers", '--label', $b.Label, '--samples') + $b.Samples
    if ($b.Canary) { $a += '--canary' }
    return $a
}

# ---------------------------------------------------------------------------------------
if ($DryRun) { Write-Host '=== DRY RUN: checks and commands only; nothing is executed ===' }
else {
    New-Item -ItemType Directory -Force $Out | Out-Null
    Add-Type -Namespace Win32 -Name Power -MemberDefinition '[DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint esFlags);'
    [void][Win32.Power]::SetThreadExecutionState([uint32]'0x80000001')
}
Log "=== run_v3_dev.ps1 start (DryRun=$DryRun) ==="
if (-not (Check-Inputs)) { Log 'ABORT: input checks failed; nothing was run'; exit 1 }

$total = ($Groups | ForEach-Object { $_.N } | Measure-Object -Sum).Sum
Log ("samples: {0} = {1} (+ canary)" -f $total, (($Groups | ForEach-Object { $_.N }) -join ' + '))
$est = Estimate-Minutes
if ($est) {
    Log ("estimate: {0} runs x {1} s (mean of {2} v3 smoke runs) / {3} workers = about {4} min ({5:N1} h); retries and slow samples add to it" -f ($total + 1), $est.Mean, $est.Samples, $Workers, $est.Minutes, ($est.Minutes / 60))
} else { Log 'estimate: no v3 smoke runs to estimate from' }

foreach ($b in $Batches) {
    $args_ = Batch-Args $b
    $log = Join-Path $Out ($b.Name + '.log')
    if ($DryRun) { Write-Host ("[{0}] py {1}  >> eval\v3\dev\{0}.log  (up to {2} attempts)" -f $b.Name, ($args_ -join ' '), $MaxAttempts); continue }
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        Wait-Docker
        $t0 = Get-Date
        Log ("START {0} attempt {1}/{2}: py {3}" -f $b.Name, $attempt, $MaxAttempts, ($args_ -join ' '))
        Add-Content -Path $log -Value ("===== {0} attempt {1} {2} =====" -f $b.Name, $attempt, (Get-Date -Format s)) -Encoding utf8
        & py @args_ 2>&1 | Out-File -FilePath $log -Append -Encoding utf8
        $code = $LASTEXITCODE
        $mins = [math]::Round(((Get-Date) - $t0).TotalMinutes, 1)
        $bad = @(Incomplete-Runs $b.Label)
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
Log 'ALL DONE (see eval\v3\dev\results.md)'
