<#
run_itw.ps1 -- the in-the-wild sets A (Sentry-recent) and B (CWS-random), run ONCE each on the frozen v3 configuration
(eval/v3/FREEZE_v3.md, eval/v3/in_the_wild/CRITERIA.md incl. amendment 1). Windows PowerShell 5.1+.
Profile v3 ONLY (no v2). Run it from anywhere:

  powershell -ExecutionPolicy Bypass -File eval\v3\in_the_wild\run_itw.ps1 -DryRun   # checks, counts, estimate; no sandbox
  powershell -ExecutionPolicy Bypass -File eval\v3\in_the_wild\run_itw.ps1           # A, then B
  powershell -ExecutionPolicy Bypass -File eval\v3\in_the_wild\run_itw.ps1 -Trial    # pipeline test, see below

Packages live OUTSIDE the repository, in the folder `itw` next to it (..\itw\A, ..\itw\B); traces go to
eval\v3\in_the_wild\traces_A and traces_B (gitignored). Log (appended): eval\v3\in_the_wild\runner.log.

Refuses to start unless ALL hold (every check is evaluated and logged; any failure aborts):
  - the tag v3.0-freeze exists and is an ancestor of HEAD;
  - the working tree is clean (untracked outputs under eval\v3\dev, eval\v3\test and docs\AI_HANDOFF.md are ignored);
  - every file/tree listed in FREEZE_v3.md has the id recorded there at HEAD AND at the tag;
  - image extprobe-sandbox:v3 has the id recorded in eval\v3\IMAGE.md;
  - eval/verify_samples.py --itw ..\itw passes (SHA-256 of every .crx = docs\samples_manifest_itw_{A,B}.csv, MV3);
  - for each set, at its start, no sample is older than 24 h since its recorded download time (CRITERIA section 2).
Each set runs at most 3 attempts (runners skip samples with a trace; samples left incomplete by a Docker failure are
moved to ..._incomplete before the next attempt). A finished set (every sample has a trace) is not run again.
The PC is kept awake. No absolute path or IP address is written to the log.

-Trial: pipeline test on 2 SPARE packages per set (never part of A or B) in ..\itw\_trial\A and \B, traces in
..\itw\_trial_out, both deleted at the end. The working-tree check is only a warning and the 24 h rule is skipped; the
official run never uses this mode. Only exit codes and run statuses are printed.
#>
param([switch]$DryRun, [switch]$Trial)

$ErrorActionPreference = 'Continue'
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
Set-Location $Repo
$Tag = 'v3.0-freeze'
$Itw = Join-Path $Repo '..\itw'
$Out = Join-Path $Repo 'eval\v3\in_the_wild'
$RunnerLog = Join-Path $Out 'runner.log'
$MaxAttempts = 3
$Workers = 2
$MaxAgeHours = 24
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONUNBUFFERED = '1'

if ($Trial) {
    $Sets = @(
        @{ Name = 'TRIAL_A'; Dir = '..\itw\_trial\A'; Results = '..\itw\_trial_out\A'; Manifest = $null },
        @{ Name = 'TRIAL_B'; Dir = '..\itw\_trial\B'; Results = '..\itw\_trial_out\B'; Manifest = $null }
    )
} else {
    $Sets = @(
        @{ Name = 'ITW_A'; Dir = '..\itw\A'; Results = 'eval\v3\in_the_wild\traces_A'; Manifest = 'docs\samples_manifest_itw_A.csv' },
        @{ Name = 'ITW_B'; Dir = '..\itw\B'; Results = 'eval\v3\in_the_wild\traces_B'; Manifest = 'docs\samples_manifest_itw_B.csv' }
    )
}

function Log([string]$msg) {
    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
    Write-Host $line
    if (-not $DryRun -and -not $Trial) { Add-Content -Path $RunnerLog -Value $line -Encoding utf8 }
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
    $have = (& git tag --list $Tag | Out-String).Trim()
    if (-not $have) { Log "CHECK FAIL: tag $Tag does not exist"; $ok = $false }
    else {
        & git merge-base --is-ancestor $Tag HEAD 2>$null
        if ($LASTEXITCODE -eq 0) { Log "check: tag $Tag is an ancestor of HEAD" }
        else { Log "CHECK FAIL: tag $Tag is not an ancestor of HEAD"; $ok = $false }
    }
    $dirty = (& git status --porcelain | Out-String).Split("`n") |
        Where-Object { $_.Trim() -and $_ -notmatch '^\?\? eval/v3/(dev|test)/' -and $_ -notmatch '^\?\? docs/AI_HANDOFF\.md' }
    if ($dirty) {
        if ($Trial) { Log ("CHECK WARN (trial only): working tree not clean:`n" + ($dirty -join "`n")) }
        else { Log ("CHECK FAIL: working tree not clean:`n" + ($dirty -join "`n")); $ok = $false }
    } else { Log 'check: working tree clean' }
    $fz = Join-Path $Repo 'eval\v3\FREEZE_v3.md'
    if (-not (Test-Path $fz)) { Log 'CHECK FAIL: eval/v3/FREEZE_v3.md missing'; $ok = $false }
    else {
        $n = 0; $bad = 0
        foreach ($line in Get-Content $fz -Encoding utf8) {
            $m = [regex]::Match($line, '^\|\s*`([^`]+)`\s*\|\s*`([0-9a-f]{40})`\s*\|')
            if (-not $m.Success) { continue }
            $n++
            $p = $m.Groups[1].Value
            $want = $m.Groups[2].Value
            $gotHead = (& git rev-parse "HEAD:$p" 2>$null | Out-String).Trim()
            $gotTag = (& git rev-parse "${Tag}:$p" 2>$null | Out-String).Trim()
            if ($gotHead -ne $want -or $gotTag -ne $want) {
                Log ("CHECK FAIL: {0}: HEAD {1}, tag {2}, FREEZE_v3.md {3}" -f $p, $gotHead, $gotTag, $want); $bad++
            }
        }
        if ($n -eq 0) { Log 'CHECK FAIL: FREEZE_v3.md lists no file ids'; $ok = $false }
        elseif ($bad -eq 0) { Log "check: $n frozen files/trees match FREEZE_v3.md at HEAD and at $Tag" }
        else { $ok = $false }
    }
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
    }
    if ($Trial) {
        foreach ($s in $Sets) {
            $c = Count-Crx $s.Dir
            if ($c -eq 2) { Log ("check: {0} has 2 spare .crx" -f $s.Dir) } else { Log ("CHECK FAIL: {0} has {1} .crx, expected 2 spare" -f $s.Dir, $c); $ok = $false }
        }
    } else {
        $vs = & py eval\verify_samples.py --itw ..\itw 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) { Log 'check: samples verified (--itw: A and B, checksums and MV3 OK)' }
        else { Log "CHECK FAIL: eval/verify_samples.py --itw`n$vs"; $ok = $false }
        foreach ($s in $Sets) {
            $mp = Join-Path $Repo $s.Manifest
            if (-not (Test-Path $mp)) { Log ("CHECK FAIL: {0} missing" -f $s.Manifest); $ok = $false; continue }
            $n = @(Import-Csv $mp -Encoding UTF8).Count
            $c = Count-Crx $s.Dir
            if ($n -gt 0 -and $c -eq $n) { Log ("check: {0} {1} .crx (= manifest rows)" -f $s.Dir, $c) }
            else { Log ("CHECK FAIL: {0} has {1} .crx, manifest has {2}" -f $s.Dir, $c, $n); $ok = $false }
        }
    }
    return $ok
}

function Age-Ok($s) {
    # CRITERIA section 2: run within 24 h of the download. Checked at the start of each set (oldest sample).
    if ($Trial) { return $true }
    $rows = @(Import-Csv (Join-Path $Repo $s.Manifest) -Encoding UTF8)
    $oldest = ($rows | ForEach-Object { [datetime]::Parse($_.downloaded_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal) } | Measure-Object -Minimum).Minimum
    $age = ((Get-Date).ToUniversalTime() - $oldest).TotalHours
    if ($age -le $MaxAgeHours) { Log ("check: {0} oldest download {1:N1} h ago (limit {2} h)" -f $s.Name, $age, $MaxAgeHours); return $true }
    Log ("CHECK FAIL: {0} oldest download {1:N1} h ago, limit {2} h (CRITERIA section 2); nothing was run for this set" -f $s.Name, $age, $MaxAgeHours)
    return $false
}

function Incomplete-Runs([string]$results) {
    $dir = Join-Path $Repo $results
    if (-not (Test-Path $dir)) { return @() }
    $bad = @()
    foreach ($d in Get-ChildItem $dir -Directory) {
        if ($d.Name -like '_*') { continue }
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
    return @(Get-ChildItem $dir -Directory | Where-Object { $_.Name -notlike '_*' -and (Test-Path (Join-Path $_.FullName 'output\events.json')) }).Count
}

# ---------------------------------------------------------------------------------------
if ($DryRun) { Write-Host '=== DRY RUN: checks and commands only; nothing is executed ===' }
elseif ($Trial) { Write-Host '=== TRIAL: 2 spare packages per set, results deleted at the end ===' }
else {
    New-Item -ItemType Directory -Force $Out | Out-Null
    Add-Type -Namespace Win32 -Name Power -MemberDefinition '[DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint esFlags);'
    [void][Win32.Power]::SetThreadExecutionState([uint32]'0x80000001')
}
Log "=== run_itw.ps1 start (DryRun=$DryRun, Trial=$Trial, profile v3 only) ==="
if (-not (Check-Inputs)) { Log 'ABORT: input checks failed; nothing was run'; exit 1 }

$total = 0
foreach ($s in $Sets) { $total += (Count-Crx $s.Dir) }
Log ("samples: {0} extensions in {1} set(s)" -f $total, $Sets.Count)
$e3 = Mean-Duration @('eval\v3\dev\traces')
if ($e3) {
    $m3 = [math]::Round($total * $e3.Mean / $Workers / 60, 0)
    Log ("estimate: v3 {0} x {1} s (mean of {2} dev traces) / {3} workers = about {4} min ({5:N1} h)" -f $total, $e3.Mean, $e3.N, $Workers, $m3, ($m3 / 60))
} else { Log 'estimate: no earlier traces to estimate from' }

$allOk = $true
foreach ($s in $Sets) {
    $expected = Count-Crx $s.Dir
    $args3 = @('eval\v3\run_v3.py', '--out', $s.Results, '--workers', "$Workers", '--samples', $s.Dir)
    if ($DryRun) { Write-Host ("[{0}] py {1}  (up to {2} attempts, once)" -f $s.Name, ($args3 -join ' '), $MaxAttempts); continue }
    if (-not (Age-Ok $s)) { $allOk = $false; break }
    if ((Done-Count $s.Results) -ge $expected) { Log ("SKIP {0}: all {1} samples already have a trace" -f $s.Name, $expected); continue }
    $log = Join-Path $Out ($s.Name + '.log')
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        Wait-Docker
        $t0 = Get-Date
        Log ("START {0} attempt {1}/{2}" -f $s.Name, $attempt, $MaxAttempts)
        if (-not $Trial) { Add-Content -Path $log -Value ("===== {0} attempt {1} {2} =====" -f $s.Name, $attempt, (Get-Date -Format s)) -Encoding utf8 }
        $outText = & py @args3 2>&1 | Out-String
        $code = $LASTEXITCODE
        if (-not $Trial) { Add-Content -Path $log -Value $outText -Encoding utf8 }
        $mins = [math]::Round(((Get-Date) - $t0).TotalMinutes, 1)
        $bad = @(Incomplete-Runs $s.Results)
        Log ("END   {0} attempt {1}: exit {2}, {3} min, incomplete samples: {4}" -f $s.Name, $attempt, $code, $mins, $bad.Count)
        if ($code -eq 0 -and $bad.Count -eq 0) { break }
        if ($attempt -lt $MaxAttempts) {
            $keep = Join-Path (Join-Path $Repo $s.Results) ("_incomplete\try{0}" -f $attempt)
            New-Item -ItemType Directory -Force $keep | Out-Null
            foreach ($d in $bad) { Move-Item $d.FullName (Join-Path $keep $d.Name) -Force }
            Log ("RETRY {0}: {1} incomplete sample(s) will be re-run" -f $s.Name, $bad.Count)
        } else {
            Log ("GIVE UP {0} after {1} attempts: {2} sample(s) still incomplete: {3}" -f $s.Name, $MaxAttempts, $bad.Count, (($bad | ForEach-Object { $_.Name }) -join ', '))
        }
    }
    if ($Trial) {
        foreach ($d in Get-ChildItem (Join-Path $Repo $s.Results) -Directory | Where-Object { $_.Name -notlike '_*' }) {
            $m = Get-Content (Join-Path $d.FullName 'meta.json') -Raw -Encoding utf8 | ConvertFrom-Json
            Log ("trial {0}: docker_exit={1} run_status={2} duration={3}s" -f $s.Name, $m.docker_exit, $m.run_status, $m.duration_s)
        }
    }
}
if ($Trial) {
    Remove-Item (Join-Path $Repo '..\itw\_trial_out') -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $Repo '..\itw\_trial') -Recurse -Force -ErrorAction SilentlyContinue
    Log 'trial results and spare packages deleted'
    exit 0
}
if ($DryRun) { Write-Host '=== DRY RUN complete: checks passed; nothing was executed ==='; exit 0 }
if (-not $allOk) { Log 'ABORT: a set was not run (see above)'; exit 1 }
Log 'ALL DONE (traces in eval\v3\in_the_wild\traces_A and traces_B; analysis is a separate step)'
