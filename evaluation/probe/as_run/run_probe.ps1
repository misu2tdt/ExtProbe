<#
run_probe.ps1 -- the v3.1-probe trial (eval/v3_1_probe/CRITERIA.md), run ONCE on image extprobe-sandbox:v3.1-probe.
Windows PowerShell 5.1+. Exploratory: no primary result is replaced.

  powershell -ExecutionPolicy Bypass -File run_probe.ps1 -DryRun   # checks, counts, estimate; no sandbox
  powershell -ExecutionPolicy Bypass -File run_probe.ps1 -Trial    # pipeline test on 2 development packages
  powershell -ExecutionPolicy Bypass -File run_probe.ps1           # the trial: sets (a), (b), (c)

Package lists are built by eval/v3_1_probe/prepare_lists.py into ..\itw\probe\lists (outside the repository); traces go
to eval\v3_1_probe\traces_{a,b,c} (gitignored); log: eval\v3_1_probe\runner.log (gitignored). No id is printed.

Refuses to start unless ALL hold (every check is evaluated and logged; any failure aborts):
  - the current branch is probe-dev;
  - none of eval\v3_1_probe\traces_a, traces_b, traces_c exists (the trial runs once: an earlier or partial run is
    never resumed or overwritten; move it away by hand if it must be discarded);
  - the tag v3.0-freeze exists and is an ancestor of HEAD; every file/tree of FREEZE_v3.md has its recorded id at HEAD
    and at the tag (the frozen v3 configuration is untouched);
  - the working tree is clean (untracked outputs under eval\v3\dev, eval\v3\test and docs\AI_HANDOFF.md are ignored);
  - image extprobe-sandbox:v3 has the id of eval\v3\IMAGE.md and extprobe-sandbox:v3.1-probe the id of
    eval\v3_1_probe\IMAGE.md; the probe image holds the managed policy ProxyMode=direct (root-owned) at the path
    Chrome for Testing reads;
  - prepare_lists.py --official passes: id lists = SHA-256 of CRITERIA.md, no dossier sample, package SHA-256 = the
    committed manifests.
Within this one run, each set gets at most 3 attempts (samples left incomplete by a Docker failure are moved to
_incomplete and only they are re-run). The PC is kept awake.

-Trial: 2 development packages (1 malware, 1 benign, popup declared, not in the dossiers), traces in a temporary
folder deleted at the end; the working-tree check is a warning only; prints run statuses and counts only.
The branch check applies to every mode; the trace-folder check to -DryRun and the official run (not to -Trial).
#>
param([switch]$DryRun, [switch]$Trial)

$ErrorActionPreference = 'Continue'
$Repo = $PSScriptRoot
Set-Location $Repo
$Tag = 'v3.0-freeze'
$Out = Join-Path $Repo 'eval\v3_1_probe'
$Lists = Join-Path $Repo '..\itw\probe\lists'
$RunnerLog = Join-Path $Out 'runner.log'
$MaxAttempts = 3
$Workers = 2
$Timeout = 240
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONUNBUFFERED = '1'

if ($Trial) {
    $TrialDir = Join-Path $env:TEMP 'extprobe_probe_trial'
    $Sets = @(@{ Name = 'TRIAL'; List = (Join-Path $TrialDir 'list_trial.txt'); Results = (Join-Path $TrialDir 'traces') })
} else {
    $Sets = @(
        @{ Name = 'PROBE_a'; List = (Join-Path $Lists 'list_a.txt'); Results = 'eval\v3_1_probe\traces_a' },
        @{ Name = 'PROBE_b'; List = (Join-Path $Lists 'list_b.txt'); Results = 'eval\v3_1_probe\traces_b' },
        @{ Name = 'PROBE_c'; List = (Join-Path $Lists 'list_c.txt'); Results = 'eval\v3_1_probe\traces_c' }
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

function Recorded-Id([string]$file) {
    $line = Select-String -Path (Join-Path $Repo $file) -Pattern 'local image id' | Select-Object -First 1
    if (-not $line) { return $null }
    $m = [regex]::Match($line.Line, 'sha256:[0-9a-f]{64}')
    if ($m.Success) { return $m.Value } else { return $null }
}

function Path-Of($p) { if ([IO.Path]::IsPathRooted($p)) { return $p } else { return (Join-Path $Repo $p) } }

function Check-Inputs {
    $ok = $true
    $branch = (& git rev-parse --abbrev-ref HEAD | Out-String).Trim()
    if ($branch -eq 'probe-dev') { Log 'check: branch probe-dev' } else { Log "CHECK FAIL: current branch is '$branch', not probe-dev"; $ok = $false }
    if (-not $Trial) {
        $existing = @($Sets | Where-Object { Test-Path (Path-Of $_.Results) } | ForEach-Object { $_.Results })
        if ($existing.Count -eq 0) { Log 'check: no traces_a / traces_b / traces_c folder yet (the trial has not run)' }
        else { Log ("CHECK FAIL: trace folder(s) already exist: {0} -- the trial runs once; refusing" -f ($existing -join ', ')); $ok = $false }
    }
    $have = (& git tag --list $Tag | Out-String).Trim()
    if (-not $have) { Log "CHECK FAIL: tag $Tag does not exist"; $ok = $false }
    else {
        & git merge-base --is-ancestor $Tag HEAD 2>$null
        if ($LASTEXITCODE -eq 0) { Log "check: tag $Tag is an ancestor of HEAD" } else { Log "CHECK FAIL: tag $Tag is not an ancestor of HEAD"; $ok = $false }
    }
    $fz = Join-Path $Repo 'eval\v3\FREEZE_v3.md'
    $n = 0; $bad = 0
    foreach ($line in Get-Content $fz -Encoding utf8) {
        $m = [regex]::Match($line, '^\|\s*`([^`]+)`\s*\|\s*`([0-9a-f]{40})`\s*\|')
        if (-not $m.Success) { continue }
        $n++
        $p = $m.Groups[1].Value; $want = $m.Groups[2].Value
        $gotHead = (& git rev-parse "HEAD:$p" 2>$null | Out-String).Trim()
        $gotTag = (& git rev-parse "${Tag}:$p" 2>$null | Out-String).Trim()
        if ($gotHead -ne $want -or $gotTag -ne $want) { Log ("CHECK FAIL: {0}: HEAD {1}, tag {2}, FREEZE_v3.md {3}" -f $p, $gotHead, $gotTag, $want); $bad++ }
    }
    if ($n -gt 0 -and $bad -eq 0) { Log "check: $n frozen files/trees match FREEZE_v3.md at HEAD and at $Tag" } else { $ok = $false }
    $dirty = (& git status --porcelain | Out-String).Split("`n") |
        Where-Object { $_.Trim() -and $_ -notmatch '^\?\? eval/v3/(dev|test)/' -and $_ -notmatch '^\?\? docs/AI_HANDOFF\.md' }
    if ($dirty) {
        if ($Trial) { Log ("CHECK WARN (trial only): working tree not clean:`n" + ($dirty -join "`n")) }
        else { Log ("CHECK FAIL: working tree not clean:`n" + ($dirty -join "`n")); $ok = $false }
    } else { Log 'check: working tree clean' }
    $v = Docker-Version
    if (-not $v) {
        if ($DryRun) { Log 'CHECK FAIL: docker not reachable (a real run would wait for it)'; $ok = $false }
        else { Wait-Docker; $v = Docker-Version }
    }
    if ($v) {
        Log "check: docker engine $v"
        foreach ($pair in @(@('extprobe-sandbox:v3', 'eval\v3\IMAGE.md'), @('extprobe-sandbox:v3.1-probe', 'eval\v3_1_probe\IMAGE.md'))) {
            $want = Recorded-Id $pair[1]; $got = Image-Id $pair[0]
            if ($want -and $got -eq $want) { Log ("check: image {0} = {1} ({2})" -f $pair[0], $got, $pair[1]) }
            else { Log ("CHECK FAIL: image {0} is '{1}', {2} says '{3}'" -f $pair[0], $got, $pair[1], $want); $ok = $false }
        }
        $pol = (& docker run --rm --entrypoint stat extprobe-sandbox:v3.1-probe -c '%U %a' /etc/opt/chrome_for_testing/policies/managed/extprobe_proxy.json 2>$null | Out-String).Trim()
        $polText = (& docker run --rm --entrypoint cat extprobe-sandbox:v3.1-probe /etc/opt/chrome_for_testing/policies/managed/extprobe_proxy.json 2>$null | Out-String) -replace '\s', ''
        if ($pol -eq 'root 644' -and $polText -eq '{"ProxyMode":"direct"}') { Log 'check: probe image holds the managed policy ProxyMode=direct (root, 0644)' }
        else { Log ("CHECK FAIL: managed proxy policy in the probe image: '{0}' '{1}'" -f $pol, $polText); $ok = $false }
    }
    if ($Trial) {
        New-Item -ItemType Directory -Force $TrialDir | Out-Null
        $pl = & py eval\v3_1_probe\prepare_lists.py --dev-trial $TrialDir 2>&1 | Out-String
    } else {
        $pl = & py eval\v3_1_probe\prepare_lists.py --official $Lists 2>&1 | Out-String
    }
    $plOk = ($LASTEXITCODE -eq 0)
    foreach ($l in $pl.Trim().Split("`n")) { if ($l.Trim()) { Log $l.Trim() } }
    if (-not $plOk) { $ok = $false }
    return $ok
}

function Incomplete-Runs([string]$results) {
    $dir = Path-Of $results
    if (-not (Test-Path $dir)) { return @() }
    $bad = @()
    foreach ($d in Get-ChildItem $dir -Directory) {
        if ($d.Name -like '_*') { continue }
        $metaPath = Join-Path $d.FullName 'meta.json'
        if (-not (Test-Path $metaPath)) { continue }
        $m = Get-Content $metaPath -Raw -Encoding utf8 | ConvertFrom-Json
        $hasEvents = Test-Path (Join-Path $d.FullName 'output\events.json')
        if (-not $hasEvents -or $m.docker_exit -ne 0) { $bad += $d }
    }
    return $bad
}

# ---------------------------------------------------------------------------------------
if ($DryRun) { Write-Host '=== DRY RUN: checks and commands only; nothing is executed ===' }
elseif ($Trial) { Write-Host '=== TRIAL: 2 development packages, results deleted at the end ===' }
else {
    Add-Type -Namespace Win32 -Name Power -MemberDefinition '[DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint esFlags);'
    [void][Win32.Power]::SetThreadExecutionState([uint32]'0x80000001')
}
Log "=== run_probe.ps1 start (DryRun=$DryRun, Trial=$Trial, image extprobe-sandbox:v3.1-probe) ==="
if (-not (Check-Inputs)) { Log 'ABORT: input checks failed; nothing was run'; exit 1 }

$total = 0
foreach ($s in $Sets) { if (Test-Path $s.List) { $total += @(Get-Content $s.List | Where-Object { $_.Trim() }).Count } }
Log ("samples: {0} in {1} set(s); estimate about {2} min (2 workers, ~95 s per sample incl. the probe)" -f $total, $Sets.Count, [math]::Round($total * 95 / $Workers / 60, 0))

foreach ($s in $Sets) {
    $expected = @(Get-Content $s.List | Where-Object { $_.Trim() }).Count
    $args1 = @('eval\v3_1_probe\run_probe.py', '--list', $s.List, '--out', $s.Results, '--workers', "$Workers", '--timeout', "$Timeout", '--quiet')
    if ($DryRun) { Write-Host ("[{0}] py run_probe.py --list <{1} packages> --out {2}  (up to {3} attempts, once)" -f $s.Name, $expected, $s.Results, $MaxAttempts); continue }
    $log = Join-Path $Out ($s.Name + '.log')
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        Wait-Docker
        $t0 = Get-Date
        Log ("START {0} attempt {1}/{2} ({3} packages)" -f $s.Name, $attempt, $MaxAttempts, $expected)
        $outText = & py @args1 2>&1 | Out-String
        $code = $LASTEXITCODE
        if (-not $Trial) { Add-Content -Path $log -Value ("===== {0} attempt {1} {2} =====`n{3}" -f $s.Name, $attempt, (Get-Date -Format s), $outText) -Encoding utf8 }
        $mins = [math]::Round(((Get-Date) - $t0).TotalMinutes, 1)
        $bad = @(Incomplete-Runs $s.Results)
        Log ("END   {0} attempt {1}: exit {2}, {3} min, incomplete samples: {4}" -f $s.Name, $attempt, $code, $mins, $bad.Count)
        if ($code -eq 0 -and $bad.Count -eq 0) { break }
        if ($attempt -lt $MaxAttempts) {
            $keep = Join-Path (Path-Of $s.Results) ("_incomplete\try{0}" -f $attempt)
            New-Item -ItemType Directory -Force $keep | Out-Null
            foreach ($d in $bad) { Move-Item $d.FullName (Join-Path $keep $d.Name) -Force }
            Log ("RETRY {0}: {1} incomplete sample(s) will be re-run" -f $s.Name, $bad.Count)
        } else {
            Log ("GIVE UP {0} after {1} attempts: {2} sample(s) still incomplete" -f $s.Name, $MaxAttempts, $bad.Count)
        }
    }
}

if ($Trial) {
    $sum = & py eval\v3_1_probe\trial_summary.py $Sets[0].Results 2>&1 | Out-String
    foreach ($l in $sum.Trim().Split("`n")) { if ($l.Trim()) { Log $l.Trim() } }
    Remove-Item $TrialDir -Recurse -Force -ErrorAction SilentlyContinue
    Log 'trial traces and lists deleted'
    exit 0
}
if ($DryRun) { Write-Host '=== DRY RUN complete: checks passed; nothing was executed ==='; exit 0 }
Log 'START py eval\v3_1_probe\analysis.py'
& py eval\v3_1_probe\analysis.py 2>&1 | Out-File -FilePath (Join-Path $Out 'final.log') -Append -Encoding utf8
Log ("END   analysis: exit {0}" -f $LASTEXITCODE)
Log 'ALL DONE (see eval\v3_1_probe\results.md)'
