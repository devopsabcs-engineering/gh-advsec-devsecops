#Requires -Version 7.0
<#
.SYNOPSIS
    Pushes the current branch and, for gitlab.com remotes, auto-retries a pipeline that was
    killed by GitLab.com's compute-minutes quota gate at creation time.

.DESCRIPTION
    GitLab.com evaluates the namespace compute-minutes quota when a pipeline is CREATED (on a
    fresh push). When the namespace is over quota, the pipeline is marked 'failed' within ~1s
    with every job stuck in 'created' (started_at is null) - even when every job is tagged for a
    self-hosted runner fleet that does not consume shared minutes. Retrying the pipeline skips
    that creation-time gate, so the retry runs normally on the fleet.

    This wrapper performs a normal 'git push', then (only for gitlab.com remotes) waits for the
    resulting pipeline and, if it died at the creation gate, retries it automatically via glab.
    For non-gitlab.com remotes it just pushes and returns.

    Permanent fixes (GitLab-side, not automatable here): add compute minutes to the namespace,
    or wait for the monthly quota reset.

.PARAMETER Remote
    Git remote to push to. Defaults to 'origin'.

.PARAMETER RefSpec
    Optional branch or refspec to push (e.g. 'main'). Defaults to the current branch.

.PARAMETER WaitSeconds
    Seconds to wait between polls while the pipeline is being created. Defaults to 8.

.PARAMETER PollAttempts
    Number of polls to locate the created pipeline. Defaults to 6.

.EXAMPLE
    pwsh -File scripts/Push-Main.ps1
    Pushes the current branch and auto-retries a creation-gated GitLab pipeline.

.EXAMPLE
    git pushm
    Same, via the optional alias:  git config alias.pushm '!pwsh -File scripts/Push-Main.ps1'
#>
[CmdletBinding()]
param(
    [string]$Remote = 'origin',
    [string]$RefSpec,
    [int]$WaitSeconds = 8,
    [int]$PollAttempts = 6
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$pushArgs = @('push', $Remote)
if ($RefSpec) { $pushArgs += $RefSpec }
& git @pushArgs
if ($LASTEXITCODE -ne 0) { throw 'git push failed.' }

$remoteUrl = (& git remote get-url $Remote).Trim()
if ($remoteUrl -notmatch 'gitlab\.com') {
    Write-Host "Remote '$Remote' is not gitlab.com; no pipeline retry workaround needed."
    return
}

if (-not (Get-Command glab -ErrorAction SilentlyContinue)) {
    Write-Warning 'glab CLI not found; cannot auto-retry. If the pipeline died at creation, retry it manually.'
    return
}

$sha = (& git rev-parse HEAD).Trim()
$projectPath = ($remoteUrl -replace '^.*gitlab\.com[:/]', '') -replace '\.git$', ''
$projectEnc = [uri]::EscapeDataString($projectPath)

$pipeline = $null
for ($attempt = 1; $attempt -le $PollAttempts; $attempt++) {
    Start-Sleep -Seconds $WaitSeconds
    $pipes = @(glab api "projects/$projectEnc/pipelines?sha=$sha&per_page=1" | ConvertFrom-Json)
    if ($pipes.Count -gt 0) {
        $pipeline = $pipes[0]
        if ($pipeline.status -in @('failed', 'running', 'success', 'pending')) { break }
    }
}

if (-not $pipeline) {
    Write-Warning "No pipeline found for commit $sha after $($PollAttempts * $WaitSeconds)s. Check GitLab manually."
    return
}

if ($pipeline.status -ne 'failed') {
    Write-Host "Pipeline $($pipeline.id) status: $($pipeline.status). No creation-gate retry needed."
    return
}

# Distinguish a creation-time quota kill (all jobs still 'created') from a real job failure.
$jobs = @(glab api "projects/$projectEnc/pipelines/$($pipeline.id)/jobs?per_page=100" | ConvertFrom-Json)
$startedJobs = @($jobs | Where-Object { $_.status -ne 'created' })
if ($startedJobs.Count -gt 0) {
    Write-Warning "Pipeline $($pipeline.id) failed after jobs started - this is a real failure, not the creation gate. Inspect the jobs."
    return
}

Write-Host "Pipeline $($pipeline.id) died at the GitLab.com creation-time quota gate; retrying on the fleet..."
$retry = glab api --method POST "projects/$projectEnc/pipelines/$($pipeline.id)/retry" | ConvertFrom-Json
Write-Host "Retried pipeline $($retry.id) - status: $($retry.status)."
