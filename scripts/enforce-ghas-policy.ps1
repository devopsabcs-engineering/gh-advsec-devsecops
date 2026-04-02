<#
.SYNOPSIS
    Enforces GitHub Advanced Security features on all public repositories
    in an organization. Free for public repos.

.DESCRIPTION
    Enables the following GHAS features on every public repo in the org:
      - Dependency graph (on by default for public repos)
      - Dependabot alerts
      - Dependabot security updates
      - Secret scanning
      - Secret scanning push protection
      - Code scanning default setup (CodeQL)
      - Private vulnerability reporting

    Also configures org-level settings so new repos inherit these defaults.

.PARAMETER Org
    The GitHub organization name (e.g. devopsabcs-engineering).

.PARAMETER DryRun
    If set, prints what would be changed without making API calls.

.PARAMETER SkipOrgDefaults
    If set, skips updating organization-level default settings.

.EXAMPLE
    .\enforce-ghas-policy.ps1 -Org devopsabcs-engineering
    .\enforce-ghas-policy.ps1 -Org devopsabcs-engineering -DryRun
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Org,

    [switch]$DryRun,

    [switch]$SkipOrgDefaults
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------- helpers ----------
function Write-Status {
    param([string]$Repo, [string]$Feature, [string]$Result)
    $icon = switch ($Result) {
        'enabled'  { '[+]' }
        'skipped'  { '[~]' }
        'failed'   { '[!]' }
        'dry-run'  { '[?]' }
        default    { '[ ]' }
    }
    Write-Host "  $icon $Feature : $Result" -ForegroundColor $(
        switch ($Result) { 'enabled' { 'Green' } 'failed' { 'Red' } 'skipped' { 'Yellow' } default { 'Cyan' } }
    )
}

function Invoke-GhApi {
    param(
        [string]$Method,
        [string]$Endpoint,
        [string]$Body
    )
    $apiArgs = @('api', '-X', $Method, $Endpoint, '--silent')
    if ($Body) {
        $apiArgs += @('--input', '-')
        $result = $Body | & gh @apiArgs 2>&1
    }
    else {
        $result = & gh @apiArgs 2>&1
    }

    $exitCode = if (Test-Path variable:global:LASTEXITCODE) { $global:LASTEXITCODE } else { 0 }
    if ($exitCode -ne 0) {
        return @{ success = $false; output = ($result -join "`n") }
    }
    return @{ success = $true; output = ($result -join "`n") }
}

# ---------- pre-flight ----------
try {
    $ghVersionOutput = & gh --version 2>&1
    $ghVersion = ($ghVersionOutput | Select-Object -First 1)
}
catch {
    Write-Error 'GitHub CLI (gh) is not installed or not on PATH.'
}
if (-not $ghVersion) {
    Write-Error 'GitHub CLI (gh) is not installed or not on PATH.'
}
Write-Host "Using $ghVersion"
Write-Host "Organization: $Org"
if ($DryRun) { Write-Host '*** DRY RUN — no changes will be made ***' -ForegroundColor Cyan }
Write-Host ''

# ---------- 1. Org-level defaults for new repos ----------
if (-not $SkipOrgDefaults) {
    Write-Host '=== Configuring organization-level defaults ===' -ForegroundColor White
    $orgBody = @{
        dependabot_alerts_enabled_for_new_repositories                 = $true
        dependabot_security_updates_enabled_for_new_repositories       = $true
        dependency_graph_enabled_for_new_repositories                  = $true
        secret_scanning_enabled_for_new_repositories                   = $true
        secret_scanning_push_protection_enabled_for_new_repositories   = $true
    } | ConvertTo-Json -Compress

    if ($DryRun) {
        Write-Host '  [?] Would set org defaults: dependabot alerts, dependabot security updates, dependency graph, secret scanning, push protection' -ForegroundColor Cyan
    }
    else {
        $r = Invoke-GhApi -Method 'PATCH' -Endpoint "/orgs/$Org" -Body $orgBody
        if ($r.success) {
            Write-Host '  [+] Org defaults configured for new repositories.' -ForegroundColor Green
        }
        else {
            Write-Host "  [!] Failed to set org defaults: $($r.output)" -ForegroundColor Red
        }
    }
    Write-Host ''
}

# ---------- 2. Discover public repos ----------
Write-Host '=== Discovering public repositories ===' -ForegroundColor White
$reposJson = & gh api "/orgs/$Org/repos" --paginate -q '[ .[] | select(.visibility == "public") | { name: .name, full_name: .full_name, archived: .archived, fork: .fork } ]' 2>&1
$exitCode = if (Test-Path variable:global:LASTEXITCODE) { $global:LASTEXITCODE } else { 1 }
if ($exitCode -ne 0) {
    Write-Error "Failed to list repos: $reposJson"
}
$repos = $reposJson | ConvertFrom-Json
Write-Host "  Found $($repos.Count) public repo(s).`n"

# ---------- 3. Per-repo enforcement ----------
$summary = @{ enabled = 0; skipped = 0; failed = 0 }

foreach ($repo in $repos) {
    $fullName = $repo.full_name
    $repoName = $repo.name

    if ($repo.archived) {
        Write-Host "--- $fullName (ARCHIVED — skipping) ---" -ForegroundColor DarkGray
        $summary.skipped++
        continue
    }

    Write-Host "--- $fullName ---" -ForegroundColor White

    # 3a. Dependabot alerts
    if ($DryRun) {
        Write-Status $repoName 'Dependabot alerts' 'dry-run'
    }
    else {
        $r = Invoke-GhApi -Method 'PUT' -Endpoint "/repos/$fullName/vulnerability-alerts"
        Write-Status $repoName 'Dependabot alerts' $(if ($r.success) { 'enabled' } else { 'failed' })
        if (-not $r.success) { $summary.failed++ }
    }

    # 3b. Dependabot security updates
    if ($DryRun) {
        Write-Status $repoName 'Dependabot security updates' 'dry-run'
    }
    else {
        $r = Invoke-GhApi -Method 'PUT' -Endpoint "/repos/$fullName/automated-security-fixes"
        Write-Status $repoName 'Dependabot security updates' $(if ($r.success) { 'enabled' } else { 'failed' })
        if (-not $r.success) { $summary.failed++ }
    }

    # 3c. Secret scanning + push protection
    $secBody = @{
        security_and_analysis = @{
            secret_scanning                 = @{ status = 'enabled' }
            secret_scanning_push_protection = @{ status = 'enabled' }
        }
    } | ConvertTo-Json -Depth 4 -Compress

    if ($DryRun) {
        Write-Status $repoName 'Secret scanning + push protection' 'dry-run'
    }
    else {
        $r = Invoke-GhApi -Method 'PATCH' -Endpoint "/repos/$fullName" -Body $secBody
        Write-Status $repoName 'Secret scanning + push protection' $(if ($r.success) { 'enabled' } else { 'failed' })
        if (-not $r.success) { $summary.failed++ }
    }

    # 3d. Code scanning default setup (CodeQL)
    $csBody = @{
        state = 'configured'
    } | ConvertTo-Json -Compress

    if ($DryRun) {
        Write-Status $repoName 'Code scanning default setup (CodeQL)' 'dry-run'
    }
    else {
        $r = Invoke-GhApi -Method 'PATCH' -Endpoint "/repos/$fullName/code-scanning/default-setup" -Body $csBody
        if ($r.success) {
            Write-Status $repoName 'Code scanning default setup (CodeQL)' 'enabled'
        }
        else {
            # Code scanning may fail for repos with no supported languages
            Write-Status $repoName 'Code scanning default setup (CodeQL)' 'skipped'
            Write-Host "    Reason: $($r.output)" -ForegroundColor DarkGray
        }
    }

    # 3e. Private vulnerability reporting
    if ($DryRun) {
        Write-Status $repoName 'Private vulnerability reporting' 'dry-run'
    }
    else {
        $r = Invoke-GhApi -Method 'PUT' -Endpoint "/repos/$fullName/private-vulnerability-reporting"
        Write-Status $repoName 'Private vulnerability reporting' $(if ($r.success) { 'enabled' } else { 'failed' })
        if (-not $r.success) { $summary.failed++ }
    }

    if (-not $DryRun) { $summary.enabled++ }
    Write-Host ''
}

# ---------- 4. Summary ----------
Write-Host '=== Summary ===' -ForegroundColor White
Write-Host "  Repos processed : $($summary.enabled)"
Write-Host "  Repos skipped   : $($summary.skipped)"
Write-Host "  Feature failures: $($summary.failed)"
if ($summary.failed -gt 0) {
    Write-Host '  Review failures above. Common causes: insufficient permissions, repo has no supported languages for CodeQL.' -ForegroundColor Yellow
}
Write-Host 'Done.' -ForegroundColor Green
