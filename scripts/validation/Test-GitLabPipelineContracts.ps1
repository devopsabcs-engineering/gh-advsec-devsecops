[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$rootPipeline = Join-Path $RepositoryRoot '.gitlab-ci.yml'
$moduleRoot = Join-Path $RepositoryRoot '.gitlab\ci'
$expectedModules = @('common.yml', 'build.yml', 'security.yml', 'supply-chain.yml', 'deploy.yml', 'governance.yml')
$expectedSources = @(
    'ci.yml',
    'cicd.yml',
    'CIS-Anchore-Grype.yml',
    'CIS-Trivy-AquaSecurity.yml',
    'DAST-ZAP-Zed-Attach-Proxy-Checkmarx.yml',
    'enforce-ghas-policy.yml',
    'IACS-AquaSecurity-tfsec.yml',
    'IACS-Checkmarx-kics.yml',
    'IACS-Microsoft-Security-DevOps.yml',
    'MSDO-Microsoft-Security-DevOps.yml',
    'SAST-ESLint.yml',
    'SAST-GitHubAdvancedSecurity-CodeQL.yml',
    'SAST-Kubesec.yml',
    'SCA-Anchore-Syft-SBOM.yml',
    'SCA-GitHubAdvancedSecurity-DependencyReview.yml',
    'SCA-Microsoft-SBOM.yml',
    'SCA-OpenSSF-Scorecard.yml',
    'security-agent-workflow.yml',
    'static.yml'
)
$scheduleProfiles = @(
    'daily-governance',
    'openssf-scorecard',
    'sast-codeql',
    'sast-eslint',
    'sast-kubesec',
    'weekly-container-dast',
    'weekly-iac',
    'weekly-msdo'
)
$errors = [System.Collections.Generic.List[string]]::new()

if (-not (Test-Path -LiteralPath $rootPipeline -PathType Leaf)) {
    $errors.Add('Root .gitlab-ci.yml is missing.')
}

$moduleContent = [System.Collections.Generic.List[string]]::new()
foreach ($module in $expectedModules) {
    $modulePath = Join-Path $moduleRoot $module
    if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
        $errors.Add("Required GitLab CI module is missing: $module")
        continue
    }
    $content = Get-Content -LiteralPath $modulePath -Raw
    $moduleContent.Add($content)
    if ($module -ne 'common.yml' -and (Get-Content -LiteralPath $rootPipeline -Raw) -notmatch [regex]::Escape(".gitlab/ci/$module")) {
        $errors.Add("Root pipeline does not include module: $module")
    }
}

$combinedContent = $moduleContent -join [Environment]::NewLine
foreach ($source in $expectedSources) {
    $marker = [regex]::Escape("Source parity: .github/workflows/$source")
    $count = [regex]::Matches($combinedContent, $marker).Count
    if ($count -ne 1) {
        $errors.Add("Expected exactly one GitLab parity marker for $source; found $count.")
    }
}

foreach ($profile in $scheduleProfiles) {
    if ($combinedContent -notmatch [regex]::Escape("SCAN_PROFILE == `"$profile`"")) {
        $errors.Add("Scheduled pipeline profile is not routed to a job: $profile")
    }
}

$mutableImagePattern = '(?im)^\s*(?:image:\s*|[A-Z0-9_]+_IMAGE:\s*)[^\r\n]*(?::latest|@main|@master)\s*$'
$allPipelineContent = (Get-Content -LiteralPath $rootPipeline -Raw) + [Environment]::NewLine + $combinedContent
if ($allPipelineContent -match $mutableImagePattern) {
    $errors.Add('GitLab CI configuration contains a mutable image or tool reference.')
}

foreach ($requiredText in @('reports:', 'sast:', 'container_scanning:', 'codequality:', 'id_tokens:', 'pages: true')) {
    if ($allPipelineContent -notmatch [regex]::Escape($requiredText)) {
        $errors.Add("Required GitLab capability declaration is missing: $requiredText")
    }
}

foreach ($requiredWikiText in @('docs:gitlab-wiki:', 'GITLAB_WIKI_PUBLISH_TOKEN', 'wiki-documentation/wiki-documentation-manifest.json', '-Mode PublishSecuritySummary')) {
    if ($allPipelineContent -notmatch [regex]::Escape($requiredWikiText)) {
        $errors.Add("Required GitLab Wiki publication declaration is missing: $requiredWikiText")
    }
}

if ($errors.Count -gt 0) {
    throw ($errors -join [Environment]::NewLine)
}

$report = [ordered]@{
    status = 'local-pass'
    sourceWorkflowCount = $expectedSources.Count
    moduleCount = $expectedModules.Count
    scheduleProfileCount = $scheduleProfiles.Count
    validatedAtUtc = [DateTime]::UtcNow.ToString('o')
}

if ($OutputPath) {
    $parent = Split-Path -Parent $OutputPath
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $report | ConvertTo-Json | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM
}

[pscustomobject]$report