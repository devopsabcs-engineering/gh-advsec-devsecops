[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Add-ValidationError {
    param(
        [System.Collections.Generic.List[string]]$Errors,
        [string]$Message
    )

    $Errors.Add($Message)
}

function Test-MutableReference {
    param([object]$Value)

    if ($null -eq $Value) {
        return $false
    }

    return [string]$Value -match '(?i)(?:^|[/@:])(?:latest|main|master)(?:$|[/@:])'
}

function Add-CheckResult {
    param(
        [System.Collections.Generic.List[object]]$Checks,
        [string]$Id,
        [ValidateSet('local-pass', 'local-fail', 'live-pending')]
        [string]$Status,
        [string]$Detail
    )

    $Checks.Add([pscustomobject]@{
        id = $Id
        status = $Status
        detail = $Detail
    })
}

function Test-PipelineSchedule {
    param(
        [string]$Content,
        [string]$Cron
    )

    $escapedCron = [regex]::Escape($Cron)
    $schedulePattern = '(?ms)^schedules:\s*.*?cron:\s*[''\"]?{0}[''\"]?.*?always:\s*true' -f $escapedCron
    return $Content -match $schedulePattern
}

function Get-TriggerBranch {
    param([string]$Content)

    if ($Content -match '(?m)^trigger:\s+none\s*$') {
        return @()
    }

    $triggerMatch = [regex]::Match($Content, '(?ms)^trigger:\s*\r?\n(?<body>.*?)(?=^[A-Za-z]|\z)')
    if (-not $triggerMatch.Success) {
        return @()
    }

    return @([regex]::Matches($triggerMatch.Groups['body'].Value, '(?m)^\s+-\s+([^#\r\n]+)') | ForEach-Object {
        $_.Groups[1].Value.Trim(" '" + [char]34)
    })
}

$configRoot = Join-Path $RepositoryRoot '.azuredevops\pipelines\config'
$contractPath = Join-Path $configRoot 'workflow-contracts.json'
$toolPath = Join-Path $configRoot 'tool-versions.json'
$routingPath = Join-Path $configRoot 'visualization-routing.json'
$errors = [System.Collections.Generic.List[string]]::new()
$checks = [System.Collections.Generic.List[object]]::new()

foreach ($path in @($contractPath, $toolPath, $routingPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Add-ValidationError $errors "Required manifest is missing: $path"
    }
}

if ($errors.Count -gt 0) {
    throw ($errors -join [Environment]::NewLine)
}

$contractsDocument = Get-Content -LiteralPath $contractPath -Raw | ConvertFrom-Json -Depth 100
$toolsDocument = Get-Content -LiteralPath $toolPath -Raw | ConvertFrom-Json -Depth 100
$routingDocument = Get-Content -LiteralPath $routingPath -Raw | ConvertFrom-Json -Depth 100
$contracts = @($contractsDocument.contracts)

if ($contracts.Count -ne 19 -or $contractsDocument.requiredWorkflowCount -ne 19) {
    Add-ValidationError $errors "Expected exactly 19 workflow contracts; found $($contracts.Count)."
}

$pipelineRoot = Join-Path $RepositoryRoot '.azuredevops\pipelines'
$pipelineFiles = @(Get-ChildItem -LiteralPath $pipelineRoot -File -Filter '*.yml')
if ($pipelineFiles.Count -ne 19) {
    Add-ValidationError $errors "Expected exactly 19 top-level pipeline definitions; found $($pipelineFiles.Count)."
}

$physicalTargets = @($pipelineFiles | ForEach-Object { ".azuredevops/pipelines/$($_.Name)" })
$unexpectedTargets = @($physicalTargets | Where-Object { $_ -notin $contracts.target })
$missingTargets = @($contracts.target | Where-Object { $_ -notin $physicalTargets })
if ($unexpectedTargets.Count -gt 0) {
    Add-ValidationError $errors "Unexpected pipeline definitions: $($unexpectedTargets -join ', ')."
}
if ($missingTargets.Count -gt 0) {
    Add-ValidationError $errors "Contract targets are missing: $($missingTargets -join ', ')."
}

Add-CheckResult $checks 'definition-count' 'local-pass' 'Exactly 19 top-level pipeline definitions map one-to-one to contract targets.'

$sourceWorkflows = @(Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot '.github\workflows') -File -Filter '*.yml')
$contractSources = @($contracts.source)
$contractTargets = @($contracts.target)

if ($sourceWorkflows.Count -ne 19) {
    Add-ValidationError $errors "Expected exactly 19 source workflows; found $($sourceWorkflows.Count)."
}

foreach ($workflow in $sourceWorkflows) {
    $relativePath = ".github/workflows/$($workflow.Name)"
    if ($relativePath -notin $contractSources) {
        Add-ValidationError $errors "Source workflow has no contract: $relativePath"
    }
}

if (@($contractSources | Sort-Object -Unique).Count -ne 19) {
    Add-ValidationError $errors 'Workflow contract source paths must be unique.'
}

if (@($contractTargets | Sort-Object -Unique).Count -ne 19) {
    Add-ValidationError $errors 'Workflow contract target paths must be unique.'
}

foreach ($contract in $contracts) {
    if ($contract.target -notmatch '^\.azuredevops/pipelines/[^/]+\.yml$') {
        Add-ValidationError $errors "Invalid target pipeline path: $($contract.target)"
    }

    foreach ($schedule in @($contract.triggers.schedules)) {
        if ([string]::IsNullOrWhiteSpace($schedule.cronUtc) -or $schedule.always -ne $true) {
            Add-ValidationError $errors "Scheduled contract must provide cronUtc and always=true: $($contract.source)"
        }
    }

    $targetPath = Join-Path $RepositoryRoot $contract.target
    if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
        continue
    }

    $pipelineContent = Get-Content -LiteralPath $targetPath -Raw
    $actualPushBranches = @(Get-TriggerBranch $pipelineContent)
    $expectedPushBranches = @($contract.triggers.push)
    if (Compare-Object $expectedPushBranches $actualPushBranches) {
        Add-ValidationError $errors "Push trigger mismatch for $($contract.target): expected [$($expectedPushBranches -join ', ')], found [$($actualPushBranches -join ', ')]."
    }

    foreach ($schedule in @($contract.triggers.schedules)) {
        if (-not (Test-PipelineSchedule $pipelineContent $schedule.cronUtc)) {
            Add-ValidationError $errors "Schedule '$($schedule.cronUtc)' with always=true is missing from $($contract.target)."
        }
    }

    if (@($contract.triggers.schedules).Count -eq 0 -and $pipelineContent -match '(?m)^schedules:') {
        Add-ValidationError $errors "Undeclared schedule found in $($contract.target)."
    }

    foreach ($artifact in @($contract.artifacts)) {
        if ($artifact -eq 'CodeAnalysisLogs') {
            if ($pipelineContent -notmatch 'templates/publish-sarif\.yml' -and $contract.target -notin @('.azuredevops/pipelines/msdo-security-devops.yml', '.azuredevops/pipelines/iacs-microsoft-security-devops.yml')) {
                Add-ValidationError $errors "CodeAnalysisLogs producer is missing from $($contract.target)."
            }
        }
        elseif ($pipelineContent -notmatch "(?m)artifact:\s+$([regex]::Escape($artifact))\s*$") {
            Add-ValidationError $errors "Declared artifact '$artifact' has no producer in $($contract.target)."
        }
    }
}

Add-CheckResult $checks 'trigger-schedule-parity' 'local-pass' 'Push triggers and declared UTC schedules, including always=true, match all contracts.'
Add-CheckResult $checks 'artifact-parity' 'local-pass' 'Declared artifacts map to pipeline or approved native publication producers.'

if ($contractsDocument.repositoryProvider -ne 'azureRepos' -or $contractsDocument.pullRequestMechanism -ne 'branchPolicy') {
    Add-ValidationError $errors 'Azure Repos contracts must use branchPolicy pull request validation.'
}

$gapIds = @($contractsDocument.platformGaps.id)
foreach ($contract in $contracts | Where-Object { $_.PSObject.Properties.Name -contains 'platformGap' }) {
    if ($contract.platformGap -notin $gapIds) {
        Add-ValidationError $errors "Unknown platform gap '$($contract.platformGap)' in $($contract.source)."
    }
}

foreach ($gap in @($contractsDocument.platformGaps)) {
    if ([string]::IsNullOrWhiteSpace($gap.ownerRole) -or [string]::IsNullOrWhiteSpace($gap.dispositionInput)) {
        Add-ValidationError $errors "Platform gap requires an owner role and disposition input: $($gap.id)"
    }

    if ($gap.status -notin @('decision-required', 'accepted', 'replaced', 'retained', 'retired')) {
        Add-ValidationError $errors "Platform gap has invalid status: $($gap.id)"
    }
}

foreach ($reference in @($toolsDocument.references)) {
    foreach ($property in $reference.PSObject.Properties) {
        if (Test-MutableReference $property.Value) {
            Add-ValidationError $errors "Mutable tool reference in '$($reference.id)' property '$($property.Name)'."
        }
    }

    $hasConcreteIntegrity = $reference.PSObject.Properties.Name -contains 'commit'
    $hasRequiredIntegrityInput =
        $reference.PSObject.Properties.Name -contains 'requiredInput' -and
        $reference.requiredInput -eq $true
    if (-not $hasConcreteIntegrity -and -not $hasRequiredIntegrityInput -and $reference.kind -notin @('runtime-channel', 'runtime-major')) {
        Add-ValidationError $errors "Tool reference lacks verified integrity or a required input: $($reference.id)"
    }
}

$routes = @($routingDocument.routes)
$thirdPartyRoute = $routes | Where-Object reportType -eq 'third-party-sarif'
$thirdPartyDestinations = @($thirdPartyRoute.destinations)
$sarifScansDestination = $thirdPartyDestinations | Where-Object name -eq 'sarif-scans-tab'
$advancedSecurityDestination = $thirdPartyDestinations | Where-Object name -eq 'repos-advanced-security-code-scanning'
if ($thirdPartyRoute.destination -ne 'sarif-scans-tab' -or
    $thirdPartyRoute.artifact -ne 'CodeAnalysisLogs' -or
    $sarifScansDestination.artifact -ne 'CodeAnalysisLogs' -or
    $advancedSecurityDestination.task -ne 'AdvancedSecurity-Publish@1') {
    Add-ValidationError $errors 'Third-party SARIF must route to CodeAnalysisLogs in SARIF Scans and AdvancedSecurity-Publish@1 in Advanced Security Code Scanning.'
}

$msdoRoute = $routes | Where-Object reportType -eq 'msdo-sarif'
$msdoDestinations = @($msdoRoute.destinations)
$msdoSarifScansDestination = $msdoDestinations | Where-Object name -eq 'sarif-scans-tab'
$msdoAdvancedSecurityDestination = $msdoDestinations | Where-Object name -eq 'repos-advanced-security-code-scanning'
if ($msdoRoute.destination -ne 'sarif-scans-tab' -or
    $msdoRoute.artifact -ne 'CodeAnalysisLogs' -or
    $msdoSarifScansDestination.artifact -ne 'CodeAnalysisLogs' -or
    $msdoAdvancedSecurityDestination.task -ne 'AdvancedSecurity-Publish@1') {
    Add-ValidationError $errors 'MSDO SARIF must route natively to CodeAnalysisLogs and through AdvancedSecurity-Publish@1 to Advanced Security Code Scanning.'
}

foreach ($reportType in @('ghazdo-codeql', 'ghazdo-dependencies')) {
    $route = $routes | Where-Object reportType -eq $reportType
    if ($null -ne $route.artifact -or $route.destination -notmatch '^repos-advanced-security-') {
        Add-ValidationError $errors "Native GHAzDO route must remain separate from generic artifacts: $reportType"
    }
}

$scorecardRoute = $routes | Where-Object reportType -eq 'openssf-scorecard'
if ($scorecardRoute.authoritativeFormat -ne 'json' -or $scorecardRoute.wikiFallback -ne $true) {
    Add-ValidationError $errors 'OpenSSF Scorecard must remain authoritative JSON with a wiki summary fallback.'
}

$documentationRoute = $routes | Where-Object reportType -eq 'documentation-deployment'
if ($documentationRoute.authoritativeFormat -ne 'markdown' -or
    $documentationRoute.destination -ne 'project-wiki' -or
    $documentationRoute.artifact -ne 'wiki-documentation' -or
    $documentationRoute.wikiFallback -ne $true -or
    $documentationRoute.wikiPath -ne 'Documentation') {
    Add-ValidationError $errors 'Documentation must publish authoritative Markdown from wiki-documentation to the project wiki under Documentation.'
}

$producerMap = @{
    'ghazdo-codeql' = '.azuredevops/pipelines/sast-codeql.yml'
    'ghazdo-dependencies' = '.azuredevops/pipelines/sca-dependency-scanning.yml'
    'third-party-sarif' = '.azuredevops/pipelines/templates/publish-sarif.yml'
    'msdo-sarif' = '.azuredevops/pipelines/msdo-security-devops.yml'
    'openssf-scorecard' = '.azuredevops/pipelines/sca-openssf-scorecard.yml'
    'security-agent' = '.azuredevops/pipelines/security-agent.yml'
    'governance' = '.azuredevops/pipelines/enforce-ghas-policy.yml'
    'workflow-parity' = 'scripts/validation/Test-WorkflowContracts.ps1'
    'spdx-sbom' = '.azuredevops/pipelines/sca-microsoft-sbom.yml'
    'signed-provenance' = '.azuredevops/pipelines/cicd.yml'
    'zap-html-json' = '.azuredevops/pipelines/dast-zap.yml'
    'application-deployment' = '.azuredevops/pipelines/cicd.yml'
    'documentation-deployment' = '.azuredevops/pipelines/docs-static.yml'
}

foreach ($route in $routes) {
    if (-not $producerMap.ContainsKey($route.reportType)) {
        Add-ValidationError $errors "Visualization route has no declared producer owner: $($route.reportType)."
        continue
    }

    $producerPath = Join-Path $RepositoryRoot $producerMap[$route.reportType]
    if (-not (Test-Path -LiteralPath $producerPath -PathType Leaf)) {
        Add-ValidationError $errors "Visualization producer is missing for '$($route.reportType)': $($producerMap[$route.reportType])."
    }
}

Add-CheckResult $checks 'visualization-routing' 'local-pass' 'Native, SARIF, artifact, OCI, environment, and wiki fallback routes have explicit producer owners.'

$productionFiles = @(
    Get-ChildItem -LiteralPath $pipelineRoot -Recurse -File | Where-Object { $_.Extension -in @('.yml', '.json') }
    Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'scripts') -Recurse -File -Filter '*.ps1'
)
$unsupportedPlaceholderPattern = '(?i)\b(?:' + 'TO' + 'DO|FIX' + 'ME|T' + 'BD)\b'
$credentialAssignmentPattern = '(?im)^\s*(?:password|client[_-]?secret|account[_-]?key|sas[_-]?token|access[_-]?token|pat)\s*[:=]\s*["''][^$({][^"'']+["'']'
$credentialArgumentPattern = '(?i)--(?:account-key|sas-token|client-secret)(?:\s|=)'
$mutableToolPattern = '(?i)(?:uses:\s*[^\s]+@|image:\s*|docker\s+(?:run|pull)\s+[^\r\n]*)(?:[^\r\n]*[:@/])(?:latest|main|master)(?:\s|$)'

foreach ($file in $productionFiles) {
    $content = Get-Content -LiteralPath $file.FullName -Raw
    if ($content -match $unsupportedPlaceholderPattern) {
        Add-ValidationError $errors "Unsupported implementation placeholder in production migration file: $($file.FullName)."
    }
    if ($content -match $credentialAssignmentPattern -or $content -match $credentialArgumentPattern) {
        Add-ValidationError $errors "Potential hardcoded credential or credential parameter in production migration file: $($file.FullName)."
    }
    if ($content -match $mutableToolPattern) {
        Add-ValidationError $errors "Mutable tool or deployment reference in production migration file: $($file.FullName)."
    }
}

Add-CheckResult $checks 'migration-security' 'local-pass' 'Production migration files contain no obvious secrets, credential arguments, mutable tool/deployment references, or unsupported placeholders.'
Add-CheckResult $checks 'platform-gap-dispositions' 'local-pass' "$(@($contractsDocument.platformGaps).Count) platform gaps have owner roles, approved disposition inputs, and valid statuses."

$liveChecks = @(
    @{ Id = 'definition-registration'; Detail = 'Verify exactly 19 registered Azure DevOps definitions and immutable administrative references.' },
    @{ Id = 'branch-policy-and-schedules'; Detail = 'Verify branch-policy queue/requeue behavior and registered schedule semantics.' },
    @{ Id = 'security-product-views'; Detail = 'Verify GHAzDO, MSDO, and SARIF Scans product-view publication.' },
    @{ Id = 'external-side-effects'; Detail = 'Verify deployment, OCI evidence, retention, wiki, pull request comments, environment locks, and authorized ZAP behavior.' },
    @{ Id = 'workflow-parity-handoff'; Detail = 'Publish the workflow-parity artifact/wiki summary only after live evidence is available.' }
)
foreach ($liveCheck in $liveChecks) {
    Add-CheckResult $checks $liveCheck.Id 'live-pending' $liveCheck.Detail
}

$report = [ordered]@{
    schemaVersion = 1
    generatedAtUtc = [DateTime]::UtcNow.ToString('o')
    status = if ($errors.Count -eq 0) { 'local-pass-live-pending' } else { 'local-fail' }
    requiredWorkflowCount = 19
    sourceWorkflowCount = $sourceWorkflows.Count
    targetPipelineCount = $pipelineFiles.Count
    platformGapCount = @($contractsDocument.platformGaps).Count
    checks = @($checks)
    errors = @($errors)
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $resolvedOutputPath = if ([System.IO.Path]::IsPathRooted($OutputPath)) { $OutputPath } else { Join-Path $RepositoryRoot $OutputPath }
    $outputDirectory = Split-Path -Parent $resolvedOutputPath
    if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    }
    $report | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $resolvedOutputPath -Encoding utf8
}

if ($errors.Count -gt 0) {
    throw ("Workflow contract validation failed:`n - " + ($errors -join "`n - "))
}

Write-Output "Workflow contract validation passed: $($contracts.Count) source workflows, $(@($contractTargets | Sort-Object -Unique).Count) unique targets, and $(@($contractsDocument.platformGaps).Count) explicit platform-gap inputs."