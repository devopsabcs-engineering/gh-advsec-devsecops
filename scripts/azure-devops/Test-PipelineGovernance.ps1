[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ConfigurationPath,

    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Initialize-PipelineGovernance.ps1')

$resolvedInput = Resolve-Path -LiteralPath $ConfigurationPath
$configuration = Get-Content -LiteralPath $resolvedInput -Raw | ConvertFrom-Json -Depth 100
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$contracts = Get-Content -LiteralPath (Join-Path $repositoryRoot '.azuredevops\pipelines\config\workflow-contracts.json') -Raw | ConvertFrom-Json -Depth 100
Assert-GovernanceConfiguration $configuration -ContractsDocument $contracts -RepositoryRoot $repositoryRoot
$state = Get-CurrentGovernanceState $configuration
$plan = Get-GovernancePlan $configuration $contracts $state.policies $state.retention $state.checks $state.pipelinePermissions $state.securityPermissions

$findings = @($plan | Where-Object action -ne 'none' | ForEach-Object {
    [pscustomobject]@{
        category = $_.category
        key = $_.key
        observedStatus = $_.action
        expectedStatus = 'none'
    }
})

$report = [pscustomobject]@{
    schemaVersion = 1
    verifiedAtUtc = [DateTime]::UtcNow.ToString('o')
    organizationUrl = $configuration.organizationUrl
    project = $configuration.project
    repositoryId = $configuration.repositoryId
    passed = $findings.Count -eq 0
    findings = $findings
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $report | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM
}

$report | ConvertTo-Json -Depth 100
if (-not $report.passed) {
    throw "Governance verification failed with $($findings.Count) drift finding(s)."
}
