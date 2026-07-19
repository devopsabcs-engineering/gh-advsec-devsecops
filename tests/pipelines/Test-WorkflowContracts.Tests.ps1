$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$validatorPath = Join-Path $repositoryRoot 'scripts\validation\Test-WorkflowContracts.ps1'

Describe 'Test-WorkflowContracts Phase 10 parity report' {
    function Copy-ValidationFixture {
        param([Parameter(Mandatory)][string]$Destination)

        foreach ($relativePath in @('.github\workflows', '.azuredevops\pipelines', 'scripts')) {
            $sourcePath = Join-Path $repositoryRoot $relativePath
            $destinationPath = Join-Path $Destination $relativePath
            New-Item -ItemType Directory -Path (Split-Path -Parent $destinationPath) -Force | Out-Null
            Copy-Item -LiteralPath $sourcePath -Destination $destinationPath -Recurse
        }
    }

    It 'reports complete local parity while keeping live handoff checks pending' {
        $reportPath = Join-Path $TestDrive 'workflow-parity-report.json'

        & $validatorPath -RepositoryRoot $repositoryRoot -OutputPath $reportPath

        $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json -Depth 100
        $report.status | Should Be 'local-pass-live-pending'
        $report.requiredWorkflowCount | Should Be 19
        $report.sourceWorkflowCount | Should Be 19
        $report.targetPipelineCount | Should Be 19
        $report.platformGapCount | Should Be 4
        @($report.checks | Where-Object status -eq 'local-fail').Count | Should Be 0
        @($report.checks | Where-Object status -eq 'live-pending').Count | Should Be 5
        @($report.checks | Where-Object id -eq 'workflow-parity-handoff').status | Should Be 'live-pending'
    }

    It 'fails closed when an uncontracted top-level pipeline definition exists' {
        $fixtureRoot = Join-Path $TestDrive 'repository'
        Copy-ValidationFixture -Destination $fixtureRoot
        Set-Content -LiteralPath (Join-Path $fixtureRoot '.azuredevops\pipelines\unexpected.yml') -Value "trigger: none`n"

        $validationError = $null
        try {
            & $validatorPath -RepositoryRoot $fixtureRoot
        }
        catch {
            $validationError = $_
        }

        $validationError | Should Not BeNullOrEmpty
        $validationError.Exception.Message | Should Match 'Expected exactly 19 top-level pipeline definitions; found 20'
    }

    It 'fails closed when a declared schedule omits always true' {
        $fixtureRoot = Join-Path $TestDrive 'schedule-repository'
        Copy-ValidationFixture -Destination $fixtureRoot
        $pipelinePath = Join-Path $fixtureRoot '.azuredevops\pipelines\cis-trivy.yml'
        $pipeline = Get-Content -LiteralPath $pipelinePath -Raw
        $pipeline -replace 'always:\s+true', 'always: false' | Set-Content -LiteralPath $pipelinePath

        $validationError = $null
        try {
            & $validatorPath -RepositoryRoot $fixtureRoot
        }
        catch {
            $validationError = $_
        }

        $validationError | Should Not BeNullOrEmpty
        $validationError.Exception.Message | Should Match "Schedule '0 1 \* \* 0' with always=true is missing from \.azuredevops/pipelines/cis-trivy\.yml"
    }
}