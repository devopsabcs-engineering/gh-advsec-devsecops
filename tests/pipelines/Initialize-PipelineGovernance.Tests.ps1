$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repositoryRoot 'scripts\azure-devops\Initialize-PipelineGovernance.ps1')
$contracts = Get-Content -LiteralPath (Join-Path $repositoryRoot '.azuredevops\pipelines\config\workflow-contracts.json') -Raw | ConvertFrom-Json -Depth 100

function New-TestConfiguration {
    $definitions = [ordered]@{}
    $definitionId = 100
    foreach ($contract in @($contracts.contracts)) {
        $definitions[$contract.target] = $definitionId
        $definitionId++
    }

    return [pscustomobject]@{
        organizationUrl = 'https://dev.azure.com/example'
        project = 'nonproduction'
        repositoryId = '11111111-1111-1111-1111-111111111111'
        pipelineDefinitions = [pscustomobject]$definitions
        retention = [pscustomobject]@{ runDays = 30; pullRequestRunDays = 30 }
        documentationEnvironment = [pscustomobject]@{
            id = '42'
            name = 'docs-nonproduction'
            pipelineIds = @(118)
            exclusiveLockCheckTypeId = '22222222-2222-2222-2222-222222222222'
            timeoutMinutes = 43200
        }
        applicationEnvironment = [pscustomobject]@{ id = '43'; name = 'app-nonproduction'; pipelineIds = @(101) }
        serviceConnections = @([pscustomobject]@{ id = '33333333-3333-3333-3333-333333333333'; pipelineIds = @(101, 118) })
        variableGroups = @([pscustomobject]@{
            id = '12'
            pipelineIds = @(101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 115, 116, 117, 118)
            variableNames = @('COSIGN_SHA256', 'ESLINT_8_10_0_INTEGRITY', 'JEKYLL_GEM_SHA256')
        })
        permissionUpdates = @([pscustomobject]@{
            namespaceId = '44444444-4444-4444-4444-444444444444'
            subject = 'vssgp.example-build-service'
            token = 'repoV2/example'
            allowBit = 1
            denyBit = 0
        })
    }
}

Describe 'Assert-GovernanceConfiguration' {
    It 'requires exactly one definition ID for every contracted YAML path' {
        $configuration = New-TestConfiguration
        $configuration.pipelineDefinitions.PSObject.Properties.Remove('.azuredevops/pipelines/docs-static.yml')
        $threw = $false

        try {
            Assert-GovernanceConfiguration $configuration -ContractsDocument $contracts -RepositoryRoot $repositoryRoot
        }
        catch {
            $threw = $true
        }

        $threw | Should Be $true
    }

    It 'rejects duplicate definition IDs' {
        $configuration = New-TestConfiguration
        $configuration.pipelineDefinitions.'.azuredevops/pipelines/docs-static.yml' = $configuration.pipelineDefinitions.'.azuredevops/pipelines/ci.yml'
        $threw = $false

        try {
            Assert-GovernanceConfiguration $configuration -ContractsDocument $contracts -RepositoryRoot $repositoryRoot
        }
        catch {
            $threw = $true
        }

        $threw | Should Be $true
    }

    It 'rejects a protected resource scoped to an unknown pipeline ID' {
        $configuration = New-TestConfiguration
        $configuration.serviceConnections[0].pipelineIds = @(999)
        $threw = $false

        try {
            Assert-GovernanceConfiguration $configuration -ContractsDocument $contracts -RepositoryRoot $repositoryRoot
        }
        catch {
            $threw = $true
        }

        $threw | Should Be $true
    }

    It 'rejects duplicate pipeline IDs within a protected resource scope' {
        $configuration = New-TestConfiguration
        $configuration.documentationEnvironment.pipelineIds = @(118, 118)
        $threw = $false

        try {
            Assert-GovernanceConfiguration $configuration -ContractsDocument $contracts -RepositoryRoot $repositoryRoot
        }
        catch {
            $threw = $true
        }

        $threw | Should Be $true
    }
}

Describe 'Get-DesiredPolicyConfigurations' {
    It 'creates one blocking automatic build policy for every pull request contract' {
        $configuration = New-TestConfiguration
        $policies = @(Get-DesiredPolicyConfiguration $configuration $contracts)
        $expectedBuildCount = @($contracts.contracts | Where-Object { @($_.triggers.pullRequest) -contains 'main' }).Count
        $buildPolicies = @($policies | Where-Object typeId -eq $script:PolicyTypeIds.BuildValidation)

        $buildPolicies.Count | Should Be $expectedBuildCount
        $buildPolicies | ForEach-Object {
            $_.isBlocking | Should Be $true
            $_.settings.manualQueueOnly | Should Be $false
            $_.settings.queueOnSourceUpdateOnly | Should Be $false
            $_.settings.validDuration | Should Be 0
            $_.settings.scope[0].refName | Should Be 'refs/heads/main'
        }
    }

    It 'requires every pull request pipeline definition ID' {
        $configuration = New-TestConfiguration
        $configuration.pipelineDefinitions.'.azuredevops/pipelines/ci.yml' = $null
        $threw = $false

        try {
            Get-DesiredPolicyConfiguration $configuration $contracts | Out-Null
        }
        catch {
            $threw = $true
        }

        $threw | Should Be $true
    }
}

Describe 'Get-GovernancePlan' {
    It 'produces no branch-policy changes when current state is equivalent' {
        $configuration = New-TestConfiguration
        $desiredPolicies = @(Get-DesiredPolicyConfiguration $configuration $contracts)
        $existingPolicies = @($desiredPolicies | ForEach-Object {
            [pscustomobject]@{
                id = [guid]::NewGuid().ToString()
                type = [pscustomobject]@{ id = $_.typeId }
                isEnabled = $_.isEnabled
                isBlocking = $_.isBlocking
                settings = [pscustomobject]$_.settings
            }
        })
        $retention = [pscustomobject]@{ daysToKeep = 30; daysToKeepPullRequestRuns = 30 }
        $checks = @([pscustomobject]@{
            id = 'check-1'
            type = [pscustomobject]@{ id = $configuration.documentationEnvironment.exclusiveLockCheckTypeId }
            resource = [pscustomobject]@{ id = $configuration.documentationEnvironment.id }
            settings = [pscustomobject]@{ timeout = 43200 }
        })
        $permissions = @(
            [pscustomobject]@{
                resourceType = 'endpoint'
                resourceId = $configuration.serviceConnections[0].id
                allPipelines = [pscustomobject]@{ authorized = $false }
                pipelines = @(
                    [pscustomobject]@{ id = 101; authorized = $true },
                    [pscustomobject]@{ id = 118; authorized = $true }
                )
            },
            [pscustomobject]@{
                resourceType = 'variablegroup'
                resourceId = $configuration.variableGroups[0].id
                allPipelines = [pscustomobject]@{ authorized = $false }
                pipelines = @($configuration.variableGroups[0].pipelineIds | ForEach-Object { [pscustomobject]@{ id = $_; authorized = $true } })
            },
            [pscustomobject]@{
                resourceType = 'environment'
                resourceId = $configuration.applicationEnvironment.id
                allPipelines = [pscustomobject]@{ authorized = $false }
                pipelines = @([pscustomobject]@{ id = 101; authorized = $true })
            },
            [pscustomobject]@{
                resourceType = 'environment'
                resourceId = $configuration.documentationEnvironment.id
                allPipelines = [pscustomobject]@{ authorized = $false }
                pipelines = @([pscustomobject]@{ id = 118; authorized = $true })
            }
        )
        $securityPermissions = @([pscustomobject]@{
            key = "$($configuration.permissionUpdates[0].namespaceId):$($configuration.permissionUpdates[0].subject):$($configuration.permissionUpdates[0].token)"
            allow = 1
            deny = 0
        })

        $plan = @(Get-GovernancePlan $configuration $contracts $existingPolicies $retention $checks $permissions $securityPermissions)

        @($plan | Where-Object { $_.category -eq 'branch-policy' -and $_.action -ne 'none' }).Count | Should Be 0
        @($plan | Where-Object { $_.category -in @('retention', 'environment-check', 'pipeline-permission', 'security-permission') -and $_.action -ne 'none' }).Count | Should Be 0
    }

    It 'updates a drifted build policy instead of creating a duplicate' {
        $configuration = New-TestConfiguration
        $desired = @(Get-DesiredPolicyConfiguration $configuration $contracts)[0]
        $existing = [pscustomobject]@{
            id = 'policy-1'
            type = [pscustomobject]@{ id = $desired.typeId }
            isEnabled = $true
            isBlocking = $false
            settings = [pscustomobject]$desired.settings
        }

        $plan = @(Get-GovernancePlan $configuration $contracts @($existing))
        $operation = $plan | Where-Object key -eq $desired.key

        $operation.action | Should Be 'update'
        $operation.existingId | Should Be 'policy-1'
    }

    It 'rejects retention shorter than 30 days' {
        $configuration = New-TestConfiguration
        $configuration.retention.runDays = 29
        $threw = $false

        try {
            Get-GovernancePlan $configuration $contracts | Out-Null
        }
        catch {
            $threw = $true
        }

        $threw | Should Be $true
    }
}

Describe 'Invoke-GovernancePlan' {
    It 'constructs a policy configuration POST for a missing build policy' {
        Mock Invoke-JsonFileCommand
        Mock Invoke-AzDevOpsCommand
        $configuration = New-TestConfiguration
        $desired = @(Get-DesiredPolicyConfiguration $configuration $contracts)[0]
        $operation = [pscustomobject]@{
            category = 'branch-policy'
            key = $desired.key
            action = 'create'
            existingId = $null
            desired = $desired
        }

        Invoke-GovernancePlan $configuration @($operation)

        Assert-MockCalled Invoke-JsonFileCommand 1 -Exactly -ParameterFilter {
            $Arguments -contains '--area' -and
            $Arguments -contains 'policy' -and
            $Arguments -contains '--http-method' -and
            $Arguments -contains 'POST'
        }
        Assert-MockCalled Invoke-AzDevOpsCommand 0 -Exactly
    }

    It 'constructs a least-privilege variable-group permission PATCH' {
        Mock Invoke-JsonFileCommand
        Mock Invoke-AzDevOpsCommand
        $configuration = New-TestConfiguration
        $operation = [pscustomobject]@{
            category = 'pipeline-permission'
            key = 'variablegroup:12'
            action = 'update'
            desired = @{
                resourceType = 'variablegroup'
                resourceId = '12'
                allPipelines = @{ authorized = $false }
                pipelines = @(@{ id = 101; authorized = $true })
            }
        }

        Invoke-GovernancePlan $configuration @($operation)

        Assert-MockCalled Invoke-JsonFileCommand 1 -Exactly -Scope It -ParameterFilter {
            $Arguments -contains 'resourceType=variablegroup' -and
            $Arguments -contains 'resourceId=12' -and
            $Arguments -contains 'PATCH' -and
            $Body.allPipelines.authorized -eq $false
        }
        Assert-MockCalled Invoke-AzDevOpsCommand 0 -Exactly -Scope It
    }
}

Describe 'Start-PipelineGovernanceInitialization' {
    It 'does not invoke mutations during a dry run' {
        Mock Get-CurrentGovernanceState {
            [pscustomobject]@{ policies = @(); retention = $null; checks = @(); pipelinePermissions = @(); securityPermissions = @() }
        }
        Mock Invoke-GovernancePlan
        $configuration = New-TestConfiguration
        $path = Join-Path $TestDrive 'governance.json'
        $configuration | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $path -Encoding utf8NoBOM

        Start-PipelineGovernanceInitialization -InputPath $path | Out-Null

        Assert-MockCalled Invoke-GovernancePlan 0 -Exactly
    }
}