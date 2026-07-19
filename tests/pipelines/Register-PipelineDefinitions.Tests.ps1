$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repositoryRoot 'scripts\azure-devops\Register-PipelineDefinitions.ps1')
$contracts = Get-Content -LiteralPath (Join-Path $repositoryRoot '.azuredevops\pipelines\config\workflow-contracts.json') -Raw | ConvertFrom-Json -Depth 100

function Get-TestRegistrationConfiguration {
    param([string]$SourceBranch)

    $definitions = [ordered]@{}
    foreach ($contract in @($contracts.contracts)) {
        $definitions[$contract.target] = $null
    }
    $configuration = [pscustomobject]@{
        organizationUrl = 'https://dev.azure.com/example'
        project = 'nonproduction'
        repositoryId = '11111111-1111-1111-1111-111111111111'
        pipelineDefinitions = [pscustomobject]$definitions
    }
    if ($PSBoundParameters.ContainsKey('SourceBranch')) {
        $configuration | Add-Member -NotePropertyName sourceBranch -NotePropertyValue $SourceBranch
    }
    return $configuration
}

Describe 'Get-PipelineRegistrationPlan' {
    It 'plans exactly 19 unique YAML registrations without making live calls' {
        $plan = @(Get-PipelineRegistrationPlan (Get-TestRegistrationConfiguration) $contracts $repositoryRoot)

        $plan.Count | Should Be 19
        @($plan.yamlPath | Sort-Object -Unique).Count | Should Be 19
        @($plan | Where-Object action -ne 'create').Count | Should Be 0
    }

    It 'rejects an extra YAML registration path' {
        $configuration = Get-TestRegistrationConfiguration
        $configuration.pipelineDefinitions | Add-Member -NotePropertyName '.azuredevops/pipelines/extra.yml' -NotePropertyValue $null
        $threw = $false

        try { Get-PipelineRegistrationPlan $configuration $contracts $repositoryRoot | Out-Null } catch { $threw = $true }

        $threw | Should Be $true
    }

    It 'rejects invalid organization, project, and repository values before planning' {
        foreach ($invalidConfiguration in @(
            @{ property = 'organizationUrl'; value = 'http://dev.azure.com/example' },
            @{ property = 'organizationUrl'; value = 'https://example.invalid/org' },
            @{ property = 'project'; value = ' ' },
            @{ property = 'repositoryId'; value = '' }
        )) {
            $configuration = Get-TestRegistrationConfiguration
            $configuration.($invalidConfiguration.property) = $invalidConfiguration.value
            $threw = $false

            try { Get-PipelineRegistrationPlan $configuration $contracts $repositoryRoot | Out-Null } catch { $threw = $true }

            $threw | Should Be $true
        }
    }

    It 'rejects nonpositive and duplicate captured definition IDs' {
        foreach ($invalidId in @(0, -1, 'not-an-integer')) {
            $configuration = Get-TestRegistrationConfiguration
            @($configuration.pipelineDefinitions.PSObject.Properties)[0].Value = $invalidId
            $threw = $false

            try { Get-PipelineRegistrationPlan $configuration $contracts $repositoryRoot | Out-Null } catch { $threw = $true }

            $threw | Should Be $true
        }

        $configuration = Get-TestRegistrationConfiguration
        @($configuration.pipelineDefinitions.PSObject.Properties)[0].Value = 101
        @($configuration.pipelineDefinitions.PSObject.Properties)[1].Value = 101
        $threw = $false

        try { Get-PipelineRegistrationPlan $configuration $contracts $repositoryRoot | Out-Null } catch { $threw = $true }

        $threw | Should Be $true
    }

    It 'defaults an absent source branch to main' {
        $configuration = Get-TestRegistrationConfiguration

        Get-PipelineRegistrationPlan $configuration $contracts $repositoryRoot | Out-Null

        $configuration.sourceBranch | Should Be 'main'
    }

    It 'normalizes a refs heads source branch' {
        $configuration = Get-TestRegistrationConfiguration -SourceBranch 'refs/heads/feature/2987-azdo-pipeline-migration'

        Get-PipelineRegistrationPlan $configuration $contracts $repositoryRoot | Out-Null

        $configuration.sourceBranch | Should Be 'feature/2987-azdo-pipeline-migration'
    }

    It 'rejects unsafe source branch values' {
        foreach ($invalidSourceBranch in @(
            '',
            ' ',
            "feature/line`nbreak",
            '-feature/leading-option',
            '--organization',
            'feature/name;az pipelines list',
            'refs/tags/v1'
        )) {
            $configuration = Get-TestRegistrationConfiguration -SourceBranch $invalidSourceBranch
            $threw = $false

            try { Get-PipelineRegistrationPlan $configuration $contracts $repositoryRoot | Out-Null } catch { $threw = $true }

            $threw | Should Be $true
        }
    }
}

Describe 'Invoke-PipelineDefinitionCreate' {
    BeforeEach {
        Mock Invoke-PipelineDefinitionCreateCommand {
            [pscustomobject]@{ exitCode = 0; output = @('unparseable successful create output') }
        }
        Mock Get-RegisteredPipelineDefinition {
            @([pscustomobject]@{
                id = 701
                name = 'ci'
                process = [pscustomobject]@{ yamlFilename = '.azuredevops/pipelines/ci.yml' }
                repository = [pscustomobject]@{
                    id = '11111111-1111-1111-1111-111111111111'
                    defaultBranch = 'refs/heads/feature/2987-azdo-pipeline-migration'
                }
            })
        }
    }

    It 'passes an explicit feature branch to Azure CLI' {
        $configuration = Get-TestRegistrationConfiguration -SourceBranch 'feature/2987-azdo-pipeline-migration'
        Get-PipelineRegistrationPlan $configuration $contracts $repositoryRoot | Out-Null
        $registration = [pscustomobject]@{ name = 'ci'; yamlPath = '.azuredevops/pipelines/ci.yml' }

        $definitionId = Invoke-PipelineDefinitionCreate $configuration $registration

        $definitionId | Should Be 701
        Assert-MockCalled Invoke-PipelineDefinitionCreateCommand 1 -Exactly -Scope It -ParameterFilter {
            $Configuration.sourceBranch -eq 'feature/2987-azdo-pipeline-migration'
        }
    }

    It 'passes the default main branch to Azure CLI' {
        $configuration = Get-TestRegistrationConfiguration
        Get-PipelineRegistrationPlan $configuration $contracts $repositoryRoot | Out-Null
        $registration = [pscustomobject]@{ name = 'ci'; yamlPath = '.azuredevops/pipelines/ci.yml' }

        Invoke-PipelineDefinitionCreate $configuration $registration | Out-Null

        Assert-MockCalled Invoke-PipelineDefinitionCreateCommand 1 -Exactly -Scope It -ParameterFilter {
            $Configuration.sourceBranch -eq 'main'
        }
    }

    It 'fails closed when authoritative read-back finds zero exact matches' {
        Mock Get-RegisteredPipelineDefinition { @() }
        $configuration = Get-TestRegistrationConfiguration
        Get-PipelineRegistrationPlan $configuration $contracts $repositoryRoot | Out-Null
        $registration = [pscustomobject]@{ name = 'ci'; yamlPath = '.azuredevops/pipelines/ci.yml' }
        $threw = $false

        try { Invoke-PipelineDefinitionCreate $configuration $registration | Out-Null } catch { $threw = $true }

        $threw | Should Be $true
    }

    It 'fails closed when authoritative read-back finds multiple exact matches' {
        Mock Get-RegisteredPipelineDefinition {
            @(701, 702 | ForEach-Object {
                [pscustomobject]@{
                    id = $_
                    process = [pscustomobject]@{ yamlFilename = '.azuredevops/pipelines/ci.yml' }
                    repository = [pscustomobject]@{ id = '11111111-1111-1111-1111-111111111111' }
                }
            })
        }
        $configuration = Get-TestRegistrationConfiguration
        Get-PipelineRegistrationPlan $configuration $contracts $repositoryRoot | Out-Null
        $registration = [pscustomobject]@{ name = 'ci'; yamlPath = '.azuredevops/pipelines/ci.yml' }
        $threw = $false

        try { Invoke-PipelineDefinitionCreate $configuration $registration | Out-Null } catch { $threw = $true }

        $threw | Should Be $true
    }
}

Describe 'Get-RegisteredPipelineDefinition' {
    It 'parses the authoritative Build Definitions value array' {
        Mock Invoke-PipelineDefinitionListCommand {
            [pscustomobject]@{
                exitCode = 0
                output = @('{"count":1,"value":[{"id":216,"name":"ci","process":{"yamlFilename":".azuredevops/pipelines/ci.yml"},"repository":{"id":"11111111-1111-1111-1111-111111111111","defaultBranch":"refs/heads/feature/2987-azdo-pipeline-migration"}}]}')
            }
        }

        $definitions = @(Get-RegisteredPipelineDefinition (Get-TestRegistrationConfiguration))

        $definitions.Count | Should Be 1
        $definitions[0].id | Should Be 216
        $definitions[0].process.yamlFilename | Should Be '.azuredevops/pipelines/ci.yml'
        $definitions[0].repository.id | Should Be '11111111-1111-1111-1111-111111111111'
    }
}

Describe 'Invoke-PipelineDefinitionListCommand' {
    It 'uses the authoritative Build Definitions API with full properties' {
        $script:listArguments = @()
        Mock Invoke-AzureDevOpsCliCommand {
            $script:listArguments = @($Arguments)
            [pscustomobject]@{ exitCode = 0; output = @('{"count":0,"value":[]}') }
        }
        $configuration = Get-TestRegistrationConfiguration

        Invoke-PipelineDefinitionListCommand $configuration | Out-Null

        ($script:listArguments -join '|') | Should Be (
            'devops|invoke|--organization|https://dev.azure.com/example|--area|build|--resource|definitions|' +
            '--route-parameters|project=nonproduction|--query-parameters|includeAllProperties=true|' +
            '--api-version|7.1|--output|json'
        )
        Assert-MockCalled Invoke-AzureDevOpsCliCommand 1 -Exactly -Scope It
    }
}

Describe 'Invoke-PipelineRegistrationPlan' {
    It 'reuses exactly one definition matching the full YAML path and repository' {
        Mock Invoke-PipelineDefinitionCreate { throw 'create must not be called' }
        $configuration = Get-TestRegistrationConfiguration
        $plan = @(Get-PipelineRegistrationPlan $configuration $contracts $repositoryRoot | Select-Object -First 1)
        $existing = @(
            [pscustomobject]@{ id = 216; name = $plan[0].name; process = [pscustomobject]@{ yamlFilename = $plan[0].yamlPath }; repository = [pscustomobject]@{ id = $configuration.repositoryId; defaultBranch = 'refs/heads/main' } },
            [pscustomobject]@{ id = 202; process = [pscustomobject]@{ yamlFilename = ".azuredevops/pipelines/$($plan[0].name)-other.yml" }; repository = [pscustomobject]@{ id = $configuration.repositoryId } }
        )
        $outputPath = Join-Path $TestDrive 'reuse.json'

        $result = Invoke-PipelineRegistrationPlan $configuration $plan $existing $outputPath

        $result.($plan[0].yamlPath) | Should Be 216
        Assert-MockCalled Invoke-PipelineDefinitionCreate 0 -Exactly -Scope It
    }

    It 'rejects multiple definitions matching the same exact YAML path' {
        Mock Invoke-PipelineDefinitionCreate
        $configuration = Get-TestRegistrationConfiguration
        $plan = @(Get-PipelineRegistrationPlan $configuration $contracts $repositoryRoot | Select-Object -First 1)
        $existing = @(201, 202 | ForEach-Object {
            [pscustomobject]@{ id = $_; process = [pscustomobject]@{ yamlFilename = $plan[0].yamlPath }; repository = [pscustomobject]@{ id = $configuration.repositoryId } }
        })
        $threw = $false

        try { Invoke-PipelineRegistrationPlan $configuration $plan $existing (Join-Path $TestDrive 'ambiguous.json') | Out-Null } catch { $threw = $true }

        $threw | Should Be $true
        Assert-MockCalled Invoke-PipelineDefinitionCreate 0 -Exactly -Scope It
    }

    It 'persists reused and created IDs while leaving later paths null after failure' {
        $script:createAttempt = 0
        Mock Invoke-PipelineDefinitionCreate {
            $script:createAttempt = $script:createAttempt + 1
            if ($script:createAttempt -eq 2) { throw 'simulated later failure' }
            return 302
        }
        $configuration = Get-TestRegistrationConfiguration -SourceBranch 'feature/2987-azdo-pipeline-migration'
        $plan = @(Get-PipelineRegistrationPlan $configuration $contracts $repositoryRoot)
        $existing = @([pscustomobject]@{
            id = 301
            process = [pscustomobject]@{ yamlFilename = $plan[0].yamlPath }
            repository = [pscustomobject]@{ id = $configuration.repositoryId }
        })
        $outputPath = Join-Path $TestDrive 'partial.json'
        $threw = $false

        try { Invoke-PipelineRegistrationPlan $configuration $plan $existing $outputPath | Out-Null } catch { $threw = $true }

        $threw | Should Be $true
        $saved = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json -Depth 100
        $saved.sourceBranch | Should Be 'feature/2987-azdo-pipeline-migration'
        @($saved.pipelineDefinitions.PSObject.Properties).Count | Should Be 19
        $saved.pipelineDefinitions.PSObject.Properties[$plan[0].yamlPath].Value | Should Be 301
        $saved.pipelineDefinitions.PSObject.Properties[$plan[1].yamlPath].Value | Should Be 302
        $saved.pipelineDefinitions.PSObject.Properties[$plan[2].yamlPath].Value | Should Be $null
        @(Get-ChildItem -LiteralPath $TestDrive -Filter '*.tmp').Count | Should Be 0
    }

    It 'reuses checkpointed IDs and creates only unresolved definitions on retry' {
        $configuration = Get-TestRegistrationConfiguration
        @($configuration.pipelineDefinitions.PSObject.Properties)[0].Value = 401
        @($configuration.pipelineDefinitions.PSObject.Properties)[1].Value = 402
        $plan = @(Get-PipelineRegistrationPlan $configuration $contracts $repositoryRoot)
        $existing = @($plan | Where-Object { $null -ne $_.definitionId } | ForEach-Object {
            [pscustomobject]@{
                id = $_.definitionId
                process = [pscustomobject]@{ yamlFilename = $_.yamlPath }
                repository = [pscustomobject]@{ id = $configuration.repositoryId }
            }
        })
        $script:nextDefinitionId = 500
        Mock Invoke-PipelineDefinitionCreate {
            $definitionId = $script:nextDefinitionId
            $script:nextDefinitionId = $script:nextDefinitionId + 1
            return $definitionId
        }

        Invoke-PipelineRegistrationPlan $configuration $plan $existing (Join-Path $TestDrive 'retry.json') | Out-Null

        Assert-MockCalled Invoke-PipelineDefinitionCreate 17 -Exactly -Scope It
    }
}

Describe 'Start-PipelineRegistration' {
    It 'does not invoke registration during a dry run' {
        Mock Invoke-PipelineRegistrationPlan
        Mock Get-RegisteredPipelineDefinition
        $path = Join-Path $TestDrive 'registration.json'
        Get-TestRegistrationConfiguration | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $path -Encoding utf8NoBOM

        Start-PipelineRegistration -InputPath $path | Out-Null

        Assert-MockCalled Invoke-PipelineRegistrationPlan 0 -Exactly -Scope It
        Assert-MockCalled Get-RegisteredPipelineDefinition 0 -Exactly -Scope It
    }

    It 'uses only the read-only definition query during verification' {
        Mock Invoke-PipelineRegistrationPlan
        Mock Get-RegisteredPipelineDefinition {
            @($script:verificationConfiguration.pipelineDefinitions.PSObject.Properties | ForEach-Object {
                [pscustomobject]@{ id = $_.Value; process = [pscustomobject]@{ yamlFilename = $_.Name } }
            })
        }
        $script:verificationConfiguration = Get-TestRegistrationConfiguration
        $definitionId = 100
        foreach ($property in @($script:verificationConfiguration.pipelineDefinitions.PSObject.Properties)) {
            $property.Value = $definitionId
            $definitionId++
        }
        $path = Join-Path $TestDrive 'verification.json'
        $script:verificationConfiguration | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $path -Encoding utf8NoBOM

        Start-PipelineRegistration -InputPath $path -VerifyDefinitions | Out-Null

        Assert-MockCalled Get-RegisteredPipelineDefinition 1 -Exactly -Scope It
        Assert-MockCalled Invoke-PipelineRegistrationPlan 0 -Exactly -Scope It
    }

    It 'requires captured IDs before read-only verification' {
        Mock Get-RegisteredPipelineDefinition
        $path = Join-Path $TestDrive 'missing-ids.json'
        Get-TestRegistrationConfiguration | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $path -Encoding utf8NoBOM
        $threw = $false

        try { Start-PipelineRegistration -InputPath $path -VerifyDefinitions | Out-Null } catch { $threw = $true }

        $threw | Should Be $true
        Assert-MockCalled Get-RegisteredPipelineDefinition 0 -Exactly -Scope It
    }
}

Describe 'Test-RegisteredPipelineDefinition' {
    It 'detects a definition whose registered YAML path differs from configuration' {
        $configuration = Get-TestRegistrationConfiguration
        $definitionId = 100
        foreach ($property in @($configuration.pipelineDefinitions.PSObject.Properties)) {
            $property.Value = $definitionId
            $definitionId++
        }
        $registered = @($configuration.pipelineDefinitions.PSObject.Properties | ForEach-Object {
            [pscustomobject]@{ id = $_.Value; process = [pscustomobject]@{ yamlFilename = $_.Name } }
        })
        $registered[0].process.yamlFilename = '.azuredevops/pipelines/wrong.yml'

        @(Test-RegisteredPipelineDefinition $configuration $registered).Count | Should Be 1
    }
}