[CmdletBinding()]
param(
    [string]$ConfigurationPath,

    [string]$OutputPath,

    [switch]$Apply,

    [switch]$Verify
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-PipelineRegistrationConfiguration {
    param([pscustomobject]$Configuration)

    $sourceBranchProperty = $Configuration.PSObject.Properties['sourceBranch']
    if ($null -eq $sourceBranchProperty) {
        $Configuration | Add-Member -NotePropertyName sourceBranch -NotePropertyValue 'main'
    }
    else {
        $sourceBranch = [string]$sourceBranchProperty.Value
        if ([string]::IsNullOrWhiteSpace($sourceBranch)) {
            throw 'sourceBranch must be nonempty when supplied.'
        }
        if ($sourceBranch.StartsWith('refs/heads/', [StringComparison]::Ordinal)) {
            $sourceBranch = $sourceBranch.Substring('refs/heads/'.Length)
        }
        if ($sourceBranch.StartsWith('refs/', [StringComparison]::Ordinal) -or
            $sourceBranch.StartsWith('-', [StringComparison]::Ordinal) -or
            $sourceBranch -match '[\s\p{Cc}\p{Cf}]' -or
            $sourceBranch -notmatch '^[A-Za-z0-9_][A-Za-z0-9._/-]*$' -or
            $sourceBranch -match '(^|/)\.|\.\.|@\{|//|\.lock(?:/|$)' -or
            $sourceBranch.EndsWith('.', [StringComparison]::Ordinal) -or
            $sourceBranch.EndsWith('/', [StringComparison]::Ordinal)) {
            throw 'sourceBranch must be a plain Azure Repos branch name or refs/heads ref.'
        }
        $sourceBranchProperty.Value = $sourceBranch
    }

    $organizationUri = $null
    if ([string]::IsNullOrWhiteSpace([string]$Configuration.organizationUrl) -or
        -not [Uri]::TryCreate([string]$Configuration.organizationUrl, [UriKind]::Absolute, [ref]$organizationUri) -or
        $organizationUri.Scheme -cne 'https' -or
        ($organizationUri.Host -ine 'dev.azure.com' -and
        -not $organizationUri.Host.EndsWith('.visualstudio.com', [StringComparison]::OrdinalIgnoreCase)) -or
        ($organizationUri.Host -ieq 'dev.azure.com' -and $organizationUri.AbsolutePath.Trim('/').Length -eq 0)) {
        throw 'organizationUrl must be an HTTPS Azure DevOps URL.'
    }
    if ([string]::IsNullOrWhiteSpace([string]$Configuration.project)) {
        throw 'project must be nonempty.'
    }
    if ([string]::IsNullOrWhiteSpace([string]$Configuration.repositoryId)) {
        throw 'repositoryId must be nonempty.'
    }

    $capturedIds = @($Configuration.pipelineDefinitions.PSObject.Properties |
        Where-Object { $null -ne $_.Value } |
        ForEach-Object {
            $definitionId = 0
            if (-not [int]::TryParse([string]$_.Value, [ref]$definitionId) -or $definitionId -le 0) {
                throw "Definition ID for '$($_.Name)' must be a positive integer or null."
            }
            $definitionId
        })
    if (@($capturedIds | Sort-Object -Unique).Count -ne $capturedIds.Count) {
        throw 'Captured pipeline definition IDs must be unique.'
    }
}

function Save-PipelineRegistrationProgress {
    param(
        [pscustomobject]$Configuration,
        [System.Collections.IDictionary]$DefinitionIds,
        [string]$Path
    )

    $document = [ordered]@{
        organizationUrl = $Configuration.organizationUrl
        project = $Configuration.project
        repositoryId = $Configuration.repositoryId
        sourceBranch = $Configuration.sourceBranch
        pipelineDefinitions = $DefinitionIds
    }
    $directory = Split-Path -Parent $Path
    if ([string]::IsNullOrWhiteSpace($directory)) {
        $directory = (Get-Location).Path
        $Path = Join-Path $directory $Path
    }
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        throw "OutputPath directory does not exist: $directory"
    }

    $temporaryPath = Join-Path $directory ('.{0}.{1}.tmp' -f [IO.Path]::GetFileName($Path), [Guid]::NewGuid().ToString('N'))
    $backupPath = Join-Path $directory ('.{0}.{1}.bak' -f [IO.Path]::GetFileName($Path), [Guid]::NewGuid().ToString('N'))
    try {
        $document | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $temporaryPath -Encoding utf8NoBOM
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            [IO.File]::Replace($temporaryPath, $Path, $backupPath)
        }
        else {
            Move-Item -LiteralPath $temporaryPath -Destination $Path
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
        if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
            Remove-Item -LiteralPath $backupPath -Force
        }
    }
}

function Get-PipelineRegistrationPlan {
    param(
        [pscustomobject]$Configuration,
        [pscustomobject]$ContractsDocument,
        [string]$RepositoryRoot
    )

    Assert-PipelineRegistrationConfiguration $Configuration

    $contracts = @($ContractsDocument.contracts)
    if ($contracts.Count -ne 19 -or $ContractsDocument.requiredWorkflowCount -ne 19) {
        throw "Registration requires exactly 19 workflow contracts; found $($contracts.Count)."
    }

    $configuredPaths = @($Configuration.pipelineDefinitions.PSObject.Properties.Name | Sort-Object)
    $contractPaths = @($contracts.target | Sort-Object)
    if (($configuredPaths -join "`n") -cne ($contractPaths -join "`n")) {
        throw 'Registration configuration must contain exactly the 19 contracted YAML paths.'
    }

    return @($contracts | ForEach-Object {
        $yamlPath = $_.target
        $localPath = Join-Path $RepositoryRoot ($yamlPath -replace '/', '\')
        if (-not (Test-Path -LiteralPath $localPath -PathType Leaf)) {
            throw "Contracted pipeline YAML is missing: $yamlPath"
        }

        $definitionId = $Configuration.pipelineDefinitions.PSObject.Properties[$yamlPath].Value
        [pscustomobject]@{
            source = $_.source
            yamlPath = $yamlPath
            name = [IO.Path]::GetFileNameWithoutExtension($yamlPath)
            definitionId = $definitionId
            action = if ($null -eq $definitionId) { 'create' } else { 'verify' }
        }
    })
}

function Invoke-PipelineRegistrationPlan {
    param(
        [pscustomobject]$Configuration,
        [object[]]$Plan,
        [object[]]$ExistingDefinitions,
        [string]$ResultPath
    )

    $results = [ordered]@{}
    foreach ($registration in $Plan) {
        $results[$registration.yamlPath] = $registration.definitionId
    }
    Save-PipelineRegistrationProgress -Configuration $Configuration -DefinitionIds $results -Path $ResultPath

    foreach ($registration in $Plan) {
        if ($registration.action -eq 'create') {
            $matchingDefinitions = @($ExistingDefinitions | Where-Object {
                [string]$_.process.yamlFilename -ceq $registration.yamlPath -and
                [string]$_.repository.id -ceq [string]$Configuration.repositoryId
            })
            if ($matchingDefinitions.Count -gt 1) {
                throw "Multiple pipeline definitions match exact YAML path '$($registration.yamlPath)'."
            }
            if ($matchingDefinitions.Count -eq 1) {
                $definitionId = [int]$matchingDefinitions[0].id
            }
            else {
                $definitionId = Invoke-PipelineDefinitionCreate -Configuration $Configuration -Registration $registration
                $ExistingDefinitions += [pscustomobject]@{
                    id = $definitionId
                    process = [pscustomobject]@{ yamlFilename = $registration.yamlPath }
                    repository = [pscustomobject]@{ id = $Configuration.repositoryId }
                }
            }
            if ($definitionId -le 0 -or $definitionId -in @($results.Values | Where-Object { $null -ne $_ })) {
                throw "Resolved definition ID for '$($registration.yamlPath)' must be positive and unique."
            }
            $results[$registration.yamlPath] = $definitionId
            Save-PipelineRegistrationProgress -Configuration $Configuration -DefinitionIds $results -Path $ResultPath
        }
    }

    return [pscustomobject]$results
}

function Invoke-PipelineDefinitionCreate {
    param(
        [pscustomobject]$Configuration,
        [pscustomobject]$Registration
    )

    $commandResult = Invoke-PipelineDefinitionCreateCommand -Configuration $Configuration -Registration $Registration
    if ($commandResult.exitCode -ne 0) {
        throw "Pipeline registration failed without exposing command output: $($Registration.yamlPath)"
    }

    $sourceBranch = [string]$Configuration.sourceBranch
    $sourceBranchRef = "refs/heads/$sourceBranch"
    $matchingDefinitions = @(Get-RegisteredPipelineDefinition $Configuration | Where-Object {
        [string]$_.process.yamlFilename -ceq $Registration.yamlPath -and
        [string]$_.repository.id -ceq [string]$Configuration.repositoryId
    })
    $preferredDefinitions = @($matchingDefinitions | Where-Object {
        ([string]$_.repository.defaultBranch -ceq $sourceBranch -or
        [string]$_.repository.defaultBranch -ceq $sourceBranchRef) -and
        [string]$_.name -ceq $Registration.name
    })
    if ($preferredDefinitions.Count -eq 1) {
        $matchingDefinitions = $preferredDefinitions
    }
    if ($matchingDefinitions.Count -ne 1) {
        throw "Pipeline registration read-back found $($matchingDefinitions.Count) exact definition match(es): $($Registration.yamlPath)"
    }

    $definitionId = [int]$matchingDefinitions[0].id
    if ($definitionId -le 0) {
        throw "Pipeline registration read-back returned an invalid definition ID: $($Registration.yamlPath)"
    }
    return $definitionId
}

function Invoke-PipelineDefinitionCreateCommand {
    param(
        [pscustomobject]$Configuration,
        [pscustomobject]$Registration
    )

    $output = & az pipelines create `
        --organization $Configuration.organizationUrl `
        --project $Configuration.project `
        --repository $Configuration.repositoryId `
        --repository-type tfsgit `
        --branch $Configuration.sourceBranch `
        --name $Registration.name `
        --yaml-path $Registration.yamlPath `
        --skip-first-run true `
        --output json 2>&1
    return [pscustomobject]@{
        exitCode = $LASTEXITCODE
        output = @($output)
    }
}

function Test-RegisteredPipelineDefinition {
    param(
        [pscustomobject]$Configuration,
        [object[]]$RegisteredDefinitions
    )

    $expected = @($Configuration.pipelineDefinitions.PSObject.Properties)
    $findings = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $expected) {
        $registered = $RegisteredDefinitions | Where-Object { [int]$_.id -eq [int]$entry.Value } | Select-Object -First 1
        if ($null -eq $registered -or [string]$registered.process.yamlFilename -cne $entry.Name) {
            $findings.Add([pscustomobject]@{ yamlPath = $entry.Name; definitionId = $entry.Value; status = 'missing-or-path-mismatch' })
        }
    }

    return @($findings)
}

function Get-RegisteredPipelineDefinition {
    param([pscustomobject]$Configuration)

    $commandResult = Invoke-PipelineDefinitionListCommand -Configuration $Configuration
    if ($commandResult.exitCode -ne 0) {
        throw 'Pipeline definition verification failed without exposing credentials.'
    }

    try {
        $response = ($commandResult.output -join [Environment]::NewLine) | ConvertFrom-Json -Depth 100
        return @($response.value)
    }
    catch {
        throw 'Pipeline definition verification returned an invalid response without exposing command output.'
    }
}

function Invoke-PipelineDefinitionListCommand {
    param([pscustomobject]$Configuration)

    $arguments = @(
        'devops', 'invoke',
        '--organization', [string]$Configuration.organizationUrl,
        '--area', 'build',
        '--resource', 'definitions',
        '--route-parameters', "project=$($Configuration.project)",
        '--query-parameters', 'includeAllProperties=true',
        '--api-version', '7.1',
        '--output', 'json'
    )
    return Invoke-AzureDevOpsCliCommand -Arguments $arguments
}

function Invoke-AzureDevOpsCliCommand {
    param([string[]]$Arguments)

    $output = & az @Arguments 2>&1
    return [pscustomobject]@{
        exitCode = $LASTEXITCODE
        output = @($output)
    }
}

function Start-PipelineRegistration {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$InputPath,
        [string]$ResultPath,
        [switch]$ApplyChanges,
        [switch]$VerifyDefinitions
    )

    if ($ApplyChanges -and $VerifyDefinitions) {
        throw 'Apply and Verify are mutually exclusive operations.'
    }

    $repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $configuration = Get-Content -LiteralPath (Resolve-Path -LiteralPath $InputPath) -Raw | ConvertFrom-Json -Depth 100
    $contracts = Get-Content -LiteralPath (Join-Path $repositoryRoot '.azuredevops\pipelines\config\workflow-contracts.json') -Raw | ConvertFrom-Json -Depth 100
    $plan = Get-PipelineRegistrationPlan -Configuration $configuration -ContractsDocument $contracts -RepositoryRoot $repositoryRoot
    $plan | Select-Object source, yamlPath, name, definitionId, action | Format-Table -AutoSize

    if ($VerifyDefinitions) {
        if (@($plan | Where-Object action -ne 'verify').Count -ne 0) {
            throw 'Verification requires a captured definition ID for every contracted YAML path.'
        }
        $findings = @(Test-RegisteredPipelineDefinition $configuration (Get-RegisteredPipelineDefinition $configuration))
        if ($findings.Count -ne 0) {
            $findings | Format-Table -AutoSize
            throw "Pipeline registration verification found $($findings.Count) missing or mismatched definition(s)."
        }
        Write-Information 'All 19 registered pipeline definitions map to their configured YAML paths.' -InformationAction Continue
        return $findings
    }

    if (-not $ApplyChanges) {
        Write-Information 'Dry run only. No Azure DevOps calls were made. Re-run with -Apply after administrator review.' -InformationAction Continue
        return $plan
    }
    if ([string]::IsNullOrWhiteSpace($ResultPath)) {
        throw 'OutputPath is required with -Apply so registered definition IDs are captured outside the example configuration.'
    }
    $examplePath = [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.azuredevops\pipelines\config\pipeline-registration.example.json'))
    if ([IO.Path]::GetFullPath($ResultPath) -ieq $examplePath) {
        throw 'OutputPath must not overwrite the checked-in example configuration.'
    }

    if (-not $PSCmdlet.ShouldProcess($configuration.project, 'Register 19 Azure DevOps pipeline definitions')) {
        return $plan
    }
    $existingDefinitions = @(Get-RegisteredPipelineDefinition $configuration)
    $capturedFindings = @(Test-RegisteredPipelineDefinition $configuration $existingDefinitions |
        Where-Object { $null -ne $_.definitionId })
    if ($capturedFindings.Count -ne 0) {
        throw "Captured pipeline definition verification found $($capturedFindings.Count) missing or mismatched definition(s)."
    }
    $registeredIds = Invoke-PipelineRegistrationPlan -Configuration $configuration -Plan $plan -ExistingDefinitions $existingDefinitions -ResultPath $ResultPath
    return $registeredIds
}

if ($MyInvocation.InvocationName -ne '.') {
    if ([string]::IsNullOrWhiteSpace($ConfigurationPath)) {
        throw 'ConfigurationPath is required. Use an untracked file containing approved organization identifiers.'
    }
    Start-PipelineRegistration -InputPath $ConfigurationPath -ResultPath $OutputPath -ApplyChanges:$Apply -VerifyDefinitions:$Verify | Out-Null
}