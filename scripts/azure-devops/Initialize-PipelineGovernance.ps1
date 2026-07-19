[CmdletBinding()]
param(
    [string]$ConfigurationPath,
    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:PolicyTypeIds = @{
    BuildValidation = '0609b952-1397-4640-95ec-e00a01b2c241'
    MinimumReviewers = 'fa4e907d-c16b-4a4c-9dfa-4906e5d171dd'
    CommentRequirements = 'c6a1889d-b943-4856-b76f-9e46bb6b0df2'
}

function Assert-GovernanceConfiguration {
    param(
        [pscustomobject]$Configuration,
        [pscustomobject]$ContractsDocument,
        [string]$RepositoryRoot
    )

    $requiredProperties = @(
        'organizationUrl',
        'project',
        'repositoryId',
        'pipelineDefinitions',
        'retention',
        'documentationEnvironment',
        'applicationEnvironment',
        'serviceConnections',
        'variableGroups',
        'permissionUpdates'
    )

    foreach ($property in $requiredProperties) {
        if ($Configuration.PSObject.Properties.Name -notcontains $property) {
            throw "Governance configuration is missing '$property'."
        }
    }

    foreach ($property in @('organizationUrl', 'project', 'repositoryId')) {
        if ([string]::IsNullOrWhiteSpace($Configuration.$property)) {
            throw "Governance configuration requires a nonempty '$property'."
        }
    }

    if ($null -ne $ContractsDocument) {
        $contracts = @($ContractsDocument.contracts)
        $expectedTargets = @($contracts.target | Sort-Object)
        $configuredTargets = @($Configuration.pipelineDefinitions.PSObject.Properties.Name | Sort-Object)
        if ($contracts.Count -ne 19 -or $ContractsDocument.requiredWorkflowCount -ne 19) {
            throw "Governance requires exactly 19 workflow contracts; found $($contracts.Count)."
        }
        if ((ConvertTo-ComparableJson $configuredTargets) -ne (ConvertTo-ComparableJson $expectedTargets)) {
            throw 'Pipeline definitions must contain exactly the 19 contracted YAML paths.'
        }

        $definitionIds = @($Configuration.pipelineDefinitions.PSObject.Properties | ForEach-Object {
            $definitionId = 0
            if ($null -eq $_.Value -or -not [int]::TryParse([string]$_.Value, [ref]$definitionId) -or $definitionId -le 0) {
                throw "Pipeline definition ID for '$($_.Name)' must be a positive integer."
            }
            $definitionId
        })
        if (@($definitionIds | Sort-Object -Unique).Count -ne 19) {
            throw 'Pipeline definition IDs must be unique across all 19 YAML paths.'
        }

        $protectedResources = @(
            @($Configuration.serviceConnections) | ForEach-Object { [pscustomobject]@{ resourceType = 'endpoint'; value = $_ } }
            @($Configuration.variableGroups) | ForEach-Object { [pscustomobject]@{ resourceType = 'variablegroup'; value = $_ } }
            @($Configuration.applicationEnvironment, $Configuration.documentationEnvironment) | ForEach-Object { [pscustomobject]@{ resourceType = 'environment'; value = $_ } }
        )
        $protectedResourceKeys = [System.Collections.Generic.List[string]]::new()
        foreach ($protectedResource in $protectedResources) {
            $resource = $protectedResource.value
            if ([string]::IsNullOrWhiteSpace([string]$resource.id) -or @($resource.pipelineIds).Count -eq 0) {
                throw 'Every protected resource requires an ID and at least one explicitly authorized pipeline ID.'
            }
            $resourceKey = "$($protectedResource.resourceType):$($resource.id)"
            if ($protectedResourceKeys -contains $resourceKey) {
                throw "Protected resource IDs must be unique within each resource collection: $($resource.id)"
            }
            $protectedResourceKeys.Add($resourceKey)
            if (@($resource.pipelineIds | Sort-Object -Unique).Count -ne @($resource.pipelineIds).Count) {
                throw "Protected resource '$($resource.id)' contains duplicate pipeline IDs."
            }
            foreach ($pipelineId in @($resource.pipelineIds)) {
                if ([int]$pipelineId -notin $definitionIds) {
                    throw "Protected resource '$($resource.id)' references an unknown pipeline definition ID: $pipelineId"
                }
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($RepositoryRoot)) {
            foreach ($contract in $contracts) {
                $pipelinePath = Join-Path $RepositoryRoot ($contract.target -replace '/', '\')
                if (-not (Test-Path -LiteralPath $pipelinePath -PathType Leaf)) {
                    throw "Contracted pipeline YAML is missing: $($contract.target)"
                }

                $pipelineText = Get-Content -LiteralPath $pipelinePath -Raw
                foreach ($schedule in @($contract.triggers.schedules)) {
                    $escapedCron = [regex]::Escape([string]$schedule.cronUtc)
                    if ($pipelineText -notmatch "(?m)^\s*-\s+cron:\s*[\x22\x27]?$escapedCron[\x22\x27]?\s*$" -or $pipelineText -notmatch '(?m)^\s+always:\s*true\s*$') {
                        throw "Pipeline schedule does not match its UTC always-run contract: $($contract.target)"
                    }
                }
            }
        }
    }

    if ($Configuration.retention.runDays -lt 30 -or $Configuration.retention.pullRequestRunDays -lt 30) {
        throw 'Run and pull request retention must be at least 30 days.'
    }

    foreach ($property in @('id', 'name', 'pipelineIds', 'exclusiveLockCheckTypeId')) {
        if ([string]::IsNullOrWhiteSpace($Configuration.documentationEnvironment.$property)) {
            throw "The documentation environment '$property' is required."
        }
    }

    foreach ($property in @('id', 'name', 'pipelineIds')) {
        if ([string]::IsNullOrWhiteSpace($Configuration.applicationEnvironment.$property)) {
            throw "The application environment '$property' is required."
        }
    }

    if (@($Configuration.serviceConnections).Count -eq 0) {
        throw 'At least one explicitly scoped service connection is required.'
    }

    if (@($Configuration.variableGroups).Count -eq 0) {
        throw 'At least one explicitly scoped variable group is required for administrative and integrity inputs.'
    }

    if (@($Configuration.permissionUpdates).Count -eq 0) {
        throw 'Explicit repository and pull request permission updates are required.'
    }
}

function Get-BranchScope {
    param([pscustomobject]$Configuration)

    return @{
        repositoryId = $Configuration.repositoryId
        refName = 'refs/heads/main'
        matchKind = 'Exact'
    }
}

function Get-ProtectedPipelineResource {
    param([pscustomobject]$Configuration)

    $resources = [System.Collections.Generic.List[object]]::new()
    foreach ($resource in @($Configuration.serviceConnections)) {
        $resources.Add([pscustomobject]@{ resourceType = 'endpoint'; id = [string]$resource.id; pipelineIds = @($resource.pipelineIds) })
    }
    foreach ($resource in @($Configuration.variableGroups)) {
        $resources.Add([pscustomobject]@{ resourceType = 'variablegroup'; id = [string]$resource.id; pipelineIds = @($resource.pipelineIds) })
    }
    foreach ($resource in @($Configuration.applicationEnvironment, $Configuration.documentationEnvironment)) {
        $resources.Add([pscustomobject]@{ resourceType = 'environment'; id = [string]$resource.id; pipelineIds = @($resource.pipelineIds) })
    }
    return @($resources)
}

function Get-DesiredPolicyConfiguration {
    param(
        [pscustomobject]$Configuration,
        [pscustomobject]$ContractsDocument
    )

    $scope = Get-BranchScope $Configuration
    $policies = [System.Collections.Generic.List[object]]::new()
    $pullRequestContracts = @($ContractsDocument.contracts | Where-Object { @($_.triggers.pullRequest) -contains 'main' })

    foreach ($contract in $pullRequestContracts) {
        $definitionProperty = $Configuration.pipelineDefinitions.PSObject.Properties[$contract.target]
        if ($null -eq $definitionProperty -or $null -eq $definitionProperty.Value) {
            throw "Pipeline definition ID is required for '$($contract.target)'."
        }

        $policies.Add([pscustomobject]@{
            key = "build:$($contract.target)"
            typeId = $script:PolicyTypeIds.BuildValidation
            isEnabled = $true
            isBlocking = $true
            settings = @{
                buildDefinitionId = [int]$definitionProperty.Value
                displayName = $contract.source
                manualQueueOnly = $false
                queueOnSourceUpdateOnly = $false
                validDuration = 0
                scope = @($scope)
            }
        })
    }

    $policies.Add([pscustomobject]@{
        key = 'reviewers:minimum-one'
        typeId = $script:PolicyTypeIds.MinimumReviewers
        isEnabled = $true
        isBlocking = $true
        settings = @{
            minimumApproverCount = 1
            creatorVoteCounts = $false
            allowDownvotes = $true
            resetOnSourcePush = $true
            blockLastPusherVote = $true
            scope = @($scope)
        }
    })

    $policies.Add([pscustomobject]@{
        key = 'comments:resolved'
        typeId = $script:PolicyTypeIds.CommentRequirements
        isEnabled = $true
        isBlocking = $true
        settings = @{ scope = @($scope) }
    })

    return @($policies)
}

function ConvertTo-ComparableJson {
    param([object]$Value)

    function ConvertTo-CanonicalValue {
        param([object]$InputValue)

        if ($null -eq $InputValue -or $InputValue -is [string] -or $InputValue.GetType().IsPrimitive) {
            return $InputValue
        }

        if ($InputValue -is [System.Collections.IDictionary]) {
            $ordered = [ordered]@{}
            foreach ($key in @($InputValue.Keys | Sort-Object)) {
                $ordered[$key] = ConvertTo-CanonicalValue $InputValue[$key]
            }
            return [pscustomobject]$ordered
        }

        if ($InputValue -is [System.Collections.IEnumerable]) {
            return @($InputValue | ForEach-Object { ConvertTo-CanonicalValue $_ })
        }

        $canonical = [ordered]@{}
        foreach ($property in @($InputValue.PSObject.Properties | Sort-Object Name)) {
            $canonical[$property.Name] = ConvertTo-CanonicalValue $property.Value
        }
        return [pscustomobject]$canonical
    }

    return (ConvertTo-CanonicalValue $Value) | ConvertTo-Json -Depth 100 -Compress
}

function Test-PolicyEquivalent {
    param(
        [pscustomobject]$Existing,
        [pscustomobject]$Desired
    )

    if ($Existing.isEnabled -ne $Desired.isEnabled -or $Existing.isBlocking -ne $Desired.isBlocking) {
        return $false
    }

    return (ConvertTo-ComparableJson $Existing.settings) -eq (ConvertTo-ComparableJson $Desired.settings)
}

function Find-ExistingPolicy {
    param(
        [object[]]$ExistingPolicies,
        [pscustomobject]$Desired
    )

    $sameType = @($ExistingPolicies | Where-Object { $_.type.id -eq $Desired.typeId })
    if ($Desired.key -like 'build:*') {
        return $sameType | Where-Object {
            $_.settings.buildDefinitionId -eq $Desired.settings.buildDefinitionId
        } | Select-Object -First 1
    }

    return $sameType | Select-Object -First 1
}

function Get-GovernancePlan {
    param(
        [pscustomobject]$Configuration,
        [pscustomobject]$ContractsDocument,
        [object[]]$ExistingPolicies = @(),
        [pscustomobject]$ExistingRetention = $null,
        [object[]]$ExistingChecks = @(),
        [object[]]$ExistingPipelinePermissions = @(),
        [object[]]$ExistingSecurityPermissions = @()
    )

    Assert-GovernanceConfiguration $Configuration -ContractsDocument $ContractsDocument
    $operations = [System.Collections.Generic.List[object]]::new()

    foreach ($desired in Get-DesiredPolicyConfiguration $Configuration $ContractsDocument) {
        $existing = Find-ExistingPolicy $ExistingPolicies $desired
        $action = if ($null -eq $existing) { 'create' } elseif (Test-PolicyEquivalent $existing $desired) { 'none' } else { 'update' }
        $existingId = if ($null -eq $existing) { $null } else { $existing.id }
        $operations.Add([pscustomobject]@{ category = 'branch-policy'; key = $desired.key; action = $action; existingId = $existingId; desired = $desired })
    }

    $retentionEquivalent =
        $null -ne $ExistingRetention -and
        $ExistingRetention.daysToKeep -ge $Configuration.retention.runDays -and
        $ExistingRetention.daysToKeepPullRequestRuns -ge $Configuration.retention.pullRequestRunDays
    $operations.Add([pscustomobject]@{
        category = 'retention'
        key = 'project-build-retention'
        action = if ($retentionEquivalent) { 'none' } else { 'update' }
        desired = @{ daysToKeep = [int]$Configuration.retention.runDays; daysToKeepPullRequestRuns = [int]$Configuration.retention.pullRequestRunDays }
    })

    $environment = $Configuration.documentationEnvironment
    $desiredCheck = @{
        type = @{ id = $environment.exclusiveLockCheckTypeId }
        resource = @{ type = 'environment'; id = [string]$environment.id; name = $environment.name }
        settings = @{ timeout = [int]$environment.timeoutMinutes }
    }
    $existingLock = $ExistingChecks | Where-Object {
        $_.type.id -eq $environment.exclusiveLockCheckTypeId -and
        $_.resource.id -eq $environment.id
    } | Select-Object -First 1
    $lockEquivalent =
        $null -ne $existingLock -and
        (ConvertTo-ComparableJson $existingLock.settings) -eq (ConvertTo-ComparableJson $desiredCheck.settings)
    $operations.Add([pscustomobject]@{
        category = 'environment-check'
        key = 'documentation-exclusive-lock'
        action = if ($null -eq $existingLock) { 'create' } elseif ($lockEquivalent) { 'none' } else { 'update' }
        existingId = if ($null -eq $existingLock) { $null } else { $existingLock.id }
        desired = $desiredCheck
    })

    foreach ($resource in Get-ProtectedPipelineResource $Configuration) {
        $existingPermission = $ExistingPipelinePermissions | Where-Object { $_.resourceType -eq $resource.resourceType -and $_.resourceId -eq $resource.id } | Select-Object -First 1
        $authorizedIds = if ($null -eq $existingPermission) {
            @()
        }
        else {
            @($existingPermission.pipelines | Where-Object authorized | ForEach-Object { [int]$_.id })
        }
        $desiredIds = @($resource.pipelineIds | ForEach-Object { [int]$_ } | Sort-Object -Unique)
        $isEquivalent =
            $null -ne $existingPermission -and
            $existingPermission.allPipelines.authorized -eq $false -and
            (ConvertTo-ComparableJson @($authorizedIds | Sort-Object -Unique)) -eq (ConvertTo-ComparableJson $desiredIds)
        $operations.Add([pscustomobject]@{
            category = 'pipeline-permission'
            key = "$($resource.resourceType):$($resource.id)"
            action = if ($isEquivalent) { 'none' } else { 'update' }
            desired = @{
                resourceType = $resource.resourceType
                resourceId = $resource.id
                allPipelines = @{ authorized = $false }
                pipelines = @($desiredIds | ForEach-Object { @{ id = $_; authorized = $true } })
            }
        })
    }

    foreach ($permission in @($Configuration.permissionUpdates)) {
        $permissionKey = "$($permission.namespaceId):$($permission.subject):$($permission.token)"
        $existingPermission = $ExistingSecurityPermissions | Where-Object key -eq $permissionKey | Select-Object -First 1
        $isEquivalent =
            $null -ne $existingPermission -and
            [int64]$existingPermission.allow -eq [int64]$permission.allowBit -and
            [int64]$existingPermission.deny -eq [int64]$permission.denyBit
        $operations.Add([pscustomobject]@{
            category = 'security-permission'
            key = $permissionKey
            action = if ($isEquivalent) { 'none' } else { 'verify-or-update' }
            desired = $permission
        })
    }

    return @($operations)
}

function Invoke-AzDevOpsCommand {
    param([string[]]$Arguments)

    $output = & az @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Azure DevOps CLI command failed without exposing credentials: az $($Arguments[0..2] -join ' ') ..."
    }

    if ([string]::IsNullOrWhiteSpace(($output -join ''))) {
        return $null
    }

    return ($output -join [Environment]::NewLine) | ConvertFrom-Json -Depth 100
}

function Invoke-JsonFileCommand {
    param(
        [string[]]$Arguments,
        [object]$Body
    )

    $temporaryFile = New-TemporaryFile
    try {
        $Body | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $temporaryFile -Encoding utf8NoBOM
        Invoke-AzDevOpsCommand ($Arguments + @('--in-file', $temporaryFile.FullName, '--output', 'json'))
    }
    finally {
        Remove-Item -LiteralPath $temporaryFile -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-GovernancePlan {
    param(
        [pscustomobject]$Configuration,
        [object[]]$Operations
    )

    foreach ($operation in $Operations | Where-Object action -ne 'none') {
        switch ($operation.category) {
            'branch-policy' {
                $body = @{
                    isEnabled = $operation.desired.isEnabled
                    isBlocking = $operation.desired.isBlocking
                    type = @{ id = $operation.desired.typeId }
                    settings = $operation.desired.settings
                }
                $arguments = @('devops', 'invoke', '--organization', $Configuration.organizationUrl, '--area', 'policy', '--resource', 'configurations', '--route-parameters', "project=$($Configuration.project)", '--api-version', '7.1', '--http-method', $(if ($operation.action -eq 'create') { 'POST' } else { 'PUT' }))
                if ($operation.action -eq 'update') {
                    $arguments += @('configurationId=' + $operation.existingId)
                }
                Invoke-JsonFileCommand $arguments $body | Out-Null
            }
            'retention' {
                Invoke-JsonFileCommand @('devops', 'invoke', '--organization', $Configuration.organizationUrl, '--area', 'build', '--resource', 'retentionSettings', '--route-parameters', "project=$($Configuration.project)", '--api-version', '7.1-preview.1', '--http-method', 'PUT') $operation.desired | Out-Null
            }
            'environment-check' {
                $arguments = @('devops', 'invoke', '--organization', $Configuration.organizationUrl, '--area', 'pipelineschecks', '--resource', 'configurations', '--route-parameters', "project=$($Configuration.project)", '--api-version', '7.1-preview.1', '--http-method', $(if ($operation.action -eq 'create') { 'POST' } else { 'PATCH' }))
                if ($operation.action -eq 'update') {
                    $arguments += @('id=' + $operation.existingId)
                }
                Invoke-JsonFileCommand $arguments $operation.desired | Out-Null
            }
            'pipeline-permission' {
                Invoke-JsonFileCommand @('devops', 'invoke', '--organization', $Configuration.organizationUrl, '--area', 'pipelines', '--resource', 'pipelinePermissions', '--route-parameters', "project=$($Configuration.project)", "resourceType=$($operation.desired.resourceType)", "resourceId=$($operation.desired.resourceId)", '--api-version', '7.1-preview.1', '--http-method', 'PATCH') $operation.desired | Out-Null
            }
            'security-permission' {
                $permission = $operation.desired
                Invoke-AzDevOpsCommand @('devops', 'security', 'permission', 'update', '--organization', $Configuration.organizationUrl, '--id', $permission.namespaceId, '--subject', $permission.subject, '--token', $permission.token, '--allow-bit', [string]$permission.allowBit, '--deny-bit', [string]$permission.denyBit, '--output', 'json') | Out-Null
            }
        }
    }
}

function Get-CurrentGovernanceState {
    param([pscustomobject]$Configuration)

    $policies = Invoke-AzDevOpsCommand @('devops', 'invoke', '--organization', $Configuration.organizationUrl, '--area', 'policy', '--resource', 'configurations', '--route-parameters', "project=$($Configuration.project)", '--api-version', '7.1', '--http-method', 'GET', '--output', 'json')
    $retention = Invoke-AzDevOpsCommand @('devops', 'invoke', '--organization', $Configuration.organizationUrl, '--area', 'build', '--resource', 'retentionSettings', '--route-parameters', "project=$($Configuration.project)", '--api-version', '7.1-preview.1', '--http-method', 'GET', '--output', 'json')
    $checks = Invoke-AzDevOpsCommand @('devops', 'invoke', '--organization', $Configuration.organizationUrl, '--area', 'pipelineschecks', '--resource', 'configurations', '--route-parameters', "project=$($Configuration.project)", '--query-parameters', "resourceType=environment", "resourceId=$($Configuration.documentationEnvironment.id)", '--api-version', '7.1-preview.1', '--http-method', 'GET', '--output', 'json')
    $permissions = foreach ($resource in Get-ProtectedPipelineResource $Configuration) {
        $permission = Invoke-AzDevOpsCommand @('devops', 'invoke', '--organization', $Configuration.organizationUrl, '--area', 'pipelines', '--resource', 'pipelinePermissions', '--route-parameters', "project=$($Configuration.project)", "resourceType=$($resource.resourceType)", "resourceId=$($resource.id)", '--api-version', '7.1-preview.1', '--http-method', 'GET', '--output', 'json')
        if ($null -ne $permission) {
            $permission | Add-Member -NotePropertyName resourceType -NotePropertyValue $resource.resourceType -Force
            $permission | Add-Member -NotePropertyName resourceId -NotePropertyValue $resource.id -Force
            $permission
        }
    }
    $securityPermissions = foreach ($permission in @($Configuration.permissionUpdates)) {
        $result = Invoke-AzDevOpsCommand @('devops', 'security', 'permission', 'show', '--organization', $Configuration.organizationUrl, '--id', $permission.namespaceId, '--subject', $permission.subject, '--token', $permission.token, '--output', 'json')
        $aceProperty = $result.acesDictionary.PSObject.Properties[$permission.subject]
        if ($null -ne $aceProperty) {
            [pscustomobject]@{
                key = "$($permission.namespaceId):$($permission.subject):$($permission.token)"
                allow = [int64]$aceProperty.Value.allow
                deny = [int64]$aceProperty.Value.deny
            }
        }
    }

    return [pscustomobject]@{
        policies = @($policies.value)
        retention = $retention
        checks = @($checks.value)
        pipelinePermissions = @($permissions)
        securityPermissions = @($securityPermissions)
    }
}

function Start-PipelineGovernanceInitialization {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$InputPath,
        [switch]$ApplyChanges
    )

    $resolvedInput = Resolve-Path -LiteralPath $InputPath
    $configuration = Get-Content -LiteralPath $resolvedInput -Raw | ConvertFrom-Json -Depth 100
    $repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $contractPath = Join-Path $repositoryRoot '.azuredevops\pipelines\config\workflow-contracts.json'
    $contracts = Get-Content -LiteralPath $contractPath -Raw | ConvertFrom-Json -Depth 100
    Assert-GovernanceConfiguration $configuration -ContractsDocument $contracts -RepositoryRoot $repositoryRoot
    $state = Get-CurrentGovernanceState $configuration
    $plan = Get-GovernancePlan $configuration $contracts $state.policies $state.retention $state.checks $state.pipelinePermissions $state.securityPermissions

    $plan | Select-Object category, key, action | Format-Table -AutoSize
    if ($ApplyChanges) {
        if ($PSCmdlet.ShouldProcess($configuration.project, 'Apply Azure DevOps pipeline governance plan')) {
            Invoke-GovernancePlan $configuration $plan
            Write-Information 'Governance initialization applied. Run Test-PipelineGovernance.ps1 to verify the resulting state.' -InformationAction Continue
        }
    }
    else {
        Write-Information 'Dry run only. Re-run with -Apply after administrator review.' -InformationAction Continue
    }

    return $plan
}

if ($MyInvocation.InvocationName -ne '.') {
    if ([string]::IsNullOrWhiteSpace($ConfigurationPath)) {
        throw 'ConfigurationPath is required. Use an untracked file containing approved organization identifiers.'
    }

    Start-PipelineGovernanceInitialization -InputPath $ConfigurationPath -ApplyChanges:$Apply | Out-Null
}
