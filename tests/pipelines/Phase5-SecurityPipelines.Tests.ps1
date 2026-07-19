$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$pipelineRoot = Join-Path $repositoryRoot '.azuredevops\pipelines'
$codeql = Get-Content -LiteralPath (Join-Path $pipelineRoot 'sast-codeql.yml') -Raw
$dependency = Get-Content -LiteralPath (Join-Path $pipelineRoot 'sca-dependency-scanning.yml') -Raw
$msdo = Get-Content -LiteralPath (Join-Path $pipelineRoot 'msdo-security-devops.yml') -Raw
$iacMsdo = Get-Content -LiteralPath (Join-Path $pipelineRoot 'iacs-microsoft-security-devops.yml') -Raw

Describe 'GHAzDO CodeQL pipeline contract' {
    It 'runs on main and the exact Tuesday schedule without a YAML pull request trigger' {
        $codeql | Should Match '(?ms)^trigger:.*?include:\s*\r?\n\s+- main'
        $codeql | Should Match "cron:\s*'26 8 \* \* 2'"
        $codeql | Should Match 'always:\s+true'
        $codeql | Should Not Match '(?m)^pr:'
    }

    It 'uses independent native CodeQL jobs for the supported language set' {
        $codeql | Should Match '(?ms)strategy:\s*\r?\n\s+matrix:'
        $codeql | Should Match 'maxParallel:\s+3'
        $codeql | Should Match 'AdvancedSecurity-Codeql-Init@1'
        $codeql | Should Match 'AdvancedSecurity-Codeql-Analyze@1'
        $codeql | Should Match 'codeqlLanguage:\s+csharp'
        $codeql | Should Match 'codeqlLanguage:\s+python'
        $codeql | Should Match 'codeqlLanguage:\s+javascript'
        $codeql | Should Match 'buildtype:\s+none'
        $codeql | Should Match 'querysuite:\s+security-and-quality'
    }

    It 'does not route native GHAzDO findings through CodeAnalysisLogs' {
        $codeql | Should Not Match 'publish-sarif\.yml'
        $codeql | Should Not Match 'CodeAnalysisLogs'
        $codeql | Should Not Match 'PublishBuildArtifacts'
        $codeql | Should Not Match 'AdvancedSecurity-Publish@1'
    }
}

Describe 'GHAzDO dependency scanning pipeline contract' {
    It 'runs only through Azure Repos branch policy and fails clearly without pull request variables' {
        $dependency | Should Match '(?m)^trigger:\s+none\s*$'
        $dependency | Should Not Match '(?m)^pr:'
        $dependency | Should Match "BUILD_REASON -ne 'PullRequest'"
        foreach ($name in 'PullRequestId', 'SourceCommitId', 'TargetBranch', 'Build.Repository.ID') {
            $dependency | Should Match ([regex]::Escape($name))
        }
    }

    It 'publishes native dependency alerts and applies deterministic resolved-package admission' {
        $dependency | Should Match 'AdvancedSecurity-Dependency-Scanning@1'
        $dependency | Should Match 'Get-ResolvedNuGetGraph\.ps1'
        $dependency | Should Match 'Test-DependencyChanges\.ps1'
        $dependency | Should Match 'Get-NuGetRegistrationRecord'
        $dependency | Should Match 'Invoke-DependencyAdmission'
        $dependency | Should Match 'ConvertTo-DependencyMarkdown'
        $dependency | Should Match 'dependencyAdmissionExitCode'
        $dependency | Should Match 'dependency-admission-json'
        $dependency | Should Match 'dependency-admission-markdown'
        $dependency | Should Not Match '(?m)^\s+exit 1\s*$'
    }

    It 'persists checkout credentials for the explicit target and source revision fetches' {
        $dependency | Should Match '(?ms)- checkout: self\s+clean: true\s+fetchDepth: 0\s+persistCredentials: true'
        $dependency | Should Match 'git fetch --no-tags origin "\$env:SYSTEM_PULLREQUEST_TARGETBRANCH"'
        $dependency | Should Match 'git fetch --no-tags origin "\$env:SYSTEM_PULLREQUEST_SOURCECOMMITID"'
    }

    It 'skips artifact publishers when manual context validation fails before evidence exists' {
        $contextGate = $dependency.IndexOf('displayName: Require branch-policy pull request context')
        $evidenceEvaluation = $dependency.IndexOf('displayName: Evaluate changed resolved dependencies')
        $jsonPublisher = $dependency.IndexOf('displayName: Publish dependency admission JSON')
        $markdownPublisher = $dependency.IndexOf('displayName: Publish dependency admission Markdown')

        $contextGate | Should BeGreaterThan -1
        $evidenceEvaluation | Should BeGreaterThan -1
        $jsonPublisher | Should BeGreaterThan -1
        $markdownPublisher | Should BeGreaterThan -1
        $contextGate | Should BeLessThan $evidenceEvaluation
        $evidenceEvaluation | Should BeLessThan $jsonPublisher
        $evidenceEvaluation | Should BeLessThan $markdownPublisher
        $dependency | Should Match "condition: and\(succeededOrFailed\(\), eq\(variables\['dependencyAdmissionJsonReady'\], 'true'\)\)"
        $dependency | Should Match "condition: and\(succeededOrFailed\(\), eq\(variables\['dependencyAdmissionMarkdownReady'\], 'true'\)\)"
        $dependency | Should Not Match '(?m)^\s+condition:\s+succeededOrFailed\(\)\s*$'
    }

    It 'publishes rejected dependency evidence before enforcing the final verdict' {
        $jsonReady = $dependency.IndexOf('variable=dependencyAdmissionJsonReady]true')
        $markdownReady = $dependency.IndexOf('variable=dependencyAdmissionMarkdownReady]true')
        $exitCode = $dependency.IndexOf('variable=dependencyAdmissionExitCode]$exitCode')
        $jsonPublisher = $dependency.IndexOf('displayName: Publish dependency admission JSON')
        $markdownPublisher = $dependency.IndexOf('displayName: Publish dependency admission Markdown')
        $verdict = $dependency.IndexOf('displayName: Enforce dependency admission verdict')

        $jsonReady | Should BeGreaterThan -1
        $markdownReady | Should BeGreaterThan -1
        $exitCode | Should BeGreaterThan -1
        $jsonPublisher | Should BeGreaterThan -1
        $markdownPublisher | Should BeGreaterThan -1
        $verdict | Should BeGreaterThan -1
        $jsonReady | Should BeLessThan $jsonPublisher
        $markdownReady | Should BeLessThan $markdownPublisher
        $exitCode | Should BeLessThan $jsonPublisher
        $jsonPublisher | Should BeLessThan $verdict
        $markdownPublisher | Should BeLessThan $verdict
        $dependency | Should Match ([regex]::Escape('$exitCode = if ($result.passed) { 0 } else { 1 }'))
        $dependency | Should Match ([regex]::Escape("if ('`$(dependencyAdmissionExitCode)' -ne '0')"))
    }

    It 'keeps the intended pull request evidence and verdict sequence unchanged' {
        $dependency | Should Match "BUILD_REASON -ne 'PullRequest'"
        $dependency | Should Match 'displayName: Publish marker-owned pull request summary'
        $dependency | Should Match 'artifact:\s+dependency-admission-json'
        $dependency | Should Match 'artifact:\s+dependency-admission-markdown'
        $dependency | Should Match "throw 'Changed dependency admission failed\. Review the published JSON, Markdown, and pull request summary\.'"
    }

    It 'uses the marker-owned comment helper and maps the system token only to that step' {
        $dependency | Should Match 'Set-PullRequestComment\.ps1'
        ([regex]::Matches($dependency, 'SYSTEM_ACCESSTOKEN:\s+\$\(System\.AccessToken\)')).Count | Should Be 1
        $dependency | Should Match '(?ms)displayName: Publish marker-owned pull request summary\s+env:\s+SYSTEM_ACCESSTOKEN:\s+\$\(System\.AccessToken\)'
        $dependency | Should Not Match 'CodeAnalysisLogs'
        $dependency | Should Not Match 'publish-sarif\.yml'
        $dependency | Should Not Match 'AdvancedSecurity-Publish@1'
    }

    It 'inherits the moderate severity SPDX allowlist and unknown-license warning gate from the helper' {
        $helper = Get-Content -LiteralPath (Join-Path $repositoryRoot 'scripts\dependencies\Test-DependencyChanges.ps1') -Raw
        $helper | Should Match "AllowedLicenses = @\('MIT', 'Apache-2\.0', 'GPL-3\.0'\)"
        $helper | Should Match '\$_ -in 1, 2, 3'
        $helper | Should Match "License metadata is unknown\."
        $helper | Should Match '\$licenseFailure = -not \$licenseWarning'
        $helper | Should Match 'failed = \$vulnerabilityFailure -or \$licenseFailure'
    }
}

Describe 'Microsoft Security DevOps pipeline contracts' {
    It 'preserves exact main schedules and leaves pull request execution to branch policy' {
        $msdo | Should Match "cron:\s*'42 13 \* \* 5'"
        $iacMsdo | Should Match "cron:\s*'15 03 \* \* 5'"
        foreach ($pipeline in $msdo, $iacMsdo) {
            $pipeline | Should Match '(?ms)^trigger:.*?include:\s*\r?\n\s+- main'
            $pipeline | Should Match 'always:\s+true'
            $pipeline | Should Not Match '(?m)^pr:'
        }
    }

    It 'uses the supported general tool configuration on Windows with product publication' {
        $msdo | Should Match 'vmImage:\s+windows-latest'
        $msdo | Should Match 'MicrosoftSecurityDevOps@1'
        $msdo | Should Match 'tools:\s+bandit,checkov,templateanalyzer,terrascan,trivy'
        $msdo | Should Match 'publish:\s+true'
    }

    It 'limits IaC checkout scope and uses the native IaC category' {
        $iacMsdo | Should Match 'MicrosoftSecurityDevOps@1'
        $iacMsdo | Should Match 'categories:\s+IaC'
        foreach ($scope in 'terraform', 'blueprints', 'manifests') {
            $iacMsdo | Should Match "(?m)^\s+$scope\s*$"
        }
    }

    It 'publishes each MSDO result set to Advanced Security after native publication' {
        foreach ($pipeline in $msdo, $iacMsdo) {
            $msdoIndex = $pipeline.IndexOf('MicrosoftSecurityDevOps@1')
            $advancedSecurityIndex = $pipeline.IndexOf('AdvancedSecurity-Publish@1')

            $msdoIndex | Should BeGreaterThan -1
            $advancedSecurityIndex | Should BeGreaterThan $msdoIndex
            @([regex]::Matches($pipeline, 'MicrosoftSecurityDevOps@1')).Count | Should Be 1
            @([regex]::Matches($pipeline, 'AdvancedSecurity-Publish@1')).Count | Should Be 1
            $pipeline | Should Match "SarifsInputDirectory:\s+'\$\(Build\.ArtifactStagingDirectory\)/\.gdn/'"
            $pipeline | Should Match 'publish:\s+true'
            $pipeline | Should Not Match '(?i)Category:\s|EnableRecursiveScanning:\s'
        }
    }

    It 'does not duplicate the native MSDO artifact or route GHAzDO results as generic SARIF' {
        foreach ($pipeline in $msdo, $iacMsdo) {
            $pipeline | Should Not Match 'publish-sarif\.yml'
            $pipeline | Should Not Match 'PublishBuildArtifacts'
            $pipeline | Should Not Match 'AdvancedSecurity-Codeql'
            $pipeline | Should Not Match 'AdvancedSecurity-Dependency'
        }
    }

    It 'contains no fabricated credentials or identifiers' {
        $all = $codeql + $dependency + $msdo + $iacMsdo
        $all | Should Not Match '(?i)(client[_-]?secret|password\s*:|account[_-]?key|sas[_-]?token|pat\s*:|bearer\s+[A-Za-z0-9])'
        $all | Should Not Match '00000000-0000-0000-0000-000000000000'
    }

    It 'routes MSDO SARIF to native CodeAnalysisLogs and Advanced Security code scanning' {
        $routingPath = Join-Path $pipelineRoot 'config\visualization-routing.json'
        $routing = Get-Content -LiteralPath $routingPath -Raw | ConvertFrom-Json -Depth 100
        $route = $routing.routes | Where-Object reportType -eq 'msdo-sarif'
        $sarifScans = $route.destinations | Where-Object name -eq 'sarif-scans-tab'
        $advancedSecurity = $route.destinations | Where-Object name -eq 'repos-advanced-security-code-scanning'

        $route.destination | Should Be 'sarif-scans-tab'
        $route.artifact | Should Be 'CodeAnalysisLogs'
        $sarifScans.artifact | Should Be 'CodeAnalysisLogs'
        $advancedSecurity.task | Should Be 'AdvancedSecurity-Publish@1'
        $route.wikiFallback | Should Be $false
    }
}