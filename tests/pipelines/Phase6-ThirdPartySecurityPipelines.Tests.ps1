$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$pipelineRoot = Join-Path $repositoryRoot '.azuredevops\pipelines'

Describe 'ESLint third-party SAST pipeline contract' {
    $pipeline = Get-Content -LiteralPath (Join-Path $pipelineRoot 'sast-eslint.yml') -Raw

    It 'runs on main and the exact always-on Thursday schedule without a YAML pull request trigger' {
        $pipeline | Should Match '(?ms)^trigger:.*?include:\s*\r?\n\s+- main'
        $pipeline | Should Match "cron:\s*'39 9 \* \* 4'"
        $pipeline | Should Match 'always:\s+true'
        $pipeline | Should Not Match '(?m)^pr:'
    }

    It 'pins and integrity-verifies ESLint and its SARIF formatter' {
        $pipeline | Should Match 'ESLINT_VERSION:\s+8\.10\.0'
        $pipeline | Should Match 'ESLINT_SARIF_FORMATTER_VERSION:\s+3\.1\.0'
        $pipeline | Should Match 'ESLINT_8_10_0_INTEGRITY'
        $pipeline | Should Match 'ESLINT_SARIF_FORMATTER_3_1_0_INTEGRITY'
        $pipeline | Should Match 'ConvertFrom-Json -AsHashtable'
        $pipeline | Should Match 'npm ci --ignore-scripts'
        $pipeline | Should Match "node_modules/@microsoft/eslint-formatter-sarif/sarif\.js"
        $pipeline | Should Match '--format \$sarifFormatter'
        $pipeline | Should Not Match '(?i)(?:eslint|formatter-sarif)@(?:latest|main|master)'
    }

    It 'allows findings but blocks execution and SARIF failures through the shared publisher' {
        $pipeline | Should Match '\$scanExitCode -notin @\(0, 1\)'
        $pipeline | Should Match '(?m)^\s+exit 0\s*$'
        $pipeline | Should Match 'templates/publish-sarif\.yml'
        $pipeline | Should Match 'reportType:\s+third-party-sarif'
        $pipeline | Should Not Match '(?m)^\s*continueOnError:\s*true'
    }

    It 'contains no embedded credentials' {
        $pipeline | Should Not Match '(?i)(password|client-secret|access-token|account-key|sas-token)\s*:'
    }
}

$phase6Contracts = @(
    @{ Name = 'sast-kubesec.yml'; Cron = '18 8 \* \* 6'; Scope = @('manifests/critical-double\.yaml', 'manifests/score-5-pod-serviceaccount\.yaml') },
    @{ Name = 'iacs-checkmarx-kics.yml'; Cron = '15 03 \* \* 5'; Scope = @('terraform:/scan:ro') },
    @{ Name = 'iacs-aquasecurity-tfsec.yml'; Cron = '15 03 \* \* 5'; Scope = @('terraform:/scan:ro') },
    @{ Name = 'cis-anchore-grype.yml'; Cron = '0 1 \* \* 0'; Scope = @('Dockerfile:\s+src/webapp01/Dockerfile', 'buildContext:\s+src/webapp01') },
    @{ Name = 'cis-trivy.yml'; Cron = '0 1 \* \* 0'; Scope = @('Dockerfile:\s+src/webapp01/Dockerfile', 'buildContext:\s+src/webapp01') }
)

Describe 'Remaining Phase 6 pipeline contracts' {
    foreach ($contract in $phase6Contracts) {
        $pipeline = Get-Content -LiteralPath (Join-Path $pipelineRoot $contract.Name) -Raw

        It "$($contract.Name) preserves trigger, schedule, and exact scan scope" {
            $pipeline | Should Match '(?ms)^trigger:.*?include:\s*\r?\n\s+- main'
            $pipeline | Should Match "cron:\s*'$($contract.Cron)'"
            $pipeline | Should Match 'always:\s+true'
            $pipeline | Should Not Match '(?m)^pr:'
            foreach ($scope in $contract.Scope) { $pipeline | Should Match $scope }
        }

        It "$($contract.Name) uses immutable scanner inputs and shared SARIF publication" {
            $pipeline | Should Match 'DIGEST(?:_OR_SHA256)?'
            $pipeline | Should Match '@\$env:'
            $pipeline | Should Match 'templates/publish-sarif\.yml'
            $pipeline | Should Match 'reportType:\s+third-party-sarif'
            $pipeline | Should Not Match '(?i)\$env:(?:KUBESEC|KICS|TFSEC|GRYPE|TRIVY)_IMAGE:(?:latest|main|master)'
        }

        It "$($contract.Name) contains no embedded credentials" {
            $pipeline | Should Not Match '(?i)(password|client-secret|access-token|account-key|sas-token)\s*:'
        }
    }

    It 'keeps Kubesec deterministic and finding severities delegated to the converter' {
        $pipeline = Get-Content -LiteralPath (Join-Path $pipelineRoot 'sast-kubesec.yml') -Raw
        $pipeline | Should Match 'Convert-KubesecToSarif\.ps1'
        $pipeline | Should Match "@\('manifests/critical-double\.yaml', 'manifests/score-5-pod-serviceaccount\.yaml'\)"
        $pipeline | Should Match '\$scanExitCode -notin @\(0, 2\)'
        $pipeline | Should Not Match "(?s)Convert-KubesecToSarif\.ps1.*\$LASTEXITCODE"
        $pipeline | Should Match '(?ms)Convert-KubesecToSarif\.ps1.*?^\s+exit 0\s*$'
    }

    It 'keeps KICS findings report-only while retaining JSON and marker-owned PR feedback' {
        $pipeline = Get-Content -LiteralPath (Join-Path $pipelineRoot 'iacs-checkmarx-kics.yml') -Raw
        $pipeline | Should Match '--type terraform'
        $pipeline | Should Not Match '--platform-type'
        $pipeline | Should Match '--user \$dockerUser'
        $pipeline | Should Match '--ignore-on-exit results'
        $pipeline | Should Match 'artifact:\s+kics-json'
        $pipeline | Should Match 'Set-PullRequestComment\.ps1'
        $pipeline | Should Match 'kics-scan-summary:v1'
    }

    It 'keeps tfsec findings report-only at the tool default threshold' {
        $pipeline = Get-Content -LiteralPath (Join-Path $pipelineRoot 'iacs-aquasecurity-tfsec.yml') -Raw
        $pipeline | Should Match '--user \$dockerUser'
        $pipeline | Should Match '--soft-fail'
        $pipeline | Should Not Match '(?i)--minimum-severity|--severity'
    }

    It 'preserves Grype critical cutoff with fail-build false semantics' {
        $pipeline = Get-Content -LiteralPath (Join-Path $pipelineRoot 'cis-anchore-grype.yml') -Raw
        $pipeline | Should Match '--fail-on critical'
        $pipeline | Should Match '\$scanExitCode -notin @\(0, 2\)'
        $pipeline | Should Match 'fail-build=false'
        $pipeline | Should Match '(?m)^\s+exit 0\s*$'
    }

    It 'does not add a Trivy severity or finding exit gate' {
        $pipeline = Get-Content -LiteralPath (Join-Path $pipelineRoot 'cis-trivy.yml') -Raw
        $pipeline | Should Not Match '(?i)--severity|--exit-code'
        $pipeline | Should Match 'image --format sarif'
    }

    It 'stages validated file or directory inputs before publishing through both shared security views' {
        $publisher = Get-Content -LiteralPath (Join-Path $pipelineRoot 'templates\publish-sarif.yml') -Raw
        $validationIndex = $publisher.IndexOf('Validate third-party SARIF')
        $stagingIndex = $publisher.IndexOf('Stage validated SARIF for Advanced Security')
        $artifactIndex = $publisher.IndexOf('PublishBuildArtifacts@1')
        $advancedSecurityIndex = $publisher.IndexOf('AdvancedSecurity-Publish@1')

        $validationIndex | Should BeGreaterThan -1
        $stagingIndex | Should BeGreaterThan $validationIndex
        $artifactIndex | Should BeGreaterThan $stagingIndex
        $advancedSecurityIndex | Should BeGreaterThan $artifactIndex
        $publisher | Should Match 'Get-Item -LiteralPath \(Resolve-Path -LiteralPath.*parameters\.sarifPath'
        $publisher | Should Match '\$source\.PSIsContainer'
        $publisher | Should Match 'Get-ChildItem -LiteralPath \$source\.FullName -File -Filter ''\*\.sarif'''
        $publisher | Should Match '\$source\.Extension -eq ''\.sarif'''
        $publisher | Should Match 'Remove-Item -LiteralPath \$stagingDirectory -Recurse -Force'
        $publisher | Should Match 'No validated SARIF files were staged for Advanced Security publication\.'
        $publisher | Should Match 'PathtoPublish:\s+\$\{\{ parameters\.sarifPath \}\}'
        $publisher | Should Match 'ArtifactName:\s+CodeAnalysisLogs'
        $publisher | Should Match 'SarifsInputDirectory:\s+\$\(Agent\.TempDirectory\)/validated-third-party-sarif'
        $publisher | Should Not Match 'SarifsInputDirectory:\s+\$\{\{ parameters\.sarifPath \}\}'
        $publisher | Should Not Match '\$LASTEXITCODE'
    }

    It 'makes every third-party consumer inherit dual publication exactly once' {
        foreach ($contract in @(@{ Name = 'sast-eslint.yml' }) + $phase6Contracts) {
            $pipeline = Get-Content -LiteralPath (Join-Path $pipelineRoot $contract.Name) -Raw
            @([regex]::Matches($pipeline, 'templates/publish-sarif\.yml')).Count | Should Be 1
            $pipeline | Should Not Match 'ArtifactName:\s+CodeAnalysisLogs'
            $pipeline | Should Not Match 'AdvancedSecurity-Publish@1'
        }
    }

    It 'routes third-party SARIF to both in-product destinations' {
        $routingPath = Join-Path $pipelineRoot 'config\visualization-routing.json'
        $routing = Get-Content -LiteralPath $routingPath -Raw | ConvertFrom-Json -Depth 100
        $route = $routing.routes | Where-Object reportType -eq 'third-party-sarif'
        $sarifScans = $route.destinations | Where-Object name -eq 'sarif-scans-tab'
        $advancedSecurity = $route.destinations | Where-Object name -eq 'repos-advanced-security-code-scanning'

        $sarifScans.artifact | Should Be 'CodeAnalysisLogs'
        $advancedSecurity.task | Should Be 'AdvancedSecurity-Publish@1'
        $route.wikiFallback | Should Be $false
    }
}
