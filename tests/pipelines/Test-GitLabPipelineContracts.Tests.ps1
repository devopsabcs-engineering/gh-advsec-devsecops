Describe 'GitLab pipeline workflow parity' {
    BeforeAll {
        $repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
        $validatorPath = Join-Path $repositoryRoot 'scripts\validation\Test-GitLabPipelineContracts.ps1'
        . (Join-Path $repositoryRoot 'scripts\zap\Invoke-ZapScan.ps1')

        function Copy-GitLabFixture {
            param([Parameter(Mandatory)][string]$Destination)

            New-Item -ItemType Directory -Path (Join-Path $Destination '.gitlab') -Force | Out-Null
            Copy-Item -LiteralPath (Join-Path $repositoryRoot '.gitlab-ci.yml') -Destination $Destination
            Copy-Item -LiteralPath (Join-Path $repositoryRoot '.gitlab\ci') -Destination (Join-Path $Destination '.gitlab') -Recurse
        }
    }

    It 'maps all 19 workflows and eight schedule profiles' {
        $reportPath = Join-Path $TestDrive 'gitlab-parity.json'

        & $validatorPath -RepositoryRoot $repositoryRoot -OutputPath $reportPath | Out-Null

        $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
        $report.status | Should -Be 'local-pass'
        $report.sourceWorkflowCount | Should -Be 19
        $report.moduleCount | Should -Be 6
        $report.scheduleProfileCount | Should -Be 8
    }

    It 'runs both build producers for merge requests and main' {
        $buildPipeline = Get-Content -LiteralPath (Join-Path $repositoryRoot '.gitlab\ci\build.yml') -Raw

        ([regex]::Matches($buildPipeline, 'CI_PIPELINE_SOURCE == "merge_request_event"')).Count | Should -Be 1
        ([regex]::Matches($buildPipeline, '(?m)^    - \.rules:merge-request-and-main\r?$')).Count | Should -Be 1
    }

    It 'produces publish artifacts for weekly container and DAST scans' {
        $buildPipeline = Get-Content -LiteralPath (Join-Path $repositoryRoot '.gitlab\ci\build.yml') -Raw

        $buildPipeline | Should -Match 'SCAN_PROFILE == "weekly-container-dast"'
        $buildPipeline | Should -Match 'dotnet publish .*--output src/webapp01/publish'
        $buildPipeline | Should -Match 'src/webapp01/publish/'
    }

    It 'authenticates governance audits with the dedicated token mapping' {
        $governancePipeline = Get-Content -LiteralPath (Join-Path $repositoryRoot '.gitlab\ci\governance.yml') -Raw

        $governancePipeline | Should -Match 'GITLAB_TOKEN: \$GITLAB_GOVERNANCE_TOKEN'
    }

    It 'runs the OpenSSF disposition through PowerShell' {
        $supplyChainPipeline = Get-Content -LiteralPath (Join-Path $repositoryRoot '.gitlab\ci\supply-chain.yml') -Raw

        $supplyChainPipeline | Should -Match "pwsh -NoProfile -Command - <<'PWSH'"
        $supplyChainPipeline | Should -Match 'Set-Content supply-chain-results/scorecard/disposition\.json'
    }

    It 'publishes the approved documentation manifest to GitLab Wiki' {
        $governancePipeline = Get-Content -LiteralPath (Join-Path $repositoryRoot '.gitlab\ci\governance.yml') -Raw

        $governancePipeline | Should -Match '(?m)^docs:gitlab-wiki:\r?$'
        $governancePipeline | Should -Match 'GITLAB_WIKI_TOKEN: \$GITLAB_WIKI_PUBLISH_TOKEN'
        $governancePipeline | Should -Match 'wiki-documentation/wiki-documentation-manifest\.json'
        $governancePipeline | Should -Match 'scripts/gitlab/Publish-DocumentationWiki\.ps1'
    }

    It 'publishes the security tool breakdown table to GitLab Wiki' {
        $governancePipeline = Get-Content -LiteralPath (Join-Path $repositoryRoot '.gitlab\ci\governance.yml') -Raw

        $governancePipeline | Should -Match '-Mode PublishSecuritySummary'
        $governancePipeline | Should -Match 'security-results/summary/summary\.md'
    }

    It 'runs the DAST scan against a self-contained app inside the ZAP image' {
        $deployPipeline = Get-Content -LiteralPath (Join-Path $repositoryRoot '.gitlab\ci\deploy.yml') -Raw

        $deployPipeline | Should -Match '(?m)^    name: \$ZAP_IMAGE\r?$'
        $deployPipeline | Should -Match 'cp -r src/webapp01/dast-publish /tmp/dast-app'
        $deployPipeline | Should -Match '/tmp/dast-app/webapp01'
        $deployPipeline | Should -Match 'zap\.sh -cmd -autorun'
        $deployPipeline | Should -Not -Match '\.powershell-docker'
    }

    It 'aggregates every scanner SARIF into a per-tool breakdown and a Code Quality report' {
        $securityPipeline = Get-Content -LiteralPath (Join-Path $repositoryRoot '.gitlab\ci\security.yml') -Raw

        $securityPipeline | Should -Match '(?m)^security:summary:\r?$'
        $securityPipeline | Should -Match 'New-SecuritySummary\.ps1'
        $securityPipeline | Should -Match 'codequality: security-results/summary/gl-code-quality-report\.json'
        Test-Path -LiteralPath (Join-Path $repositoryRoot 'scripts\sarif\New-SecuritySummary.ps1') | Should -BeTrue
    }

    It 'publishes the security tool breakdown to GitLab Pages' {
        $governancePipeline = Get-Content -LiteralPath (Join-Path $repositoryRoot '.gitlab\ci\governance.yml') -Raw

        $governancePipeline | Should -Match 'security-results/summary'
        $governancePipeline | Should -Match 'public/security'
    }

    It 'selects the production Docker target for ACR builds' {
        $deployPipeline = Get-Content -LiteralPath (Join-Path $repositoryRoot '.gitlab\ci\deploy.yml') -Raw

        $deployPipeline | Should -Match '(?m)^    - az acr build .* --target final(?: |$)'
    }

    It 'probes published ports through a remote Docker daemon' {
        $previousDockerHost = $env:DOCKER_HOST
        try {
            $env:DOCKER_HOST = 'tcp://docker:2375'

            $endpoint = Get-DockerPublishedEndpoint -Port 18080

            $endpoint.Binding | Should -Be '0.0.0.0:18080:8080'
            $endpoint.ReadinessUri | Should -Be 'http://docker:18080'
        }
        finally { $env:DOCKER_HOST = $previousDockerHost }
    }

    It 'keeps local Docker ports bound to loopback' {
        $previousDockerHost = $env:DOCKER_HOST
        try {
            Remove-Item Env:DOCKER_HOST -ErrorAction SilentlyContinue

            $endpoint = Get-DockerPublishedEndpoint -Port 18080

            $endpoint.Binding | Should -Be '127.0.0.1:18080:8080'
            $endpoint.ReadinessUri | Should -Be 'http://127.0.0.1:18080'
        }
        finally { $env:DOCKER_HOST = $previousDockerHost }
    }

    It 'maps root Linux jobs to a non-root ZAP user' {
        Mock Invoke-HostIdCommand { return '0' }

        Get-LinuxHostUser | Should -Be '1000:1000'
    }

    It 'preserves a non-root Linux host user mapping' {
        Mock Invoke-HostIdCommand {
            if ($Argument -eq '-u') { return '1001' }
            return '1002'
        }

        Get-LinuxHostUser | Should -Be '1001:1002'
    }

    It 'fails when a source workflow mapping is removed' {
        $fixtureRoot = Join-Path $TestDrive 'missing-mapping'
        Copy-GitLabFixture -Destination $fixtureRoot
        $securityPath = Join-Path $fixtureRoot '.gitlab\ci\security.yml'
        (Get-Content -LiteralPath $securityPath -Raw).Replace('Source parity: .github/workflows/SAST-ESLint.yml', 'Source mapping removed') |
            Set-Content -LiteralPath $securityPath

        { & $validatorPath -RepositoryRoot $fixtureRoot } | Should -Throw -ExpectedMessage '*SAST-ESLint.yml*found 0*'
    }

    It 'fails when a mutable scanner image is introduced' {
        $fixtureRoot = Join-Path $TestDrive 'mutable-image'
        Copy-GitLabFixture -Destination $fixtureRoot
        $rootPath = Join-Path $fixtureRoot '.gitlab-ci.yml'
        (Get-Content -LiteralPath $rootPath -Raw).Replace('anchore/grype:v0.82.0', 'anchore/grype:latest') |
            Set-Content -LiteralPath $rootPath

        { & $validatorPath -RepositoryRoot $fixtureRoot } | Should -Throw -ExpectedMessage '*mutable image*'
    }
}