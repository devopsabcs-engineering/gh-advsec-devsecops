$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$pipelineRoot = Join-Path $repositoryRoot '.azuredevops\pipelines'
$dast = Get-Content -LiteralPath (Join-Path $pipelineRoot 'dast-zap.yml') -Raw
$publishSarif = Get-Content -LiteralPath (Join-Path $pipelineRoot 'templates\publish-sarif.yml') -Raw
$securityAgent = Get-Content -LiteralPath (Join-Path $pipelineRoot 'security-agent.yml') -Raw
$governance = Get-Content -LiteralPath (Join-Path $pipelineRoot 'enforce-ghas-policy.yml') -Raw

Describe 'DAST ZAP pipeline contract' {
    It 'runs from main and Sunday 01:00 UTC even without repository changes' {
        $dast | Should Match "cron:\s+'0 1 \* \* 0'"
        $dast | Should Match 'always:\s+true'
        $dast | Should Match '(?ms)^trigger:.*?include:\s*\r?\n\s+- main'
    }

    It 'defaults to the pipeline-built local application' {
        $dast | Should Match '(?s)- name: target\s+type: string\s+default: http://127\.0\.0\.1:8080'
        $dast | Should Match '(?s)- name: buildAndStart\s+type: boolean\s+default: true'
    }

    It 'gates remote active scanning before execution and pins the image digest' {
        $authorizationIndex = $dast.IndexOf('ZAP_AUTHORIZATION_RECORD is required')
        $scanIndex = $dast.IndexOf('Invoke-ZapScan.ps1')
        ($authorizationIndex -ge 0 -and $authorizationIndex -lt $scanIndex) | Should Be $true
        $dast | Should Match "'\$\{\{ parameters\.buildAndStart \}\}' -ne 'True'"
        $dast | Should Match 'ZAP_AUTHORIZATION_RECORD:\s+\$\(ZAP_AUTHORIZATION_RECORD\)'
        $dast | Should Match '@sha256:\[a-fA-F0-9\]\{64\}'
    }

    It 'uses local port 8080 with readiness, timeout, and cleanup in the helper' {
        $helper = Get-Content -LiteralPath (Join-Path $repositoryRoot 'scripts\zap\Invoke-ZapScan.ps1') -Raw
        $dast | Should Match 'default:\s+8080'
        $helper | Should Match '127\.0\.0\.1:\$\{Port\}:8080'
        $helper | Should Match '\$buildContext = Split-Path -Parent \$Dockerfile'
        $helper.Contains("'--tag', `$localImage, `$buildContext") | Should Be $true
        $helper | Should Match 'Wait-HttpReady'
        $helper | Should Match 'finally'
        $helper | Should Match "'rm', '--force'"
        $dast | Should Match '-ScanType full -ScannerTimeoutSeconds 1560'
        (Get-Content -LiteralPath (Join-Path $repositoryRoot '.zap\full-plan.yaml') -Raw) | Should Match 'maxScanDurationInMins:\s+20'
    }

    It 'publishes native validated SARIF and raw reports without a finding gate' {
        $helper = Get-Content -LiteralPath (Join-Path $repositoryRoot 'scripts\zap\Invoke-ZapScan.ps1') -Raw
        $dast | Should Match 'displayName:\s+Run report-only baseline and full scans'
        $dast | Should Match 'templates/publish-sarif\.yml'
        $dast | Should Match 'sarifPath:\s+\$\(zapSarifPath\)'
        $dast | Should Match 'artifact:\s+zap-reports'
        $publishSarif | Should Match 'Test-Sarif\.ps1'
        $publishSarif | Should Match 'No validated SARIF files were staged'
        $helper | Should Match 'Docker command failed:'
        $helper | Should Match 'ZAP did not produce \$Mode\.\$extension'
        $helper | Should Match 'Test-ZapSarifReport'
        $helper | Should Not Match '(?i)failOn(?:Error|Warning|Info)|alertThreshold|riskThreshold'
        foreach ($planName in @('baseline-plan.yaml', 'full-plan.yaml')) {
            $plan = Get-Content -LiteralPath (Join-Path $repositoryRoot ".zap\$planName") -Raw
            $plan | Should Match 'template:\s+sarif-json'
            $plan | Should Not Match '(?m)^\s*failOn(?:Error|Warning|Info):'
        }
    }

    It 'initializes fail-closed evidence before validating DAST prerequisites' {
        $initializeIndex = $dast.IndexOf('Initialize fail-closed DAST evidence')
        $validationIndex = $dast.IndexOf('Require image integrity and active-scan authorization')
        $initializeIndex | Should BeGreaterThan -1
        $initializeIndex | Should BeLessThan $validationIndex
        $dast | Should Match 'run-status\.json'
    }
}

Describe 'Security agent pipeline contract' {
    It 'is manual-only with Node 22 and corrected agent path' {
        $securityAgent | Should Match '(?m)^trigger:\s+none\s*$'
        $securityAgent | Should Not Match '(?m)^schedules:'
        $securityAgent | Should Match "versionSpec:\s+'22\.x'"
        $securityAgent | Should Match '\.github/agents/security-agent\.agent\.md'
    }

    It 'pins CLI integrity and enforces job and CLI limits' {
        $securityAgent | Should Match 'COPILOT_CLI_VERSION'
        $securityAgent | Should Match 'COPILOT_CLI_INTEGRITY'
        $securityAgent | Should Match 'GH_TOKEN:\s+\$\(COPILOT_GITHUB_TOKEN\)'
        $securityAgent | Should Match 'actual_integrity'
        $securityAgent | Should Match 'timeoutInMinutes:\s+15'
        $securityAgent | Should Match 'timeout 600 copilot'
        $securityAgent | Should Match '--silent --stream off'
        $securityAgent | Should Match '--output-format json'
        $securityAgent | Should Match '--disable-builtin-mcps --no-custom-instructions --no-auto-update'
        $securityAgent | Should Match 'timeoutInMinutes:\s+11'
    }

    It 'uses bounded tools, structured severity, sanitized wiki output, and 30-day artifact metadata' {
        $securityAgent | Should Match '--allow-tool read --allow-tool search'
        $securityAgent | Should Not Match '--allow-all-tools|--allow-all-paths'
        $securityAgent | Should Not Match '--allow-tool (?:write|edit|execute|shell)'
        $securityAgent | Should Match '>"\$raw_report" 2>"\$cli_errors"'
        $securityAgent | Should Match 'pipeline requirements replace the Delegation Map'
        $securityAgent | Should Match 'Perform the assessment directly; do not delegate or invoke agents'
        $securityAgent | Should Match 'return at most 20 findings'
        $securityAgent | Should Match 'Emit exactly one JSON object to stdout'
        $securityAgent | Should Match "type -eq 'assistant\.message'"
        $securityAgent | Should Match "type -eq 'assistant\.turn_end'"
        $securityAgent | Should Match '\$terminalMessage\.data\.content'
        $securityAgent | Should Match '\$rawOutput\.Substring\(\$start, \$index - \$start \+ 1\)'
        $securityAgent | Should Match '\$jsonObjects\.Count -ne 1'
        $securityAgent | Should Match '\$escaped = \$true'
        $securityAgent | Should Match 'one unambiguous JSON object'
        $securityAgent | Should Match '\$counts\[\$severity\] = @\(\$report\.findings \| Where-Object \{ \$_\.severity -eq \$severity \}\)\.Count'
        $securityAgent | Should Not Match 'severity counts do not equal the findings array length'
        $securityAgent | Should Match 'task\.logissue type=warning.*critical finding'
        $securityAgent | Should Not Match 'throw "Security assessment reported.*critical finding'
        $securityAgent | Should Not Match 'Write Markdown to security-reports|cp security-reports'
        $securityAgent | Should Match 'severityCounts'
        $securityAgent | Should Match 'ConvertFrom-Json'
        $securityAgent | Should Match 'security-assessment-report\.md'
        $securityAgent | Should Match 'security-assessment-report\.json'
        $securityAgent | Should Match 'Publish-WikiSummary\.ps1'
        $contract = Get-Content -LiteralPath (Join-Path $pipelineRoot 'config\workflow-contracts.json') -Raw | ConvertFrom-Json -Depth 100
        ($contract.contracts | Where-Object target -eq '.azuredevops/pipelines/security-agent.yml').retentionDays | Should Be 30
        $securityAgent | Should Not Match '(?i)Write-Host.*COPILOT_GITHUB_TOKEN'
    }

    It 'publishes precondition evidence and skips wiki output without a trusted summary' {
        $initializeIndex = $securityAgent.IndexOf('Initialize fail-closed security-agent evidence')
        $validationIndex = $securityAgent.IndexOf('Require approved CLI integrity and secret token')
        $initializeIndex | Should BeGreaterThan -1
        $initializeIndex | Should BeLessThan $validationIndex
        $securityAgent | Should Match 'repository:\s+projectWiki[\s\S]*name:\s+DevSecOps\.wiki[\s\S]*ref:\s+refs/heads/wikiMaster'
        $securityAgent | Should Match 'checkout:\s+self[\s\S]*persistCredentials:\s+false[\s\S]*path:\s+source'
        $securityAgent | Should Match 'checkout:\s+projectWiki[\s\S]*persistCredentials:\s+false[\s\S]*path:\s+project-wiki'
        $securityAgent | Should Match '\$\(Pipeline\.Workspace\)/source/scripts/azure-devops/Publish-WikiSummary\.ps1'
        $securityAgent | Should Match "-RoutingPath '\$\(Pipeline\.Workspace\)/source/\.azuredevops/pipelines/config/visualization-routing\.json'"
        $securityAgent | Should Match "Test-Path -LiteralPath '\$\(reportDirectory\)/wiki-summary\.md'"
    }
}

Describe 'Governance pipeline contract' {
    It 'is manual plus daily 06:00 UTC and always evaluates schedules' {
        $governance | Should Match '(?m)^trigger:\s+none\s*$'
        $governance | Should Match "cron:\s+'0 6 \* \* \*'"
        $governance | Should Match 'always:\s+true'
    }

    It 'defaults to no-op decision reporting and supports explicit retirement' {
        $governance | Should Match 'PLATFORM_GAP_ORG_POLICY_DISPOSITION'
        $governance | Should Match 'default:\s+decision-required'
        $governance | Should Match 'explicitly-retired'
        $governance | Should Match 'mutationAttempted = \$false'
        $governance | Should Match 'no silent Azure DevOps equivalent'
    }

    It 'requires a dry-run report before separately approved mutation' {
        $dryRunIndex = $governance.IndexOf("Initialize-PipelineGovernance.ps1' -ConfigurationPath")
        $applyIndex = $governance.IndexOf("Initialize-PipelineGovernance.ps1' -ConfigurationPath `$env:GOVERNANCE_CONFIGURATION_PATH -Apply")
        ($dryRunIndex -ge 0 -and $applyIndex -gt $dryRunIndex) | Should Be $true
        $governance | Should Match '(?s)applyApprovedReplacement.*?default:\s+false'
        $governance | Should Match 'GOVERNANCE_MUTATION_APPROVED'
        $governance | Should Match 'environment:\s+\$\(GOVERNANCE_MUTATION_ENVIRONMENT\)'
    }

    It 'publishes authoritative no-op and post-apply evidence with sanitized wiki routes' {
        $governance | Should Match 'Test-PipelineGovernance\.ps1'
        $governance | Should Match 'post-apply-evidence\.json'
        $governance | Should Match 'verifier-result\.json'
        $governance | Should Match 'artifact:\s+governance-report'
        $governance | Should Match 'artifact:\s+governance-apply-report'
        $governance | Should Match '(?s)Publish governance post-apply report.*?condition:\s+always\(\)'
        $governance | Should Match 'Publish-WikiSummary\.ps1'
        $governance | Should Match 'ReportType governance'
        $governance | Should Match 'Authoritative governance artifact'
        $contract = Get-Content -LiteralPath (Join-Path $pipelineRoot 'config\workflow-contracts.json') -Raw | ConvertFrom-Json -Depth 100
        $governanceContract = $contract.contracts | Where-Object target -eq '.azuredevops/pipelines/enforce-ghas-policy.yml'
        ($governanceContract.artifacts -contains 'governance-report') | Should Be $true
        ($governanceContract.artifacts -contains 'governance-apply-report') | Should Be $true
        ($governanceContract.gates -contains 'post-apply-verification') | Should Be $true
    }

    It 'skips optional wiki publication when its variable macro is unresolved' {
        $guard = [regex]::Escape('[string]::IsNullOrWhiteSpace($env:PROJECT_WIKI_IDENTIFIER) -or $env:PROJECT_WIKI_IDENTIFIER -match ''^\$\([A-Za-z0-9_.-]+\)$''')
        ([regex]::Matches($governance, $guard)).Count | Should Be 2
    }

    It 'targets the authoritative DevSecOps project wiki' {
        $governance | Should Match '(?m)^\s{2}PROJECT_WIKI_IDENTIFIER:\s+DevSecOps\.wiki\s*$'
        $governance | Should Match '(?s)resources:\s+repositories:.*?repository:\s+projectWiki.*?name:\s+DevSecOps\.wiki.*?ref:\s+refs/heads/wikiMaster'
        ([regex]::Matches($governance, 'checkout:\s+projectWiki')).Count | Should Be 2
        ([regex]::Matches($governance, "'\$\(Pipeline\.Workspace\)/source/scripts/azure-devops/Publish-WikiSummary\.ps1'")).Count | Should Be 2
        ([regex]::Matches($governance, "-RoutingPath '\$\(Pipeline\.Workspace\)/source/\.azuredevops/pipelines/config/visualization-routing\.json'")).Count | Should Be 2
    }

    It 'does not claim a workflow-parity producer before Phase 10' {
        $governance | Should Not Match 'workflow-parity-report|ReportType workflow-parity'
    }
}