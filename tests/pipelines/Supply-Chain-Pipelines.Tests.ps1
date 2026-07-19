$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$pipelineRoot = Join-Path $repositoryRoot '.azuredevops\pipelines'

function Get-PipelineContent {
    param([Parameter(Mandatory)][string]$Name)

    $path = Join-Path $pipelineRoot $Name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required Phase 7 pipeline is missing: $path"
    }
    return Get-Content -LiteralPath $path -Raw
}

Describe 'Syft SBOM pipeline contract' {
    $pipeline = Get-PipelineContent 'sca-anchore-syft-sbom.yml'

    It 'runs on main without a YAML pull request trigger' {
        $pipeline | Should Match '(?ms)^trigger:.*?include:\s*\r?\n\s+- main'
        $pipeline | Should Not Match '(?m)^pr:'
        $pipeline | Should Not Match '(?m)^schedules:'
    }

    It 'builds and scans a deterministic local image with an immutable Syft input' {
        $pipeline | Should Match 'buildContext:\s+src/webapp01'
        $pipeline | Should Match 'Dockerfile:\s+src/webapp01/Dockerfile'
        $pipeline | Should Match "applicationImage = '\$\(imageName\):\$\(Build\.SourceVersion\)'"
        $pipeline | Should Match 'SYFT_IMAGE_DIGEST'
        $pipeline | Should Match '@\$env:SYFT_IMAGE_DIGEST'
    }

    It 'publishes native SPDX JSON without hiding execution failure' {
        $pipeline | Should Match 'syft-sbom\.spdx\.json'
        $pipeline | Should Match 'artifact:\s+syft-sbom'
        $pipeline | Should Match 'ConvertFrom-Json'
        $pipeline | Should Not Match '(?m)^\s*continueOnError:\s*true'
    }
}

Describe 'Microsoft SBOM pipeline contract' {
    $pipeline = Get-PipelineContent 'sca-microsoft-sbom.yml'

    It 'runs on main without a YAML pull request trigger' {
        $pipeline | Should Match '(?ms)^trigger:.*?include:\s*\r?\n\s+- main'
        $pipeline | Should Not Match '(?m)^pr:'
    }

    It 'Release-builds with .NET 9 and installs a checksum-verified SBOM tool' {
        $pipeline | Should Match 'version:\s+9\.0\.x'
        $pipeline | Should Match '--configuration Release'
        $pipeline | Should Match 'templates/install-pinned-tool\.yml'
        $pipeline | Should Match 'toolId:\s+microsoft-sbom-tool'
        $pipeline | Should Match 'SBOM_TOOL_SHA256'
    }

    It 'publishes SPDX evidence and gates the GitHub submission gap explicitly' {
        $pipeline | Should Match 'spdx_2\.2'
        $pipeline | Should Match 'artifact:\s+microsoft-spdx-sbom'
        $pipeline | Should Match 'PLATFORM_GAP_SPDX_SUBMISSION_DISPOSITION'
        $pipeline | Should Match '(?i)GitHub dependency submission has no Azure DevOps equivalent'
        $pipeline | Should Not Match "@\('accepted', 'replaced'"
    }
}

Describe 'OpenSSF Scorecard pipeline contract' {
    $pipeline = Get-PipelineContent 'sca-openssf-scorecard.yml'

    It 'runs on main and the exact always-on Wednesday schedule without a YAML pull request trigger' {
        $pipeline | Should Match '(?ms)^trigger:.*?include:\s*\r?\n\s+- main'
        $pipeline | Should Match "cron:\s*'25 23 \* \* 3'"
        $pipeline | Should Match 'always:\s+true'
        $pipeline | Should Not Match '(?m)^pr:'
    }

    It 'authorizes the protected project wiki repository with explicit credential-free checkouts' {
        $pipeline | Should Match '(?ms)resources:\s+repositories:\s+- repository: projectWiki\s+type: git\s+name: DevSecOps\.wiki\s+ref: refs/heads/wikiMaster'
        $pipeline | Should Match '(?ms)- checkout: self\s+clean: true\s+persistCredentials: false\s+path: source'
        $pipeline | Should Match '(?ms)- checkout: projectWiki\s+clean: true\s+persistCredentials: false\s+fetchDepth: 1\s+path: project-wiki'
        $pipeline | Should Match '\$\(Pipeline\.Workspace\)/source/scripts/azure-devops/Publish-WikiSummary\.ps1'
        $pipeline | Should Not Match '(?m)^\s+persistCredentials:\s+true\s*$'
    }

    It 'uses immutable Scorecard input and validates authoritative JSON only' {
        $pipeline | Should Match 'SCORECARD_IMAGE_DIGEST'
        $pipeline | Should Match '@\$env:SCORECARD_IMAGE_DIGEST'
        $pipeline | Should Match 'scorecard-results\.json'
        $pipeline | Should Match 'ConvertFrom-Json'
        $pipeline | Should Not Match '(?i)sarif'
    }

    It 'runs the container as the validated numeric non-root hosted-agent UID and GID' {
        $pipeline | Should Match '(?m)\$hostUid\s*=\s*\[string\]\(& id -u\)'
        $pipeline | Should Match '(?m)\$hostGid\s*=\s*\[string\]\(& id -g\)'
        $pipeline | Should Match "\$hostUid -notmatch '\^\[1-9\]\[0-9\]\*\$'"
        $pipeline | Should Match "\$hostGid -notmatch '\^\[1-9\]\[0-9\]\*\$'"
        $pipeline | Should Match '--user "\$\{hostUid\}:\$\{hostGid\}"'
        $pipeline | Should Not Match '(?i)--user\s+(?:"?0(?::0)?"?|root)'
        $pipeline | Should Not Match '(?i)\bchmod\s+(?:-R\s+)?(?:[0-7]*[2367][0-7]{2}|a\+w|go\+w)\b'
    }

    It 'uses the job-scoped Azure DevOps authentication contract without persisting credentials' {
        $pipeline | Should Match '--env AZURE_DEVOPS_AUTH_TOKEN'
        $pipeline | Should Match '--env SCORECARD_EXPERIMENTAL'
        $pipeline | Should Match 'AZURE_DEVOPS_AUTH_TOKEN:\s+\$\(System\.AccessToken\)'
        $pipeline | Should Match 'SCORECARD_EXPERIMENTAL:\s+''1'''
        $pipeline | Should Not Match 'SCORECARD_AUTH_TOKEN'
        $pipeline | Should Not Match '(?m)^\s+GITHUB_AUTH_TOKEN:'
    }

    It 'retains the artifact for 30 days and publishes only a sanitized wiki summary' {
        $pipeline | Should Match 'artifact:\s+openssf-scorecard-json'
        $pipeline | Should Match 'retentionDays:\s+30'
        $pipeline | Should Match 'daysValid\s*=\s*30'
        $pipeline | Should Match "definitionId\s*=\s*\[int\]'\$\(System\.DefinitionId\)'"
        $pipeline | Should Match "runId\s*=\s*\[int\]'\$\(Build\.BuildId\)'"
        $pipeline | Should Match '(?ms)\$lease\s*=\s*ConvertTo-Json\s+-InputObject\s+@\(@\{.*?\}\)\s+-Depth\s+10'
        $pipeline | Should Not Match '@\(@\{.*?\}\)\s*\|\s*ConvertTo-Json'
        $pipeline | Should Match 'Publish-WikiSummary\.ps1'
        $pipeline | Should Match 'ReportType\s+''openssf-scorecard'''
        $pipeline | Should Match 'ScorecardJsonPath'
        $pipeline | Should Match '-RoutingPath\s+''\$\(Pipeline\.Workspace\)/source/\.azuredevops/pipelines/config/visualization-routing\.json'''
        $pipeline | Should Match 'PLATFORM_GAP_SCORECARD_PUBLICATION_DISPOSITION'
        $pipeline | Should Not Match "@\('accepted', 'replaced'"
    }
}