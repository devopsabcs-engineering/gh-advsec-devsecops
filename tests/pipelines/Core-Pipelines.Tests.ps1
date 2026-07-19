$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$pipelineRoot = Join-Path $repositoryRoot '.azuredevops\pipelines'
$ci = Get-Content -LiteralPath (Join-Path $pipelineRoot 'ci.yml') -Raw
$cicd = Get-Content -LiteralPath (Join-Path $pipelineRoot 'cicd.yml') -Raw
$docs = Get-Content -LiteralPath (Join-Path $pipelineRoot 'docs-static.yml') -Raw

Describe 'Core CI pipeline contract' {
    It 'leaves Azure Repos pull request execution to branch policy' {
        $ci | Should Match '(?m)^trigger:\s+none\s*$'
        $ci | Should Not Match '(?m)^pr:'
    }

    It 'restores and Release-builds the solution with .NET 9' {
        $ci | Should Match 'version:\s+9\.0\.x'
        $ci | Should Match 'command:\s+restore'
        $ci | Should Match '--configuration Release --no-restore'
        $ci | Should Match 'gh-aspnet-webapp-01\.sln'
    }

    It 'builds the application image from the required context and commit identity' {
        $ci | Should Match 'buildContext:\s+src/webapp01'
        $ci | Should Match 'Dockerfile:\s+src/webapp01/Dockerfile'
        $ci | Should Match 'imageTag:\s+\$\(Build\.SourceVersion\)'
    }
}

Describe 'Immutable CI/CD pipeline contract' {
    It 'triggers from main without a YAML pull request trigger' {
        $cicd | Should Match '(?ms)^trigger:.*?include:\s*\r?\n\s+- main'
        $cicd | Should Not Match '(?m)^pr:'
    }

    It 'uses actual Bicep outputs through Azure Pipelines output variables' {
        $cicd.Contains("foreach (`$name in @('resourceGroupName', 'webAppName', 'webAppUrl', 'acrLoginServer'") | Should Be $true
        $cicd.Contains('##vso[task.setvariable variable=$name;isOutput=true]') | Should Be $true
        $cicd | Should Match "stageDependencies\.Provision\.Deploy\.outputs\['deployInfrastructure\.acrLoginServer'\]"
        $cicd | Should Match 'task\.setvariable variable=imageReference;isOutput=true'
        $cicd | Should Match "stageDependencies\.BuildEvidence\.BuildSignVerify\.outputs\['createEvidence\.imageReference'\]"
    }

    It 'signs and verifies the digest and both attestations before deployment' {
        $cicd | Should Match 'Sign-And-AttestImage\.ps1'
        $cicd | Should Match 'Verify-ImageEvidence\.ps1'
        $cicd | Should Match '-SbomPath\s+(?:\$sbomPath|''\$\(Pipeline\.Workspace\)/signed-image-evidence/spdx-sbom\.json'')'
        $cicd | Should Match 'spdx-sbom\.json'
        $cicd | Should Match 'slsa-provenance\.json'
        $cicd | Should Match 'if \(\$imageReference -notmatch ''@sha256:'
    }

    It 'generates the application SBOM from a deterministic Release publish drop' {
        $cicd | Should Match 'Publish application for SBOM generation'
        $cicd | Should Match '--output \$\(Agent\.TempDirectory\)/sbom-build-drop /p:UseAppHost=false'
        $cicd | Should Match 'modifyOutputPath:\s+false'
        $cicd | Should Match 'Generate -b \$buildDrop -bc ''\$\(Build\.SourcesDirectory\)'''
        $cicd | Should Not Match 'image-rootfs'
    }

    It 'deploys only a propagated digest-qualified image' {
        $deployStage = ($cicd -split '(?m)^  - stage: Deploy\s*$')[1]
        $deployStage | Should Match '--container-image-name \$imageReference'
        $deployStage | Should Match '\$imageReference -notmatch ''@sha256:'
        $deployStage | Should Not Match ':latest'
    }

    It 'provisions a clean environment without requiring a bootstrap image' {
        $mainBicep = Get-Content -LiteralPath (Join-Path $repositoryRoot 'blueprints\gh-aspnet-webapp\bicep\main.bicep') -Raw
        $resourcesBicep = Get-Content -LiteralPath (Join-Path $repositoryRoot 'blueprints\gh-aspnet-webapp\bicep\resources.bicep') -Raw
        ($cicd + $mainBicep + $resourcesBicep) | Should Not Match 'DEPLOYMENT_BOOTSTRAP_IMAGE_DIGEST'
        $resourcesBicep | Should Not Match 'linuxFxVersion'
        $resourcesBicep | Should Not Match 'DOCKER_CUSTOM_IMAGE_NAME'
        $resourcesBicep | Should Match 'acrUseManagedIdentityCreds:\s*true'
    }

    It 'publishes signed image evidence and uses existing provenance helpers' {
        $cicd | Should Match 'PublishPipelineArtifact@1'
        $cicd | Should Match 'artifact:\s+signed-image-evidence'
        $cicd | Should Match 'New-SlsaProvenance\.ps1'
        $cicd | Should Match 'Sign-And-AttestImage\.ps1'
        $cicd | Should Match 'Verify-ImageEvidence\.ps1'
        $cicd | Should Match 'leaseDaysText.*A-Za-z0-9_'
    }

    It 'does not contain registry credentials, storage keys, or shared access tokens' {
        $cicd | Should Not Match '(?i)docker_registry_server_(?:password|username)'
        $cicd | Should Not Match '(?i)--account-key'
        $cicd | Should Not Match '(?i)--sas-token'
        $cicd | Should Not Match '(?i)client-secret'
    }
}

Describe 'Documentation project-wiki pipeline contract' {
    It 'triggers from main without a YAML pull request trigger' {
        $docs | Should Match '(?ms)^trigger:.*?include:\s*\r?\n\s+- main'
        $docs | Should Not Match '(?m)^pr:'
        $docs | Should Not Match '(?m)^\s+paths:'
    }

    It 'publishes only the staged and validated wiki artifact' {
        $docs | Should Match 'Publish-DocumentationWiki\.ps1'
        $docs | Should Match 'wiki-documentation-manifest\.json'
        $docs | Should Match "namespace -ne '/Documentation'"
        $docs | Should Match 'PublishPipelineArtifact@1'
        $docs | Should Match 'artifact:\s+wiki-documentation'
    }

    It 'uses a protected deployment environment with newest-run locking' {
        $docs | Should Match 'deployment:\s+PublishProjectWiki'
        $docs | Should Match 'environment:\s+\$\(DOCUMENTATION_ENVIRONMENT\)'
        $docs | Should Match 'lockBehavior:\s+runLatest'
    }

    It 'uses System.AccessToken and contains no Jekyll, Azure service connection, or Storage deployment requirements' {
        $docs | Should Match 'SYSTEM_ACCESSTOKEN:\s+\$\(System\.AccessToken\)'
        $docs | Should Match 'PROJECT_WIKI_IDENTIFIER:\s+\$\(PROJECT_WIKI_IDENTIFIER\)'
        $docs | Should Not Match 'JEKYLL_|AZURE_SERVICE_CONNECTION|DOCS_STORAGE_ACCOUNT_NAME'
        $docs | Should Not Match 'AzureCLI@|Publish-StorageStaticSite|az storage'
    }

    It 'explicitly authorizes the project wiki repository for the scoped job token' {
        $docs | Should Match '(?ms)resources:\s+repositories:.*?repository:\s+projectWiki.*?name:\s+DevSecOps\.wiki.*?ref:\s+refs/heads/wikiMaster'
        $docs | Should Match 'checkout:\s+projectWiki'
        $docs | Should Match 'path:\s+source'
        $docs | Should Match '\$\(Pipeline\.Workspace\)/source/scripts/azure-devops/Publish-DocumentationWiki\.ps1'
    }

    It 'limits external requirements to the wiki identifier and protected environment' {
        $requiredInputBlock = [regex]::Match($docs, '(?ms)\$requiredInputs = \[ordered\]@\{(?<body>.*?)\n\s*\}').Groups['body'].Value
        $requiredInputBlock | Should Match 'PROJECT_WIKI_IDENTIFIER'
        $requiredInputBlock | Should Match 'DOCUMENTATION_ENVIRONMENT'
        $requiredInputBlock | Should Not Match 'JEKYLL|STORAGE|SERVICE_CONNECTION|RETENTION'
    }
}