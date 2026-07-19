$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repositoryRoot 'scripts\azure-devops\Publish-DocumentationWiki.ps1')

function New-DocumentationFixture {
    param([string]$Root)

    foreach ($mapping in Get-DocumentationWikiMappings) {
        $path = Join-Path $Root $mapping.SourcePath
        New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
        Set-Content -LiteralPath $path -Value "---`ntitle: $($mapping.Title)`n---`n`n# $($mapping.Title)`n`nContent for $($mapping.WikiPath)." -Encoding utf8
    }
}

    function Test-Throws {
        param([Parameter(Mandatory)][scriptblock]$Action)

        try {
            & $Action
            return $false
        }
        catch {
            return $true
        }
    }

Describe 'Documentation wiki staging' {
    It 'strips YAML frontmatter while retaining Markdown content' {
        $content = ConvertTo-DocumentationWikiContent "---`ntitle: Example`n---`n`n# Example`n"

        $content | Should Be "# Example`n"
    }

    It 'uses the native Azure DevOps TOC while preserving external links' {
        $markdown = "# Guide`n`n## Table of Contents`n`n1. [Deep Dive](#deep--dive)`n`n---`n`n## Deep Dive`n`n[Reference](https://example.com/docs)`n"

        $content = ConvertTo-DocumentationWikiContent $markdown

        $content | Should Match '(?m)^\[\[_TOC_\]\]$'
        $content | Should Not Match '\]\(#deep--dive\)'
        $content | Should Match '\[Reference\]\(https://example\.com/docs\)'
    }

    It 'uses the deterministic approved source and page mapping' {
        $mappings = @(Get-DocumentationWikiMappings)

        $mappings.SourcePath -join '|' | Should Be 'docs/devsecops-concepts.md|docs/ghas-mdc-devsecops.md|docs/GHAS-MDC-L400-Guide.md|docs/templates/security-plan-template.md'
        $mappings.WikiPath -join '|' | Should Be '/Documentation/DevSecOps-Concepts|/Documentation/GHAS-MDC-DevSecOps|/Documentation/GHAS-MDC-L400-Guide|/Documentation/Security-Plan-Template'
    }

    It 'generates an index and authoritative manifest in deterministic order' {
        New-DocumentationFixture $TestDrive
        $stage = Join-Path $TestDrive 'stage'

        $manifestPath = New-DocumentationWikiStage -RootPath $TestDrive -OutputPath $stage
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 20
        $index = Get-Content -LiteralPath (Join-Path $stage '000-documentation-index.md') -Raw

        @($manifest.pages).Count | Should Be 5
        $manifest.deletionPolicy | Should Be 'none'
        $manifest.pages[0].wikiPath | Should Be '/Documentation'
        $index | Should Match '\[DevSecOps Concepts\]\(/Documentation/DevSecOps-Concepts\)'
        $index.IndexOf('DevSecOps Concepts') -lt $index.IndexOf('Security Plan Template') | Should Be $true
        (Get-Content -LiteralPath (Join-Path $stage '010-devsecops-concepts.md') -Raw) | Should Not Match '(?m)^---$'
    }

    It 'stages native TOCs for approved guides with authored fragment links' {
        $stage = Join-Path $TestDrive 'real-stage'

        $null = New-DocumentationWikiStage -RootPath (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path -OutputPath $stage

        (Get-Content -LiteralPath (Join-Path $stage '020-ghas-mdc-devsecops.md') -Raw) | Should Match '(?m)^\[\[_TOC_\]\]$'
        (Get-Content -LiteralPath (Join-Path $stage '030-ghas-mdc-l400-guide.md') -Raw) | Should Match '(?m)^\[\[_TOC_\]\]$'
    }

    It 'rejects duplicate mappings and repository traversal' {
        New-DocumentationFixture $TestDrive
        $mappings = @(Get-DocumentationWikiMappings)
        $duplicates = @($mappings[0], $mappings[0])
        $unsafe = @([pscustomobject]@{ Order = 10; SourcePath = '../outside.md'; WikiPath = '/Documentation/Outside'; StagedFile = '010-outside.md'; Title = 'Outside' })

            (Test-Throws { Assert-DocumentationWikiMappings -Mappings $duplicates -RootPath $TestDrive }) | Should Be $true
            (Test-Throws { Assert-DocumentationWikiMappings -Mappings $unsafe -RootPath $TestDrive }) | Should Be $true
    }

    It 'rejects unsafe paths, active content, credentials, control characters, and empty pages' {
            (Test-Throws { Assert-DocumentationWikiPath '/Security/Documentation' }) | Should Be $true
            (Test-Throws { Assert-DocumentationWikiPath '/Documentation/../Security' }) | Should Be $true
            (Test-Throws { ConvertTo-DocumentationWikiContent '<script>alert(1)</script>' }) | Should Be $true
            (Test-Throws { ConvertTo-DocumentationWikiContent 'Authorization: Bearer token-value' }) | Should Be $true
            (Test-Throws { ConvertTo-DocumentationWikiContent "safe$([char]1)unsafe" }) | Should Be $true
            (Test-Throws { ConvertTo-DocumentationWikiContent "---`ntitle: Empty`n---`n" }) | Should Be $true
    }
}

Describe 'Documentation wiki publication' {
    It 'resets REST status and response header capture for every request' {
        $script = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\scripts\azure-devops\Publish-DocumentationWiki.ps1') -Raw
        $script | Should Match 'function Invoke-DocumentationWikiRestMethod[\s\S]*?\$statusCode = \$null[\s\S]*?\$responseHeaders = \$null[\s\S]*?Invoke-RestMethod @parameters'
    }

    It 'creates absent pages with If-None-Match and no delete request' {
        Mock Invoke-DocumentationWikiRestMethod {
            if ($Method -eq 'GET') { return [pscustomobject]@{ StatusCode = 404; Headers = @{}; Content = $null } }
            return [pscustomobject]@{ StatusCode = 201; Headers = @{}; Content = @{} }
        }

        Publish-DocumentationWikiPage 'https://dev.azure.com/example' 'project' 'project.wiki' '/Documentation/Page' '# Page' 'token'

        Assert-MockCalled Invoke-DocumentationWikiRestMethod 1 -ParameterFilter { $Method -eq 'PUT' -and $Headers['If-None-Match'] -eq '*' }
        Assert-MockCalled Invoke-DocumentationWikiRestMethod 0 -ParameterFilter { $Method -eq 'DELETE' }
    }

    It 'updates existing pages with the current ETag' {
        Mock Invoke-DocumentationWikiRestMethod {
            if ($Method -eq 'GET') { return [pscustomobject]@{ StatusCode = 200; Headers = @{ ETag = '"revision"' }; Content = @{} } }
            return [pscustomobject]@{ StatusCode = 200; Headers = @{}; Content = @{} }
        }

        Publish-DocumentationWikiPage 'https://dev.azure.com/example' 'project' 'project.wiki' '/Documentation/Page' '# Page' 'token'

        Assert-MockCalled Invoke-DocumentationWikiRestMethod 1 -ParameterFilter { $Method -eq 'PUT' -and $Headers['If-Match'] -eq '"revision"' }
    }

    It 'rejects a manifest that attempts to publish outside Documentation' {
        New-DocumentationFixture $TestDrive
        $stage = Join-Path $TestDrive 'stage'
        $manifestPath = New-DocumentationWikiStage -RootPath $TestDrive -OutputPath $stage
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 20
        $manifest.pages[0].wikiPath = '/Security/Documentation'

            (Test-Throws { Assert-DocumentationWikiManifest -Manifest $manifest -ManifestRoot $stage }) | Should Be $true
    }
}