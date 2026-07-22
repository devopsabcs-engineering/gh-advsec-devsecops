Describe 'GitLab documentation wiki publication' {
    BeforeAll {
        $scriptPath = (Resolve-Path (Join-Path $PSScriptRoot '..\..\scripts\gitlab\Publish-DocumentationWiki.ps1')).Path
        . $scriptPath
        $workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

        function New-GitLabDocumentationFixture {
            param([Parameter(Mandatory)][string]$Root)

            foreach ($mapping in Get-DocumentationWikiMappings) {
                $path = Join-Path $Root $mapping.SourcePath
                New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
                Set-Content -LiteralPath $path -Value "---`ntitle: $($mapping.Title)`n---`n`n# $($mapping.Title)`n" -Encoding utf8
            }

            $stage = Join-Path $Root 'stage'
            return New-DocumentationWikiStage -RootPath $Root -OutputPath $stage
        }
    }

    It 'stages the manifest through the script entrypoint' {
        $stage = Join-Path $TestDrive 'entrypoint-stage'

        & (Join-Path $workspaceRoot 'scripts\gitlab\Publish-DocumentationWiki.ps1') -Mode Stage -RepositoryRoot $workspaceRoot -StagingPath $stage | Out-Null

        Join-Path $stage 'wiki-documentation-manifest.json' | Should -Exist
    }

    It 'creates each absent allowlisted page without deleting Wiki content' {
        $manifestPath = New-GitLabDocumentationFixture -Root $TestDrive
        Mock Invoke-GitLabWikiRestMethod {
            if ($Method -eq 'GET') { return [pscustomobject]@{ StatusCode = 200; Content = @() } }
            return [pscustomobject]@{ StatusCode = 201; Content = @{} }
        }

        Publish-GitLabDocumentationWikiManifest -Path $manifestPath -BaseApiUrl 'https://gitlab.example/api/v4' -GitLabProjectId '42' -Token 'test-token'

        Should -Invoke Invoke-GitLabWikiRestMethod -Times 5 -ParameterFilter { $Method -eq 'POST' -and $Headers['PRIVATE-TOKEN'] -eq 'test-token' }
        Should -Invoke Invoke-GitLabWikiRestMethod -Times 0 -ParameterFilter { $Method -eq 'DELETE' }
    }

    It 'updates existing pages by their API-provided slug' {
        $manifestPath = New-GitLabDocumentationFixture -Root $TestDrive
        Mock Invoke-GitLabWikiRestMethod {
            if ($Method -eq 'GET') {
                $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
                return [pscustomobject]@{
                    StatusCode = 200
                    Content = @($manifest.pages | ForEach-Object {
                        $slug = ([string]$_.wikiPath).TrimStart('/')
                        [pscustomobject]@{ title = ($slug -split '/')[-1]; slug = $slug }
                    })
                }
            }
            return [pscustomobject]@{ StatusCode = 200; Content = @{} }
        }

        Publish-GitLabDocumentationWikiManifest -Path $manifestPath -BaseApiUrl 'https://gitlab.example/api/v4' -GitLabProjectId '42' -Token 'test-token'

        Should -Invoke Invoke-GitLabWikiRestMethod -Times 5 -ParameterFilter { $Method -eq 'PUT' }
        Should -Invoke Invoke-GitLabWikiRestMethod -Times 4 -ParameterFilter { $Method -eq 'PUT' -and $Uri -match '/wikis/Documentation%2F' }
        Should -Invoke Invoke-GitLabWikiRestMethod -Times 0 -ParameterFilter { $Method -eq 'POST' }
    }

    It 'rejects unsafe API settings before making a request' {
        $manifestPath = New-GitLabDocumentationFixture -Root $TestDrive

        { Publish-GitLabDocumentationWikiManifest -Path $manifestPath -BaseApiUrl 'http://gitlab.example/api/v4' -GitLabProjectId '42' -Token 'test-token' } | Should -Throw
        { Publish-GitLabDocumentationWikiManifest -Path $manifestPath -BaseApiUrl 'https://gitlab.example/api/v4' -GitLabProjectId '../42' -Token 'test-token' } | Should -Throw
        { Publish-GitLabDocumentationWikiManifest -Path $manifestPath -BaseApiUrl 'https://gitlab.example/api/v4' -GitLabProjectId '42' -Token '' } | Should -Throw
    }

    It 'creates the security summary wiki page from the generated table' {
        $summary = Join-Path $TestDrive 'summary.md'
        Set-Content -LiteralPath $summary -Value "# Security scan tool breakdown`n`n| Tool | Total |`n| --- | ---: |`n| Trivy | 3 |`n" -Encoding utf8
        Mock Invoke-GitLabWikiRestMethod {
            if ($Method -eq 'GET') { return [pscustomobject]@{ StatusCode = 200; Content = @() } }
            return [pscustomobject]@{ StatusCode = 201; Content = @{} }
        }

        Publish-GitLabSecuritySummaryWikiPage -Path $summary -WikiPath '/Documentation/Security-Findings-Summary' -BaseApiUrl 'https://gitlab.example/api/v4' -GitLabProjectId '42' -Token 'test-token'

        Should -Invoke Invoke-GitLabWikiRestMethod -Times 1 -ParameterFilter { $Method -eq 'POST' -and $Body.title -eq 'Documentation/Security-Findings-Summary' -and $Body.content -match 'Security scan tool breakdown' }
        Should -Invoke Invoke-GitLabWikiRestMethod -Times 0 -ParameterFilter { $Method -eq 'DELETE' }
    }

    It 'updates an existing security summary wiki page by its slug' {
        $summary = Join-Path $TestDrive 'summary.md'
        Set-Content -LiteralPath $summary -Value "# Security scan tool breakdown`n`n| Tool | Total |`n| --- | ---: |`n| Trivy | 3 |`n" -Encoding utf8
        Mock Invoke-GitLabWikiRestMethod {
            if ($Method -eq 'GET') { return [pscustomobject]@{ StatusCode = 200; Content = @([pscustomobject]@{ title = 'Security-Findings-Summary'; slug = 'Documentation/Security-Findings-Summary' }) } }
            return [pscustomobject]@{ StatusCode = 200; Content = @{} }
        }

        Publish-GitLabSecuritySummaryWikiPage -Path $summary -WikiPath '/Documentation/Security-Findings-Summary' -BaseApiUrl 'https://gitlab.example/api/v4' -GitLabProjectId '42' -Token 'test-token'

        Should -Invoke Invoke-GitLabWikiRestMethod -Times 1 -ParameterFilter { $Method -eq 'PUT' -and $Uri -match '/wikis/Documentation%2FSecurity-Findings-Summary' }
        Should -Invoke Invoke-GitLabWikiRestMethod -Times 0 -ParameterFilter { $Method -eq 'POST' }
    }

    It 'rejects an out-of-namespace security summary wiki path' {
        $summary = Join-Path $TestDrive 'summary.md'
        Set-Content -LiteralPath $summary -Value "# Security scan tool breakdown`n" -Encoding utf8

        { Publish-GitLabSecuritySummaryWikiPage -Path $summary -WikiPath '/Secrets/Findings' -BaseApiUrl 'https://gitlab.example/api/v4' -GitLabProjectId '42' -Token 'test-token' } | Should -Throw
    }
}