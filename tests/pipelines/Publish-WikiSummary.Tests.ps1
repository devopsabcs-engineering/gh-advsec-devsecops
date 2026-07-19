$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repositoryRoot 'scripts\azure-devops\Publish-WikiSummary.ps1')

function Get-WikiRouteFixture { [pscustomobject]@{ wikiFallback = $true; wikiPath = 'Security/OpenSSF-Scorecard' } }

Describe 'ConvertTo-SafeWikiMarkdown' {
    It 'rejects active or raw embedded content' {
        $threw = $false
        try { ConvertTo-SafeWikiMarkdown '<script>alert(1)</script>' | Out-Null } catch { $threw = $true }
        $threw | Should Be $true
    }

    It 'rejects authorization headers and bearer tokens' {
        foreach ($unsafe in @('Authorization: secret', 'Bearer abc.def_ghi')) {
            $threw = $false
            try { ConvertTo-SafeWikiMarkdown $unsafe | Out-Null } catch { $threw = $true }
            $threw | Should Be $true
        }
    }
}

Describe 'ConvertTo-ScorecardWikiSummary' {
    It 'publishes only allowlisted aggregate fields from valid Scorecard JSON' {
        $fixture = Get-Content -LiteralPath (Join-Path $repositoryRoot 'tests\fixtures\scorecard\valid.json') -Raw | ConvertFrom-Json -Depth 100

        $summary = ConvertTo-ScorecardWikiSummary `
            $fixture `
            '0123456789abcdef' `
            'accepted' `
            'https://dev.azure.com/example/project/_build/results?buildId=42' `
            'https://dev.azure.com/example/project/_build/results?buildId=42&view=artifacts'

        $summary | Should Match 'Overall score: 8\.4'
        $summary | Should Match '\| Binary-Artifacts \| 10 \|'
        $summary | Should Match 'Source revision: 0123456789abcdef'
        $summary | Should Match 'Authoritative Scorecard JSON artifact'
        $summary | Should Not Match 'raw-sensitive-detail'
        $summary | Should Not Match 'reason'
    }

    It 'rejects Scorecard JSON without checks' {
        $fixture = Get-Content -LiteralPath (Join-Path $repositoryRoot 'tests\fixtures\scorecard\invalid-missing-checks.json') -Raw | ConvertFrom-Json -Depth 100
        $threw = $false
        try {
            ConvertTo-ScorecardWikiSummary $fixture 'revision' 'accepted' 'https://example.test/run' 'https://example.test/artifact' | Out-Null
        }
        catch { $threw = $true }
        $threw | Should Be $true
    }
}

Describe 'Publish-WikiSummary' {
    It 'resets REST status and response header capture for every request' {
        $script = Get-Content -LiteralPath (Join-Path $repositoryRoot 'scripts\azure-devops\Publish-WikiSummary.ps1') -Raw
        $script | Should Match 'function Invoke-AdoWikiRestMethod[\s\S]*?\$statusCode = \$null[\s\S]*?\$responseHeaders = \$null[\s\S]*?Invoke-RestMethod @parameters'
    }

    It 'creates an approved page with optimistic create semantics' {
        Mock Invoke-AdoWikiRestMethod {
            if ($Method -eq 'GET') { return [pscustomobject]@{ StatusCode = 404; Headers = @{}; Content = $null } }
            return [pscustomobject]@{ StatusCode = 201; Headers = @{}; Content = @{} }
        }

        Publish-WikiSummary 'https://dev.azure.com/example' 'project' 'project.wiki' (Get-WikiRouteFixture) '# Summary`n[Evidence](https://example.test/run)' 'token' | Out-Null

        Assert-MockCalled Invoke-AdoWikiRestMethod 2 -ParameterFilter { $Method -eq 'PUT' -and $Headers['If-None-Match'] -eq '*' }
    }

    It 'updates an existing page using its ETag' {
        Mock Invoke-AdoWikiRestMethod {
            if ($Method -eq 'GET') { return [pscustomobject]@{ StatusCode = 200; Headers = @{ ETag = '"revision"' }; Content = @{} } }
            return [pscustomobject]@{ StatusCode = 200; Headers = @{}; Content = @{} }
        }

        Publish-WikiSummary 'https://dev.azure.com/example' 'project' 'project.wiki' (Get-WikiRouteFixture) '# Summary`n[Evidence](https://example.test/run)' 'token' | Out-Null

        Assert-MockCalled Invoke-AdoWikiRestMethod 1 -ParameterFilter { $Method -eq 'PUT' -and $Headers['If-Match'] -eq '"revision"' }
    }

    It 'fails closed when the wiki rejects a page create' {
        Mock Invoke-AdoWikiRestMethod {
            if ($Method -eq 'GET') { return [pscustomobject]@{ StatusCode = 404; Headers = @{}; Content = $null } }
            return [pscustomobject]@{ StatusCode = 403; Headers = @{}; Content = @{} }
        }

        $threw = $false
        try { Publish-WikiSummary 'https://dev.azure.com/example' 'project' 'project.wiki' (Get-WikiRouteFixture) '# Summary`n[Evidence](https://example.test/run)' 'token' } catch { $threw = $true }
        $threw | Should Be $true
    }

    It 'rejects paths outside the project-wiki allowlist' {
        $route = [pscustomobject]@{ wikiFallback = $true; wikiPath = '../Unsafe' }
        $threw = $false
        try { Publish-WikiSummary 'https://dev.azure.com/example' 'project' 'project.wiki' $route '[Evidence](https://example.test)' 'token' | Out-Null } catch { $threw = $true }
        $threw | Should Be $true
    }
}