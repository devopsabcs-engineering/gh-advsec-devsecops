$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repositoryRoot 'scripts\azure-devops\Set-PullRequestComment.ps1')

Describe 'Set-PullRequestComment' {
    It 'creates a marker-owned thread when none exists' {
        Mock Invoke-AdoPullRequestRestMethod {
            if ($Method -eq 'GET') { return [pscustomobject]@{ value = @() } }
            return [pscustomobject]@{ id = 7 }
        }

        Set-PullRequestComment 'https://dev.azure.com/example' 'project' 'repo' 12 '# Result' 'token' | Out-Null

        Assert-MockCalled Invoke-AdoPullRequestRestMethod 1 -ParameterFilter { $Method -eq 'POST' -and $Body.comments[0].content -like '*dependency-change-admission:v1*' }
    }

    It 'updates the existing marker-owned comment without duplication' {
        Mock Invoke-AdoPullRequestRestMethod {
            if ($Method -eq 'GET') {
                return [pscustomobject]@{ value = @([pscustomobject]@{ id = 3; comments = @([pscustomobject]@{ id = 4; content = '<!-- dependency-change-admission:v1 --> old' }) }) }
            }
            return [pscustomobject]@{ id = 4 }
        }

        Set-PullRequestComment 'https://dev.azure.com/example' 'project' 'repo' 12 '# Updated' 'token' | Out-Null

        Assert-MockCalled Invoke-AdoPullRequestRestMethod 1 -ParameterFilter { $Method -eq 'PATCH' -and $Uri -like '*/threads/3/comments/4*' }
    }

    It 'uses a caller-specific marker without replacing another pipeline comment' {
        Mock Invoke-AdoPullRequestRestMethod {
            if ($Method -eq 'GET') {
                return [pscustomobject]@{ value = @([pscustomobject]@{ id = 3; comments = @([pscustomobject]@{ id = 4; content = '<!-- dependency-change-admission:v1 --> old' }) }) }
            }
            return [pscustomobject]@{ id = 8 }
        }

        Set-PullRequestComment 'https://dev.azure.com/example' 'project' 'repo' 12 '# KICS' 'token' '<!-- kics-scan-summary:v1 -->' | Out-Null

        Assert-MockCalled Invoke-AdoPullRequestRestMethod 1 -ParameterFilter { $Method -eq 'POST' -and $Body.comments[0].content -like '*kics-scan-summary:v1*' }
    }

    It 'fails when duplicate marker-owned threads exist' {
        Mock Invoke-AdoPullRequestRestMethod {
            [pscustomobject]@{ value = @(
                [pscustomobject]@{ id = 1; comments = @([pscustomobject]@{ id = 1; content = '<!-- dependency-change-admission:v1 -->' }) },
                [pscustomobject]@{ id = 2; comments = @([pscustomobject]@{ id = 2; content = '<!-- dependency-change-admission:v1 -->' }) }
            ) }
        }

        $threw = $false
        try { Set-PullRequestComment 'https://dev.azure.com/example' 'project' 'repo' 12 '# Result' 'token' | Out-Null } catch { $threw = $true }
        $threw | Should Be $true
    }
}