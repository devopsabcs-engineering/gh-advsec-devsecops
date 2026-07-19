$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repositoryRoot 'scripts\static\Build-And-TestSite.ps1')
. (Join-Path $repositoryRoot 'scripts\static\Publish-StorageStaticSite.ps1')

Describe 'Test-StagedStaticSite' {
    It 'accepts a staged index with valid internal links' {
        New-Item -ItemType Directory -Path (Join-Path $TestDrive 'assets') | Out-Null
        Set-Content -LiteralPath (Join-Path $TestDrive 'assets\site.css') -Value 'body {}'
        Set-Content -LiteralPath (Join-Path $TestDrive 'index.html') -Value '<link href="assets/site.css"><h1>Site</h1>'

        Test-StagedStaticSite $TestDrive | Should Be $true
    }

    It 'rejects broken internal links' {
        Set-Content -LiteralPath (Join-Path $TestDrive 'index.html') -Value '<a href="missing.html">Missing</a>'
        $threw = $false
        try { Test-StagedStaticSite $TestDrive | Out-Null } catch { $threw = $true }
        $threw | Should Be $true
    }
}

Describe 'Publish-StorageStaticSite' {
    It 'reconciles staged output and deletes stale blobs using Entra authentication' {
        Set-Content -LiteralPath (Join-Path $TestDrive 'index.html') -Value '<h1>Site</h1>'
        Mock Invoke-AzStorageSync

        Publish-StorageStaticSite $TestDrive 'docsaccount'

        Assert-MockCalled Invoke-AzStorageSync 1 -ParameterFilter {
            $Arguments -contains 'sync' -and
            $Arguments -contains '--auth-mode' -and
            $Arguments -contains 'login' -and
            $Arguments -contains '--container' -and
            $Arguments -contains '$web' -and
            $Arguments -contains '--delete-destination' -and
            $Arguments -contains 'true' -and
            $Arguments -notcontains '--account-key' -and
            $Arguments -notcontains '--sas-token'
        }
    }
}
