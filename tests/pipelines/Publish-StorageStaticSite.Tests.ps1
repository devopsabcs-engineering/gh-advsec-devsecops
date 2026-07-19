$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repositoryRoot 'scripts\static\Publish-StorageStaticSite.ps1')

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