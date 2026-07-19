[CmdletBinding()]
param([string]$StagingPath, [string]$StorageAccountName)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-AzStorageSync {
    param([string[]]$Arguments)
    & az @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'Static-site reconciliation failed.' }
}

function Publish-StorageStaticSite {
    [CmdletBinding()]
    param([string]$Source, [string]$AccountName)
    if (-not (Test-Path -LiteralPath (Join-Path $Source 'index.html') -PathType Leaf)) { throw 'Only a validated staged site containing index.html can be published.' }
    Invoke-AzStorageSync @('storage', 'blob', 'sync', '--account-name', $AccountName, '--auth-mode', 'login', '--container', '$web', '--source', $Source, '--delete-destination', 'true', '--only-show-errors')
}

if ($PSBoundParameters.ContainsKey('StagingPath')) { Publish-StorageStaticSite $StagingPath $StorageAccountName }