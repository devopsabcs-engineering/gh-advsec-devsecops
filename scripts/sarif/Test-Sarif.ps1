[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-SarifDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath
    )

    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        throw "SARIF file does not exist: $LiteralPath"
    }

    try {
        $document = Get-Content -LiteralPath $LiteralPath -Raw | ConvertFrom-Json -Depth 100
    }
    catch {
        throw "SARIF file is not valid JSON: $LiteralPath. $($_.Exception.Message)"
    }

    if ($document.version -ne '2.1.0') {
        throw "SARIF file must declare version 2.1.0: $LiteralPath"
    }

    if (-not ($document.PSObject.Properties.Name -contains 'runs') -or @($document.runs).Count -eq 0) {
        throw "SARIF file must contain at least one run: $LiteralPath"
    }

    foreach ($run in @($document.runs)) {
        if ($null -eq $run.tool -or $null -eq $run.tool.driver -or [string]::IsNullOrWhiteSpace([string]$run.tool.driver.name)) {
            throw "Every SARIF run must identify tool.driver.name: $LiteralPath"
        }
    }

    return $true
}

$resolvedPath = Resolve-Path -LiteralPath $Path -ErrorAction Stop
$files = if ((Get-Item -LiteralPath $resolvedPath).PSIsContainer) {
    @(Get-ChildItem -LiteralPath $resolvedPath -File -Filter '*.sarif' | Sort-Object FullName)
}
else {
    @(Get-Item -LiteralPath $resolvedPath)
}

if (@($files).Count -eq 0) {
    throw "No SARIF files were found at: $Path"
}

foreach ($file in @($files)) {
    Test-SarifDocument -LiteralPath $file.FullName | Out-Null
    Write-Output "Validated SARIF: $($file.FullName)"
}
