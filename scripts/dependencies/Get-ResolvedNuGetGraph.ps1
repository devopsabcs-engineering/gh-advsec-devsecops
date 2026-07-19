[CmdletBinding()]
param(
    [string]$AssetsPath,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ResolvedNuGetGraph {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LiteralPath)

    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        throw "NuGet assets file does not exist: $LiteralPath"
    }

    try {
        $assets = Get-Content -LiteralPath $LiteralPath -Raw | ConvertFrom-Json -Depth 100
    }
    catch {
        throw "NuGet assets file is invalid JSON: $LiteralPath. $($_.Exception.Message)"
    }

    if (-not ($assets.PSObject.Properties.Name -contains 'libraries')) {
        throw "NuGet assets file has no libraries graph: $LiteralPath"
    }

    $packages = foreach ($property in $assets.libraries.PSObject.Properties) {
        if ($property.Value.type -ne 'package' -or $property.Name -notmatch '^(.+)/([^/]+)$') { continue }
        [pscustomobject][ordered]@{
            id = $Matches[1].ToLowerInvariant()
            version = $Matches[2]
        }
    }

    return @($packages | Sort-Object id, version -Unique)
}

if ($PSBoundParameters.ContainsKey('AssetsPath')) {
    $graph = @(Get-ResolvedNuGetGraph -LiteralPath $AssetsPath)
    $json = $graph | ConvertTo-Json -Depth 10
    if ($OutputPath) {
        $parent = Split-Path -Parent $OutputPath
        if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        Set-Content -LiteralPath $OutputPath -Value $json -Encoding utf8NoBOM
    }
    else {
        $json
    }
}
