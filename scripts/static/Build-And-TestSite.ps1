[CmdletBinding()]
param(
    [string]$SourcePath,
    [string]$StagingPath,
    [string]$JekyllVersion,
    [string]$JekyllGemSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-StagedStaticSite {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LiteralPath)

    $indexPath = Join-Path $LiteralPath 'index.html'
    if (-not (Test-Path -LiteralPath $indexPath -PathType Leaf)) { throw 'Staged site must contain index.html.' }
    $htmlFiles = @(Get-ChildItem -LiteralPath $LiteralPath -Recurse -File -Filter '*.html')
    foreach ($file in $htmlFiles) {
        $content = Get-Content -LiteralPath $file.FullName -Raw
        foreach ($match in [regex]::Matches($content, '(?i)(?:href|src)=["'']([^"''#?]+)')) {
            $link = $match.Groups[1].Value
            if ($link -match '^(?:[a-z]+:|//|mailto:)') { continue }
            $candidate = if ($link.StartsWith('/')) { Join-Path $LiteralPath $link.TrimStart('/') } else { Join-Path $file.DirectoryName $link }
            if ($candidate.EndsWith('/')) { $candidate = Join-Path $candidate 'index.html' }
            if (-not (Test-Path -LiteralPath $candidate)) { throw "Broken internal link '$link' in $($file.FullName)." }
        }
    }
    return $true
}

function Build-StaticSite {
    [CmdletBinding()]
    param([string]$Source, [string]$Destination, [string]$Version, [string]$GemSha256)
    if (-not $Version -or $GemSha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'Pinned Jekyll version and gem SHA-256 are required.' }
    if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Recurse -Force }
    $toolPath = Join-Path ([System.IO.Path]::GetTempPath()) "jekyll-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $toolPath -Force | Out-Null
    Push-Location $toolPath
    try {
        & gem fetch jekyll --version $Version
        if ($LASTEXITCODE -ne 0) { throw 'Jekyll gem download failed.' }
        $gem = @(Get-ChildItem -LiteralPath . -File -Filter 'jekyll-*.gem')
        if ($gem.Count -ne 1 -or (Get-FileHash $gem[0].FullName -Algorithm SHA256).Hash -ne $GemSha256) { throw 'Jekyll gem integrity verification failed.' }
        & gem install --local $gem[0].FullName --no-document
        if ($LASTEXITCODE -ne 0) { throw 'Pinned Jekyll installation failed.' }
    }
    finally {
        Pop-Location
        Remove-Item -LiteralPath $toolPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    & jekyll "_$Version`_" build --source $Source --destination $Destination
    if ($LASTEXITCODE -ne 0) { throw 'Jekyll build failed.' }
    Test-StagedStaticSite -LiteralPath $Destination | Out-Null
}

if ($PSBoundParameters.ContainsKey('SourcePath')) {
    Build-StaticSite $SourcePath $StagingPath $JekyllVersion $JekyllGemSha256
}
