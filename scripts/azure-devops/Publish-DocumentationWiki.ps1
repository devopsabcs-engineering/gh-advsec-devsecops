[CmdletBinding()]
param(
    [ValidateSet('Stage', 'Publish')]
    [string]$Mode,
    [string]$RepositoryRoot,
    [string]$StagingPath,
    [string]$OrganizationUrl,
    [string]$Project,
    [string]$WikiIdentifier,
    [string]$AccessToken = $env:SYSTEM_ACCESSTOKEN,
    [switch]$SkipEntrypoint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-DocumentationWikiMappings {
    return @(
        [pscustomobject]@{ Order = 10; SourcePath = 'docs/devsecops-concepts.md'; WikiPath = '/Documentation/DevSecOps-Concepts'; StagedFile = '010-devsecops-concepts.md'; Title = 'DevSecOps Concepts' }
        [pscustomobject]@{ Order = 20; SourcePath = 'docs/ghas-mdc-devsecops.md'; WikiPath = '/Documentation/GHAS-MDC-DevSecOps'; StagedFile = '020-ghas-mdc-devsecops.md'; Title = 'Agentic AI for DevSecOps' }
        [pscustomobject]@{ Order = 30; SourcePath = 'docs/GHAS-MDC-L400-Guide.md'; WikiPath = '/Documentation/GHAS-MDC-L400-Guide'; StagedFile = '030-ghas-mdc-l400-guide.md'; Title = 'GHAS and MDC L400 Guide' }
        [pscustomobject]@{ Order = 40; SourcePath = 'docs/templates/security-plan-template.md'; WikiPath = '/Documentation/Security-Plan-Template'; StagedFile = '040-security-plan-template.md'; Title = 'Security Plan Template' }
    )
}

function Assert-DocumentationWikiPath {
    param([Parameter(Mandatory)][string]$WikiPath)

    if ($WikiPath -match '[\u0000-\u001F\u007F\\]' -or
        $WikiPath -match '\.\.' -or
        $WikiPath -notmatch '^/Documentation(?:/[A-Za-z0-9][A-Za-z0-9.-]*)?$') {
        throw "Wiki path is outside the /Documentation namespace: $WikiPath"
    }
}

function ConvertTo-DocumentationWikiContent {
    param([Parameter(Mandatory)][string]$Markdown)

    $withoutFrontmatter = [regex]::Replace(
        $Markdown,
        '\A---[ \t]*\r?\n.*?\r?\n---[ \t]*(?:\r?\n|\z)',
        '',
        [System.Text.RegularExpressions.RegexOptions]::Singleline
    )
    if ([string]::IsNullOrWhiteSpace($withoutFrontmatter)) {
        throw 'Documentation page content is empty after frontmatter removal.'
    }
    if ($withoutFrontmatter -match '[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]') {
        throw 'Documentation page content contains control characters.'
    }
    if ($withoutFrontmatter -match '(?is)<\s*(?:script|iframe|object|embed|form|input|button)\b|\son[a-z]+\s*=|javascript\s*:|data\s*:\s*text/html') {
        throw 'Documentation page content contains active script or embedded input material.'
    }
    if ($withoutFrontmatter -match '(?i)bearer\s+[A-Za-z0-9._~-]{8,}|system\.accesstoken|(?:client[_-]?secret|account[_-]?key|sas[_-]?token|access[_-]?token)\s*[:=]\s*(?![\[({<*$])[''"]?[A-Za-z0-9+/_.~-]{8,}') {
        throw 'Documentation page content contains credential material.'
    }

    $wikiContent = [regex]::Replace(
        $withoutFrontmatter,
        '(?ms)^## Table of Contents[ \t]*\r?\n.*?^---[ \t]*\r?$',
        "## Table of Contents`n`n[[_TOC_]]`n`n---"
    )

    return $wikiContent.TrimStart("`r", "`n")
}

function Assert-DocumentationWikiMappings {
    param(
        [Parameter(Mandatory)][object[]]$Mappings,
        [Parameter(Mandatory)][string]$RootPath
    )

    if ($Mappings.Count -eq 0) { throw 'At least one documentation mapping is required.' }
    $resolvedRoot = [System.IO.Path]::GetFullPath($RootPath).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    $rootPrefix = "$resolvedRoot$([System.IO.Path]::DirectorySeparatorChar)"
    $wikiPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $sourcePaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $stagedFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($mapping in $Mappings) {
        Assert-DocumentationWikiPath ([string]$mapping.WikiPath)
        if (-not $wikiPaths.Add([string]$mapping.WikiPath)) { throw "Duplicate wiki path mapping: $($mapping.WikiPath)" }
        if (-not $sourcePaths.Add([string]$mapping.SourcePath)) { throw "Duplicate source path mapping: $($mapping.SourcePath)" }
        if ([string]$mapping.StagedFile -notmatch '^[0-9]{3}-[a-z0-9-]+\.md$' -or -not $stagedFiles.Add([string]$mapping.StagedFile)) {
            throw "Invalid or duplicate staged file mapping: $($mapping.StagedFile)"
        }

        $candidate = [System.IO.Path]::GetFullPath((Join-Path $resolvedRoot ([string]$mapping.SourcePath)))
        if (-not $candidate.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Documentation source path escapes the repository root: $($mapping.SourcePath)"
        }
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "Documentation source page is missing: $($mapping.SourcePath)"
        }
    }
}

function New-DocumentationIndexContent {
    param([Parameter(Mandatory)][object[]]$Mappings)

    $lines = @('# Documentation', '', 'Published documentation pages:')
    foreach ($mapping in @($Mappings | Sort-Object Order, WikiPath)) {
        $lines += "* [$($mapping.Title)]($($mapping.WikiPath))"
    }
    return ($lines -join [Environment]::NewLine) + [Environment]::NewLine
}

function Get-DocumentationContentHash {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function New-DocumentationWikiStage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RootPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [object[]]$Mappings = (Get-DocumentationWikiMappings)
    )

    Assert-DocumentationWikiMappings -Mappings $Mappings -RootPath $RootPath
    $resolvedRoot = [System.IO.Path]::GetFullPath($RootPath)
    $resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
    if ($resolvedOutput -eq $resolvedRoot) { throw 'The staging path must not be the repository root.' }
    if (Test-Path -LiteralPath $resolvedOutput) { Remove-Item -LiteralPath $resolvedOutput -Recurse -Force }
    New-Item -ItemType Directory -Path $resolvedOutput -Force | Out-Null

    $pages = [System.Collections.Generic.List[object]]::new()
    $indexPath = Join-Path $resolvedOutput '000-documentation-index.md'
    Set-Content -LiteralPath $indexPath -Value (New-DocumentationIndexContent $Mappings) -Encoding utf8 -NoNewline
    $pages.Add([pscustomobject]@{
        order = 0
        sourcePath = $null
        wikiPath = '/Documentation'
        contentFile = '000-documentation-index.md'
        sha256 = Get-DocumentationContentHash $indexPath
    })

    foreach ($mapping in @($Mappings | Sort-Object Order, WikiPath)) {
        $source = Join-Path $resolvedRoot ([string]$mapping.SourcePath)
        $content = ConvertTo-DocumentationWikiContent (Get-Content -LiteralPath $source -Raw)
        $destination = Join-Path $resolvedOutput ([string]$mapping.StagedFile)
        Set-Content -LiteralPath $destination -Value $content -Encoding utf8 -NoNewline
        $pages.Add([pscustomobject]@{
            order = [int]$mapping.Order
            sourcePath = [string]$mapping.SourcePath
            wikiPath = [string]$mapping.WikiPath
            contentFile = [string]$mapping.StagedFile
            sha256 = Get-DocumentationContentHash $destination
        })
    }

    $manifest = [ordered]@{
        schemaVersion = 1
        namespace = '/Documentation'
        deletionPolicy = 'none'
        pages = @($pages)
    }
    $manifestPath = Join-Path $resolvedOutput 'wiki-documentation-manifest.json'
    $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding utf8
    return $manifestPath
}

function Assert-DocumentationWikiManifest {
    param(
        [Parameter(Mandatory)][object]$Manifest,
        [Parameter(Mandatory)][string]$ManifestRoot
    )

    if ($Manifest.schemaVersion -ne 1 -or $Manifest.namespace -ne '/Documentation' -or $Manifest.deletionPolicy -ne 'none') {
        throw 'Documentation manifest metadata is invalid.'
    }
    $pages = @($Manifest.pages)
    $expectedPaths = @('/Documentation') + @((Get-DocumentationWikiMappings).WikiPath)
    if ($pages.Count -ne $expectedPaths.Count) { throw 'Documentation manifest must contain the index and exactly four approved source pages.' }
    if (Compare-Object @($expectedPaths | Sort-Object) @($pages.wikiPath | Sort-Object)) {
        throw 'Documentation manifest page set differs from the approved mapping.'
    }

    $manifestRootPath = [System.IO.Path]::GetFullPath($ManifestRoot).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    $manifestRootPrefix = "$manifestRootPath$([System.IO.Path]::DirectorySeparatorChar)"
    $seenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $seenFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($page in $pages) {
        Assert-DocumentationWikiPath ([string]$page.wikiPath)
        if (-not $seenPaths.Add([string]$page.wikiPath)) { throw "Duplicate manifest wiki path: $($page.wikiPath)" }
        if ([string]$page.contentFile -notmatch '^[0-9]{3}-[a-z0-9-]+\.md$' -or -not $seenFiles.Add([string]$page.contentFile)) {
            throw "Invalid or duplicate manifest content file: $($page.contentFile)"
        }
        $contentPath = [System.IO.Path]::GetFullPath((Join-Path $manifestRootPath ([string]$page.contentFile)))
        if (-not $contentPath.StartsWith($manifestRootPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $contentPath -PathType Leaf)) {
            throw "Manifest content file is absent or outside the staged artifact: $($page.contentFile)"
        }
        if ((Get-DocumentationContentHash $contentPath) -ne [string]$page.sha256) {
            throw "Manifest content hash does not match: $($page.contentFile)"
        }
        ConvertTo-DocumentationWikiContent (Get-Content -LiteralPath $contentPath -Raw) | Out-Null
    }
}

function Invoke-DocumentationWikiRestMethod {
    param([string]$Method, [string]$Uri, [hashtable]$Headers, [object]$Body)

    $statusCode = $null
    $responseHeaders = $null
    $parameters = @{
        Method = $Method
        Uri = $Uri
        Headers = $Headers
        ContentType = 'application/json'
        SkipHttpErrorCheck = $true
        StatusCodeVariable = 'statusCode'
        ResponseHeadersVariable = 'responseHeaders'
    }
    if ($null -ne $Body) { $parameters.Body = $Body | ConvertTo-Json -Depth 10 }
    $content = Invoke-RestMethod @parameters
    return [pscustomobject]@{ StatusCode = $statusCode; Headers = $responseHeaders; Content = $content }
}

function Publish-DocumentationWikiPage {
    param(
        [Parameter(Mandatory)][string]$OrgUrl,
        [Parameter(Mandatory)][string]$ProjectName,
        [Parameter(Mandatory)][string]$Wiki,
        [Parameter(Mandatory)][string]$WikiPath,
        [Parameter(Mandatory)][string]$Content,
        [Parameter(Mandatory)][string]$Token
    )

    Assert-DocumentationWikiPath $WikiPath
    $safeContent = ConvertTo-DocumentationWikiContent $Content
    $projectSegment = [uri]::EscapeDataString($ProjectName)
    $wikiSegment = [uri]::EscapeDataString($Wiki)
    $encodedPath = [uri]::EscapeDataString($WikiPath)
    $uri = "$($OrgUrl.TrimEnd('/'))/$projectSegment/_apis/wiki/wikis/$wikiSegment/pages?path=$encodedPath&api-version=7.1"
    $headers = @{ Authorization = "Bearer $Token" }
    $current = Invoke-DocumentationWikiRestMethod GET $uri $headers $null
    if ($current.StatusCode -eq 404) {
        $headers['If-None-Match'] = '*'
        $result = Invoke-DocumentationWikiRestMethod PUT $uri $headers @{ content = $safeContent }
        if ($result.StatusCode -notin @(200, 201)) { throw "Wiki page create failed with HTTP $($result.StatusCode): $WikiPath" }
        return
    }
    if ($current.StatusCode -ne 200 -or -not $current.Headers.ETag) {
        throw "Unable to read wiki page or obtain its concurrency token: $WikiPath"
    }
    $headers['If-Match'] = [string]$current.Headers.ETag
    $result = Invoke-DocumentationWikiRestMethod PUT $uri $headers @{ content = $safeContent }
    if ($result.StatusCode -notin @(200, 201)) { throw "Wiki page update failed with HTTP $($result.StatusCode): $WikiPath" }
}

function Publish-DocumentationWikiManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][string]$OrgUrl,
        [Parameter(Mandatory)][string]$ProjectName,
        [Parameter(Mandatory)][string]$Wiki,
        [Parameter(Mandatory)][string]$Token
    )

    if ([string]::IsNullOrWhiteSpace($Token)) { throw 'SYSTEM_ACCESSTOKEN must be mapped explicitly.' }
    if ($OrgUrl -notmatch '^https://[^\s]+$') { throw 'OrganizationUrl must use HTTPS.' }
    foreach ($value in @($ProjectName, $Wiki)) {
        if ([string]::IsNullOrWhiteSpace($value) -or $value -match '[\u0000-\u001F\u007F]') { throw 'Project and wiki identifiers must be nonempty and free of control characters.' }
    }

    $resolvedManifest = (Resolve-Path -LiteralPath $ManifestPath).Path
    $manifestRoot = Split-Path -Parent $resolvedManifest
    $manifest = Get-Content -LiteralPath $resolvedManifest -Raw | ConvertFrom-Json -Depth 20
    Assert-DocumentationWikiManifest -Manifest $manifest -ManifestRoot $manifestRoot
    foreach ($page in @($manifest.pages | Sort-Object order, wikiPath)) {
        $content = Get-Content -LiteralPath (Join-Path $manifestRoot ([string]$page.contentFile)) -Raw
        Publish-DocumentationWikiPage $OrgUrl $ProjectName $Wiki ([string]$page.wikiPath) $content $Token
    }
}

if (-not $SkipEntrypoint -and $Mode -eq 'Stage') {
    if ([string]::IsNullOrWhiteSpace($RepositoryRoot) -or [string]::IsNullOrWhiteSpace($StagingPath)) {
        throw 'RepositoryRoot and StagingPath are required in Stage mode.'
    }
    New-DocumentationWikiStage -RootPath $RepositoryRoot -OutputPath $StagingPath | Out-Null
}
elseif (-not $SkipEntrypoint -and $Mode -eq 'Publish') {
    if ([string]::IsNullOrWhiteSpace($StagingPath)) { throw 'StagingPath is required in Publish mode.' }
    Publish-DocumentationWikiManifest `
        -ManifestPath (Join-Path $StagingPath 'wiki-documentation-manifest.json') `
        -OrgUrl $OrganizationUrl `
        -ProjectName $Project `
        -Wiki $WikiIdentifier `
        -Token $AccessToken
}