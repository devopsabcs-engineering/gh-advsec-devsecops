[CmdletBinding()]
param(
    [string]$OrganizationUrl,
    [string]$Project,
    [string]$WikiIdentifier,
    [string]$ReportType,
    [string]$MarkdownPath,
    [string]$ScorecardJsonPath,
    [string]$SourceRevision,
    [string]$RunUrl,
    [string]$ArtifactUrl,
    [string]$PlatformGapDisposition,
    [string]$RoutingPath = '.azuredevops/pipelines/config/visualization-routing.json',
    [string]$AccessToken = $env:SYSTEM_ACCESSTOKEN
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-SafeWikiMarkdown {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Markdown)
    if ($Markdown -match '(?is)<[^>]+>|!\[[^]]*\]\(|javascript:|data:text|bearer\s+[A-Za-z0-9._-]+|system\.accesstoken|authorization\s*:') {
        throw 'Wiki Markdown contains forbidden HTML, active content, images, or credential material.'
    }
    return ($Markdown -replace '[\u0000-\u0008\u000B\u000C\u000E-\u001F]', '')
}

function ConvertTo-ScorecardWikiSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Scorecard,
        [Parameter(Mandatory)][string]$Revision,
        [Parameter(Mandatory)][string]$Disposition,
        [Parameter(Mandatory)][string]$PipelineRunUrl,
        [Parameter(Mandatory)][string]$PipelineArtifactUrl
    )

    if ($null -eq $Scorecard.score -or @($Scorecard.checks).Count -eq 0) {
        throw 'Scorecard JSON lacks the required score or checks.'
    }
    if ($Disposition -notin @('accepted', 'retained', 'retired')) {
        throw 'The Scorecard public-publication disposition is not approved for this pipeline.'
    }
    foreach ($url in @($PipelineRunUrl, $PipelineArtifactUrl)) {
        if ($url -notmatch '^https://[^\s]+$') { throw 'Scorecard wiki links must use HTTPS.' }
    }

    $checkRows = foreach ($check in @($Scorecard.checks | Sort-Object name)) {
        if ([string]::IsNullOrWhiteSpace([string]$check.name) -or $null -eq $check.score) {
            throw 'Scorecard JSON contains an invalid check entry.'
        }
        $safeName = ([string]$check.name -replace '[^A-Za-z0-9 ._+()/\-]', ' ').Trim()
        if ([string]::IsNullOrWhiteSpace($safeName)) { throw 'Scorecard check name contains no publishable characters.' }
        "| $safeName | $($check.score) |"
    }

    return @(
        '# OpenSSF Scorecard summary'
        ''
        "Overall score: $($Scorecard.score)"
        ''
        "Source revision: $Revision"
        ''
        "Public-publication disposition: $Disposition"
        ''
        '| Check | Score |'
        '| --- | ---: |'
        $checkRows
        ''
        "[Pipeline run]($PipelineRunUrl)"
        ''
        "[Authoritative Scorecard JSON artifact]($PipelineArtifactUrl)"
        ''
        'Raw Scorecard JSON is not published to the wiki.'
    ) -join [Environment]::NewLine
}

function Invoke-AdoWikiRestMethod {
    param([string]$Method, [string]$Uri, [hashtable]$Headers, [object]$Body)
    $statusCode = $null
    $responseHeaders = $null
    $parameters = @{ Method = $Method; Uri = $Uri; Headers = $Headers; ContentType = 'application/json'; SkipHttpErrorCheck = $true; StatusCodeVariable = 'statusCode'; ResponseHeadersVariable = 'responseHeaders' }
    if ($null -ne $Body) { $parameters.Body = $Body | ConvertTo-Json -Depth 20 }
    $content = Invoke-RestMethod @parameters
    return [pscustomobject]@{ StatusCode = $statusCode; Headers = $responseHeaders; Content = $content }
}

function Publish-AdoWikiPage {
    param([string]$Uri, [string]$Markdown, [string]$Token, [string]$WikiPath)
    $headers = @{ Authorization = "Bearer $Token" }
    $current = Invoke-AdoWikiRestMethod GET $Uri $headers $null
    if ($current.StatusCode -eq 404) {
        $headers['If-None-Match'] = '*'
        $result = Invoke-AdoWikiRestMethod PUT $Uri $headers @{ content = $Markdown }
        if ($result.StatusCode -notin @(200, 201)) { throw "Wiki page create failed with HTTP $($result.StatusCode): $WikiPath" }
        return
    }
    if ($current.StatusCode -ne 200 -or -not $current.Headers.ETag) { throw "Unable to read wiki page or obtain its concurrency token: $WikiPath" }
    $headers['If-Match'] = [string]$current.Headers.ETag
    $result = Invoke-AdoWikiRestMethod PUT $Uri $headers @{ content = $Markdown }
    if ($result.StatusCode -notin @(200, 201)) { throw "Wiki page update failed with HTTP $($result.StatusCode): $WikiPath" }
}

function Publish-WikiSummary {
    [CmdletBinding()]
    param([string]$OrgUrl, [string]$ProjectName, [string]$Wiki, [object]$Route, [string]$Markdown, [string]$Token)
    if ($Route.wikiFallback -ne $true -or [string]::IsNullOrWhiteSpace([string]$Route.wikiPath)) { throw 'Report type is not approved for project-wiki publication.' }
    if ($Route.wikiPath -notmatch '^(Security|Governance)/[A-Za-z0-9][A-Za-z0-9/-]*$' -or $Route.wikiPath -match '\.\.') { throw 'Wiki path is outside the approved allowlist.' }
    $safe = ConvertTo-SafeWikiMarkdown $Markdown
    if ($safe -notmatch 'https://') { throw 'Wiki summary must link to authoritative evidence.' }
    $baseUri = "$($OrgUrl.TrimEnd('/'))/$ProjectName/_apis/wiki/wikis/$Wiki/pages"
    $parentPath = "/$($Route.wikiPath.Split('/')[0])"
    $parentUri = "$baseUri`?path=$([uri]::EscapeDataString($parentPath))&api-version=7.1"
    Publish-AdoWikiPage $parentUri "# $($parentPath.TrimStart('/'))" $Token $parentPath
    $encodedPath = [uri]::EscapeDataString("/$($Route.wikiPath)")
    $uri = "$baseUri`?path=$encodedPath&api-version=7.1"
    Publish-AdoWikiPage $uri $safe $Token "/$($Route.wikiPath)"
}

if ($PSBoundParameters.ContainsKey('OrganizationUrl')) {
    if (-not $AccessToken) { throw 'SYSTEM_ACCESSTOKEN must be mapped explicitly.' }
    $routing = Get-Content -LiteralPath $RoutingPath -Raw | ConvertFrom-Json -Depth 100
    $route = @($routing.routes | Where-Object reportType -eq $ReportType)
    if ($route.Count -ne 1) { throw "Unknown or duplicate report route: $ReportType" }
    if ($ReportType -eq 'openssf-scorecard') {
        if (-not $ScorecardJsonPath) { throw 'ScorecardJsonPath is required for the OpenSSF Scorecard route.' }
        $scorecard = Get-Content -LiteralPath $ScorecardJsonPath -Raw | ConvertFrom-Json -Depth 100
        $markdown = ConvertTo-ScorecardWikiSummary $scorecard $SourceRevision $PlatformGapDisposition $RunUrl $ArtifactUrl
    }
    else {
        if (-not $MarkdownPath) { throw 'MarkdownPath is required for this report route.' }
        $markdown = Get-Content -LiteralPath $MarkdownPath -Raw
    }
    Publish-WikiSummary $OrganizationUrl $Project $WikiIdentifier $route[0] $markdown $AccessToken | Out-Null
}