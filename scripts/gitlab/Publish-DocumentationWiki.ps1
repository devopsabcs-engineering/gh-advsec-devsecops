[CmdletBinding()]
param(
    [ValidateSet('Stage', 'Publish', 'PublishSecuritySummary')]
    [string]$Mode,
    [string]$RepositoryRoot,
    [string]$StagingPath,
    [string]$ManifestPath,
    [string]$SummaryPath,
    [string]$WikiPath = '/Documentation/Security-Findings-Summary',
    [string]$ApiUrl = $env:CI_API_V4_URL,
    [string]$ProjectId = $env:CI_PROJECT_ID,
    [string]$AccessToken = $env:GITLAB_WIKI_TOKEN
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$entrypoint = @{
    Mode = $Mode
    RepositoryRoot = $RepositoryRoot
    StagingPath = $StagingPath
    ManifestPath = $ManifestPath
    SummaryPath = $SummaryPath
    WikiPath = $WikiPath
    ApiUrl = $ApiUrl
    ProjectId = $ProjectId
    AccessToken = $AccessToken
}
. (Join-Path $PSScriptRoot '..\azure-devops\Publish-DocumentationWiki.ps1') -SkipEntrypoint
$Mode = $entrypoint.Mode
$RepositoryRoot = $entrypoint.RepositoryRoot
$StagingPath = $entrypoint.StagingPath
$ManifestPath = $entrypoint.ManifestPath
$SummaryPath = $entrypoint.SummaryPath
$WikiPath = $entrypoint.WikiPath
$ApiUrl = $entrypoint.ApiUrl
$ProjectId = $entrypoint.ProjectId
$AccessToken = $entrypoint.AccessToken

function Invoke-GitLabWikiRestMethod {
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers,
        [object]$Body
    )

    $statusCode = $null
    $parameters = @{
        Method = $Method
        Uri = $Uri
        Headers = $Headers
        ContentType = 'application/json'
        SkipHttpErrorCheck = $true
        StatusCodeVariable = 'statusCode'
    }
    if ($null -ne $Body) { $parameters.Body = $Body | ConvertTo-Json -Depth 10 }
    $content = Invoke-RestMethod @parameters
    return [pscustomobject]@{ StatusCode = $statusCode; Content = $content }
}

function Publish-GitLabDocumentationWikiManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$BaseApiUrl,
        [Parameter(Mandatory)][string]$GitLabProjectId,
        [Parameter(Mandatory)][string]$Token
    )

    if ($BaseApiUrl -notmatch '^https://[^\s]+$') { throw 'GitLab API URL must use HTTPS.' }
    if ($GitLabProjectId -notmatch '^[1-9][0-9]*$') { throw 'GitLab project ID must be numeric.' }
    if ([string]::IsNullOrWhiteSpace($Token)) { throw 'GITLAB_WIKI_TOKEN must be mapped explicitly.' }

    $resolvedManifest = (Resolve-Path -LiteralPath $Path).Path
    $manifestRoot = Split-Path -Parent $resolvedManifest
    $manifest = Get-Content -LiteralPath $resolvedManifest -Raw | ConvertFrom-Json -Depth 20
    Assert-DocumentationWikiManifest -Manifest $manifest -ManifestRoot $manifestRoot

    $headers = @{ 'PRIVATE-TOKEN' = $Token }
    $projectUri = "$($BaseApiUrl.TrimEnd('/'))/projects/$GitLabProjectId/wikis"
    $current = Invoke-GitLabWikiRestMethod -Method GET -Uri "${projectUri}?with_content=false" -Headers $headers
    if ($current.StatusCode -ne 200) { throw "Unable to list GitLab Wiki pages: HTTP $($current.StatusCode)." }

    $existingPages = @($current.Content)
    foreach ($page in @($manifest.pages | Sort-Object order, wikiPath)) {
        $title = ([string]$page.wikiPath).TrimStart('/')
        $contentPath = Join-Path $manifestRoot ([string]$page.contentFile)
        $content = ConvertTo-DocumentationWikiContent (Get-Content -LiteralPath $contentPath -Raw)
        $existing = @($existingPages | Where-Object { ([string]$_.slug).TrimStart('/') -eq $title })
        if ($existing.Count -gt 1) { throw "GitLab Wiki contains duplicate managed pages: $title" }

        if ($existing.Count -eq 0) {
            $result = Invoke-GitLabWikiRestMethod -Method POST -Uri $projectUri -Headers $headers -Body @{ title = $title; content = $content }
            if ($result.StatusCode -ne 201) { throw "GitLab Wiki page create failed with HTTP $($result.StatusCode): $title" }
            continue
        }

        $slug = [uri]::EscapeDataString([string]$existing[0].slug)
        $result = Invoke-GitLabWikiRestMethod -Method PUT -Uri "$projectUri/$slug" -Headers $headers -Body @{ title = $title; content = $content }
        if ($result.StatusCode -ne 200) { throw "GitLab Wiki page update failed with HTTP $($result.StatusCode): $title" }
    }
}

function Publish-GitLabSecuritySummaryWikiPage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$WikiPath,
        [Parameter(Mandatory)][string]$BaseApiUrl,
        [Parameter(Mandatory)][string]$GitLabProjectId,
        [Parameter(Mandatory)][string]$Token
    )

    if ($BaseApiUrl -notmatch '^https://[^\s]+$') { throw 'GitLab API URL must use HTTPS.' }
    if ($GitLabProjectId -notmatch '^[1-9][0-9]*$') { throw 'GitLab project ID must be numeric.' }
    if ([string]::IsNullOrWhiteSpace($Token)) { throw 'GITLAB_WIKI_TOKEN must be mapped explicitly.' }
    Assert-DocumentationWikiPath -WikiPath $WikiPath
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Security summary markdown was not found: $Path" }

    # Reuse the documentation sanitizer so the generated table is subject to the same
    # script/credential/control-character guards as approved documentation pages.
    $content = ConvertTo-DocumentationWikiContent (Get-Content -LiteralPath $Path -Raw)

    $headers = @{ 'PRIVATE-TOKEN' = $Token }
    $title = $WikiPath.TrimStart('/')
    $projectUri = "$($BaseApiUrl.TrimEnd('/'))/projects/$GitLabProjectId/wikis"
    $current = Invoke-GitLabWikiRestMethod -Method GET -Uri "${projectUri}?with_content=false" -Headers $headers
    if ($current.StatusCode -ne 200) { throw "Unable to list GitLab Wiki pages: HTTP $($current.StatusCode)." }

    $existing = @(@($current.Content) | Where-Object { ([string]$_.slug).TrimStart('/') -eq $title })
    if ($existing.Count -gt 1) { throw "GitLab Wiki contains duplicate managed pages: $title" }

    if ($existing.Count -eq 0) {
        $result = Invoke-GitLabWikiRestMethod -Method POST -Uri $projectUri -Headers $headers -Body @{ title = $title; content = $content }
        if ($result.StatusCode -ne 201) { throw "GitLab Wiki page create failed with HTTP $($result.StatusCode): $title" }
        return
    }

    $slug = [uri]::EscapeDataString([string]$existing[0].slug)
    $result = Invoke-GitLabWikiRestMethod -Method PUT -Uri "$projectUri/$slug" -Headers $headers -Body @{ title = $title; content = $content }
    if ($result.StatusCode -ne 200) { throw "GitLab Wiki page update failed with HTTP $($result.StatusCode): $title" }
}

if ($Mode -eq 'Stage') {
    if ([string]::IsNullOrWhiteSpace($RepositoryRoot) -or [string]::IsNullOrWhiteSpace($StagingPath)) {
        throw 'RepositoryRoot and StagingPath are required in Stage mode.'
    }
    New-DocumentationWikiStage -RootPath $RepositoryRoot -OutputPath $StagingPath
}
elseif ($Mode -eq 'Publish') {
    if ([string]::IsNullOrWhiteSpace($ManifestPath)) { throw 'ManifestPath is required in Publish mode.' }
    Publish-GitLabDocumentationWikiManifest -Path $ManifestPath -BaseApiUrl $ApiUrl -GitLabProjectId $ProjectId -Token $AccessToken
}
elseif ($Mode -eq 'PublishSecuritySummary') {
    if ([string]::IsNullOrWhiteSpace($SummaryPath)) { throw 'SummaryPath is required in PublishSecuritySummary mode.' }
    Publish-GitLabSecuritySummaryWikiPage -Path $SummaryPath -WikiPath $WikiPath -BaseApiUrl $ApiUrl -GitLabProjectId $ProjectId -Token $AccessToken
}
