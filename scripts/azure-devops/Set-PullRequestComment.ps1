[CmdletBinding()]
param(
    [string]$OrganizationUrl,
    [string]$Project,
    [string]$RepositoryId,
    [int]$PullRequestId,
    [string]$MarkdownPath,
    [string]$CommentMarker = '<!-- dependency-change-admission:v1 -->',
    [string]$AccessToken = $env:SYSTEM_ACCESSTOKEN
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-AdoPullRequestRestMethod {
    param([string]$Method, [string]$Uri, [hashtable]$Headers, [object]$Body)
    $parameters = @{ Method = $Method; Uri = $Uri; Headers = $Headers; ContentType = 'application/json' }
    if ($null -ne $Body) { $parameters.Body = $Body | ConvertTo-Json -Depth 20 }
    Invoke-RestMethod @parameters
}

function Set-PullRequestComment {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$OrganizationUrl,
        [Parameter(Mandatory)][string]$Project,
        [Parameter(Mandatory)][string]$RepositoryId,
        [Parameter(Mandatory)][int]$PullRequestId,
        [Parameter(Mandatory)][string]$Markdown,
        [Parameter(Mandatory)][string]$Token,
        [string]$Marker = '<!-- dependency-change-admission:v1 -->'
    )

    if ($Markdown -match '(?i)(bearer\s+[A-Za-z0-9._-]+|system\.accesstoken)') { throw 'Comment content contains token-like material.' }
    if ($Marker -notmatch '^<!-- [a-z0-9-]+:v[0-9]+ -->$') { throw 'Comment marker must use the approved marker-owned format.' }
    if (-not $PSCmdlet.ShouldProcess("pull request $PullRequestId", 'Create or update marker-owned comment')) { return }
    $baseUri = "$($OrganizationUrl.TrimEnd('/'))/$Project/_apis/git/repositories/$RepositoryId/pullRequests/$PullRequestId/threads"
    $headers = @{ Authorization = "Bearer $Token" }
    $threads = Invoke-AdoPullRequestRestMethod -Method GET -Uri "${baseUri}?api-version=7.1" -Headers $headers -Body $null
    $owned = @($threads.value | Where-Object { @($_.comments | Where-Object content -like "*$Marker*").Count -gt 0 })
    if ($owned.Count -gt 1) { throw 'Multiple marker-owned pull request comment threads exist.' }
    $content = "$Marker`n$Markdown"
    if ($owned.Count -eq 1) {
        $comment = @($owned[0].comments | Where-Object content -like "*$Marker*")[0]
        return Invoke-AdoPullRequestRestMethod -Method PATCH -Uri "$baseUri/$($owned[0].id)/comments/$($comment.id)?api-version=7.1" -Headers $headers -Body @{ content = $content; commentType = 1 }
    }
    return Invoke-AdoPullRequestRestMethod -Method POST -Uri "${baseUri}?api-version=7.1" -Headers $headers -Body @{ comments = @(@{ parentCommentId = 0; content = $content; commentType = 1 }); status = 1 }
}

if ($PSBoundParameters.ContainsKey('OrganizationUrl')) {
    if ([string]::IsNullOrWhiteSpace($AccessToken)) { throw 'SYSTEM_ACCESSTOKEN must be mapped explicitly into the script environment.' }
    if (-not (Test-Path -LiteralPath $MarkdownPath -PathType Leaf)) { throw "Comment Markdown does not exist: $MarkdownPath" }
    Set-PullRequestComment -OrganizationUrl $OrganizationUrl -Project $Project -RepositoryId $RepositoryId -PullRequestId $PullRequestId -Markdown (Get-Content -LiteralPath $MarkdownPath -Raw) -Token $AccessToken -Marker $CommentMarker | Out-Null
}