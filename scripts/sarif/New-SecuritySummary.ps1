<#
.SYNOPSIS
    Aggregates every scanner's SARIF output into a single per-tool breakdown and a GitLab
    Code Quality report.

.DESCRIPTION
    GitLab's native Vulnerability Report / Security Dashboard (which group findings by
    scanner, the way GitHub Advanced Security does) require the Ultimate tier. This project
    stays on a non-Ultimate plan, so this script reproduces the "tool breakdown" view without
    it:

      * It walks every *.sarif file produced by the security jobs, counts results per tool and
        per severity, and renders a Markdown table + a self-contained HTML page (published to
        GitLab Pages) that mirrors GitHub's Code scanning tool breakdown.
      * It emits a GitLab Code Quality report (CodeClimate JSON). Code Quality is available on
        every GitLab tier, so source-file findings surface inline in the merge request diff and
        the MR "Code Quality" widget.

    The script never fails the pipeline on findings; callers decide policy. It only throws on
    an unusable invocation (for example, a missing repository root).

.PARAMETER InputRoot
    Directory scanned recursively for *.sarif files. Defaults to 'security-results'.

.PARAMETER OutputDirectory
    Directory that receives summary.json, summary.md, index.html and (by default) the Code
    Quality report. Defaults to '<InputRoot>/summary'.

.PARAMETER CodeQualityPath
    Path of the emitted CodeClimate report. Defaults to
    '<OutputDirectory>/gl-code-quality-report.json'.

.PARAMETER RepositoryRoot
    Repository root used to resolve SARIF locations to repo-relative paths. Only findings that
    resolve to a file under this root are added to the Code Quality report so that merge
    request annotations map to real source files.
#>
[CmdletBinding()]
param(
    [string]$InputRoot = 'security-results',
    [string]$OutputDirectory,
    [string]$CodeQualityPath,
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Prop {
    param([object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-SeverityBucket {
    <#
        Maps a SARIF result to one of Critical/High/Medium/Low/Info. A numeric CVSS-style
        'security-severity' (0-10) takes precedence over the SARIF level keyword, matching how
        both GitHub and GitLab rank findings.
    #>
    param([object]$Result, [hashtable]$RuleSeverity)

    $ruleId = [string](Get-Prop $Result 'ruleId')
    $score = $null

    $properties = Get-Prop $Result 'properties'
    $inlineScore = Get-Prop $properties 'security-severity'
    if ($null -ne $inlineScore) { $score = $inlineScore }
    elseif ($ruleId -and $RuleSeverity.ContainsKey($ruleId)) { $score = $RuleSeverity[$ruleId] }

    if ($null -ne $score) {
        $numeric = 0.0
        if ([double]::TryParse([string]$score, [ref]$numeric)) {
            if ($numeric -ge 9.0) { return 'Critical' }
            if ($numeric -ge 7.0) { return 'High' }
            if ($numeric -ge 4.0) { return 'Medium' }
            if ($numeric -gt 0.0) { return 'Low' }
        }
    }

    switch ([string](Get-Prop $Result 'level')) {
        'error' { return 'High' }
        'warning' { return 'Medium' }
        'note' { return 'Low' }
        default { return 'Info' }
    }
}

function ConvertTo-CodeQualitySeverity {
    param([string]$Bucket)
    switch ($Bucket) {
        'Critical' { 'critical' }
        'High' { 'major' }
        'Medium' { 'minor' }
        'Low' { 'minor' }
        default { 'info' }
    }
}

function Resolve-RepoRelativePath {
    <#
        Normalises a SARIF artifact URI to a repo-relative path. Returns $null when the URI is
        not a file inside the repository (for example a container image reference from a
        registry scan), so callers can exclude it from Code Quality annotations.
    #>
    param([string]$Uri, [string]$Root)

    if ([string]::IsNullOrWhiteSpace($Uri)) { return $null }
    $path = $Uri -replace '^file:///?', ''
    $path = $path -replace '\\', '/'
    if ($path -match '^[a-z][a-z0-9+.-]*://') { return $null }   # http(s), oci, etc.

    $normalizedRoot = ($Root -replace '\\', '/').TrimEnd('/')
    if ($normalizedRoot -and $path.StartsWith("$normalizedRoot/")) {
        $path = $path.Substring($normalizedRoot.Length + 1)
    }
    # Strip a GitLab CI checkout prefix such as /builds/<group>/<project>/.
    $path = $path -replace '^/?builds/[^/]+/[^/]+/', ''
    $path = $path.TrimStart('/')
    if (-not $path) { return $null }

    $candidate = Join-Path $Root ($path -replace '/', [IO.Path]::DirectorySeparatorChar)
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $null }
    return $path
}

if (-not (Test-Path -LiteralPath $RepositoryRoot -PathType Container)) {
    throw "RepositoryRoot does not exist: $RepositoryRoot"
}
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $InputRoot 'summary' }
if (-not $CodeQualityPath) { $CodeQualityPath = Join-Path $OutputDirectory 'gl-code-quality-report.json' }

$buckets = @('Critical', 'High', 'Medium', 'Low', 'Info')
$toolStats = [ordered]@{}
$codeQuality = [System.Collections.Generic.List[object]]::new()
$hasher = [System.Security.Cryptography.SHA256]::Create()

$sarifFiles = @()
if (Test-Path -LiteralPath $InputRoot -PathType Container) {
    $resolvedOutput = [IO.Path]::GetFullPath($OutputDirectory)
    $sarifFiles = @(
        Get-ChildItem -LiteralPath $InputRoot -Recurse -Filter '*.sarif' -File |
            Where-Object { -not $_.FullName.StartsWith($resolvedOutput, [StringComparison]::OrdinalIgnoreCase) }
    )
}

foreach ($file in $sarifFiles) {
    try {
        $sarif = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json -Depth 100
    }
    catch {
        Write-Warning "Skipping unparseable SARIF file: $($file.FullName)"
        continue
    }

    foreach ($run in @(Get-Prop $sarif 'runs')) {
        $driver = Get-Prop (Get-Prop $run 'tool') 'driver'
        $toolName = [string](Get-Prop $driver 'name')
        if (-not $toolName) { $toolName = $file.Directory.Name }

        $ruleSeverity = @{}
        foreach ($rule in @(Get-Prop $driver 'rules')) {
            $ruleId = [string](Get-Prop $rule 'id')
            $ruleProps = Get-Prop $rule 'properties'
            $ruleScore = Get-Prop $ruleProps 'security-severity'
            if ($ruleId -and $null -ne $ruleScore) { $ruleSeverity[$ruleId] = $ruleScore }
        }

        if (-not $toolStats.Contains($toolName)) {
            $entry = [ordered]@{ tool = $toolName; Total = 0 }
            foreach ($bucket in $buckets) { $entry[$bucket] = 0 }
            $toolStats[$toolName] = $entry
        }

        foreach ($result in @(Get-Prop $run 'results')) {
            $bucket = Get-SeverityBucket -Result $result -RuleSeverity $ruleSeverity
            $toolStats[$toolName][$bucket]++
            $toolStats[$toolName]['Total']++

            $message = [string](Get-Prop (Get-Prop $result 'message') 'text')
            $ruleId = [string](Get-Prop $result 'ruleId')
            $firstLocation = @(Get-Prop $result 'locations') | Select-Object -First 1
            $physical = Get-Prop $firstLocation 'physicalLocation'
            $uri = [string](Get-Prop (Get-Prop $physical 'artifactLocation') 'uri')
            $relativePath = Resolve-RepoRelativePath -Uri $uri -Root $RepositoryRoot
            if (-not $relativePath) { continue }

            $line = 1
            $region = Get-Prop $physical 'region'
            $startLine = Get-Prop $region 'startLine'
            if ($null -ne $startLine) { $line = [int]$startLine }

            $fingerprintSource = "$toolName|$ruleId|$relativePath|$line|$message"
            $fingerprint = ([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($fingerprintSource))) -replace '-', '').ToLowerInvariant()
            $description = if ($message) { "${toolName}: $message" } else { "$toolName finding: $ruleId" }

            $codeQuality.Add([ordered]@{
                description = $description
                check_name = if ($ruleId) { $ruleId } else { $toolName }
                fingerprint = $fingerprint
                severity = ConvertTo-CodeQualitySeverity -Bucket $bucket
                location = [ordered]@{ path = $relativePath; lines = [ordered]@{ begin = $line } }
            })
        }
    }
}

$hasher.Dispose()

$rows = @($toolStats.Values | Sort-Object -Property @{ Expression = 'Total'; Descending = $true }, @{ Expression = 'tool'; Descending = $false })
$totals = [ordered]@{ tool = 'TOTAL'; Total = 0 }
foreach ($bucket in $buckets) { $totals[$bucket] = 0 }
foreach ($row in $rows) {
    $totals['Total'] += $row['Total']
    foreach ($bucket in $buckets) { $totals[$bucket] += $row[$bucket] }
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$commit = if ($env:CI_COMMIT_SHA) { $env:CI_COMMIT_SHA } else { 'local' }
$generatedAt = [DateTime]::UtcNow.ToString('u')

# summary.json (machine readable)
[ordered]@{
    generatedAtUtc = $generatedAt
    commit = $commit
    sarifFileCount = $sarifFiles.Count
    totals = $totals
    tools = $rows
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'summary.json') -Encoding utf8NoBOM

# summary.md (Markdown table)
$md = [System.Text.StringBuilder]::new()
[void]$md.AppendLine('# Security scan tool breakdown')
[void]$md.AppendLine('')
[void]$md.AppendLine("Generated: $generatedAt UTC &middot; Commit: ``$commit`` &middot; SARIF files: $($sarifFiles.Count)")
[void]$md.AppendLine('')
[void]$md.AppendLine('| Tool | Total | Critical | High | Medium | Low | Info |')
[void]$md.AppendLine('| --- | ---: | ---: | ---: | ---: | ---: | ---: |')
foreach ($row in $rows) {
    [void]$md.AppendLine("| $($row['tool']) | $($row['Total']) | $($row['Critical']) | $($row['High']) | $($row['Medium']) | $($row['Low']) | $($row['Info']) |")
}
[void]$md.AppendLine("| **TOTAL** | **$($totals['Total'])** | **$($totals['Critical'])** | **$($totals['High'])** | **$($totals['Medium'])** | **$($totals['Low'])** | **$($totals['Info'])** |")
$md.ToString() | Set-Content -LiteralPath (Join-Path $OutputDirectory 'summary.md') -Encoding utf8NoBOM

# index.html (self-contained page for GitLab Pages)
function ConvertTo-HtmlText {
    param([string]$Text)
    return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;')
}
$htmlRows = [System.Text.StringBuilder]::new()
foreach ($row in $rows) {
    [void]$htmlRows.AppendLine("      <tr><td class=""tool"">$(ConvertTo-HtmlText -Text $row['tool'])</td><td>$($row['Total'])</td><td class=""crit"">$($row['Critical'])</td><td class=""high"">$($row['High'])</td><td class=""med"">$($row['Medium'])</td><td class=""low"">$($row['Low'])</td><td class=""info"">$($row['Info'])</td></tr>")
}
$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security scan tool breakdown</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 2rem; color: #1f2328; }
  h1 { font-size: 1.4rem; }
  .meta { color: #656d76; margin-bottom: 1rem; font-size: .9rem; }
  table { border-collapse: collapse; width: 100%; max-width: 900px; }
  th, td { padding: .5rem .75rem; border-bottom: 1px solid #d0d7de; text-align: right; }
  th:first-child, td.tool { text-align: left; font-weight: 600; }
  thead th { background: #f6f8fa; border-bottom: 2px solid #d0d7de; }
  tbody tr:hover { background: #f6f8fa; }
  td.crit { color: #cf222e; font-weight: 600; }
  td.high { color: #bc4c00; font-weight: 600; }
  td.med  { color: #9a6700; }
  td.low  { color: #0969da; }
  td.info { color: #656d76; }
  tfoot td { font-weight: 700; border-top: 2px solid #d0d7de; }
</style>
</head>
<body>
  <h1>Security scan tool breakdown</h1>
  <div class="meta">Generated $generatedAt UTC &middot; commit <code>$commit</code> &middot; $($sarifFiles.Count) SARIF file(s) aggregated</div>
  <table>
    <thead>
      <tr><th>Tool</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr>
    </thead>
    <tbody>
$($htmlRows.ToString().TrimEnd())
    </tbody>
    <tfoot>
      <tr><td class="tool">TOTAL</td><td>$($totals['Total'])</td><td class="crit">$($totals['Critical'])</td><td class="high">$($totals['High'])</td><td class="med">$($totals['Medium'])</td><td class="low">$($totals['Low'])</td><td class="info">$($totals['Info'])</td></tr>
    </tfoot>
  </table>
</body>
</html>
"@
$html | Set-Content -LiteralPath (Join-Path $OutputDirectory 'index.html') -Encoding utf8NoBOM

# Code Quality report (CodeClimate JSON) — surfaces file findings in the MR on every tier.
$codeQualityParent = Split-Path -Parent $CodeQualityPath
if ($codeQualityParent) { New-Item -ItemType Directory -Path $codeQualityParent -Force | Out-Null }
ConvertTo-Json -InputObject @($codeQuality) -Depth 10 | Set-Content -LiteralPath $CodeQualityPath -Encoding utf8NoBOM

Write-Host "Security scan tool breakdown (commit $commit):"
$rows | ForEach-Object { [pscustomobject]$_ } | Format-Table -AutoSize | Out-String | Write-Host
Write-Host "Code Quality findings written: $($codeQuality.Count) -> $CodeQualityPath"

[pscustomobject]@{ tools = $rows; totals = $totals; codeQualityCount = $codeQuality.Count; sarifFileCount = $sarifFiles.Count }
