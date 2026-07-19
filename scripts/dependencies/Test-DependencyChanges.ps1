[CmdletBinding()]
param(
    [string]$BaseGraphPath,
    [string]$HeadGraphPath,
    [string]$MetadataPath,
    [string]$JsonOutputPath,
    [string]$MarkdownOutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:AllowedLicenses = @('MIT', 'Apache-2.0', 'GPL-3.0')

function Get-NuGetRegistrationRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PackageId,
        [Parameter(Mandatory)][string]$Version,
        [string]$RegistrationBaseUrl = 'https://api.nuget.org/v3/registration5-gz-semver2'
    )
    if ($RegistrationBaseUrl -notmatch '^https://') { throw 'NuGet registration metadata requires HTTPS.' }
    $uri = "$($RegistrationBaseUrl.TrimEnd('/'))/$($PackageId.ToLowerInvariant())/$($Version.ToLowerInvariant()).json"
    try { $response = Invoke-RestMethod -Method GET -Uri $uri } catch { throw "NuGet metadata request failed for $PackageId/$Version. $($_.Exception.Message)" }
    $entry = if ($response.catalogEntry) { $response.catalogEntry } else { $response }
    if (-not $entry) { throw "NuGet registration metadata is empty for $PackageId/$Version." }
    return [pscustomobject]@{ licenseExpression = $entry.licenseExpression; vulnerabilities = @($entry.vulnerabilities) }
}

function Get-ChangedNuGetPackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$BaseGraph,
        [Parameter(Mandatory)][object[]]$HeadGraph
    )

    $baseVersions = @{}
    foreach ($package in $BaseGraph) {
        if (-not $package.id -or -not $package.version) { throw 'Base graph contains an invalid package.' }
        $baseVersions[([string]$package.id).ToLowerInvariant()] = [string]$package.version
    }

    foreach ($package in $HeadGraph) {
        if (-not $package.id -or -not $package.version) { throw 'Head graph contains an invalid package.' }
        $id = ([string]$package.id).ToLowerInvariant()
        if (-not $baseVersions.ContainsKey($id) -or $baseVersions[$id] -ne [string]$package.version) {
            [pscustomobject][ordered]@{ id = $id; version = [string]$package.version; previousVersion = $baseVersions[$id] }
        }
    }
}

function Test-SpdxLicenseExpression {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Expression)

    $tokens = @([regex]::Matches($Expression, '\(|\)|\bAND\b|\bOR\b|\bWITH\b|[A-Za-z0-9.+-]+', 'IgnoreCase') | ForEach-Object Value)
    if (($tokens -join '') -ne ($Expression -replace '\s+', '')) { return $false }
    try {
        if ($tokens.Count -eq 0 -or $tokens -contains 'WITH') { return $false }
        $values = [System.Collections.Generic.Stack[bool]]::new()
        $operators = [System.Collections.Generic.Stack[string]]::new()
        $precedence = @{ OR = 1; AND = 2 }

        foreach ($token in $tokens) {
            if ($token -eq '(') { $operators.Push($token); continue }
            if ($token -eq ')') {
                while ($operators.Count -gt 0 -and $operators.Peek() -ne '(') {
                    $right = $values.Pop(); $left = $values.Pop(); $operator = $operators.Pop()
                    $values.Push($(if ($operator -eq 'AND') { $left -and $right } else { $left -or $right }))
                }
                if ($operators.Count -eq 0) { return $false }
                $operators.Pop() | Out-Null
                continue
            }
            if ($token -in @('AND', 'OR')) {
                while ($operators.Count -gt 0 -and $operators.Peek() -ne '(' -and $precedence[$operators.Peek()] -ge $precedence[$token]) {
                    $right = $values.Pop(); $left = $values.Pop(); $operator = $operators.Pop()
                    $values.Push($(if ($operator -eq 'AND') { $left -and $right } else { $left -or $right }))
                }
                $operators.Push($token.ToUpperInvariant())
                continue
            }
            $values.Push($token -in $script:AllowedLicenses)
        }
        while ($operators.Count -gt 0) {
            $right = $values.Pop(); $left = $values.Pop(); $operator = $operators.Pop()
            if ($operator -eq '(') { return $false }
            $values.Push($(if ($operator -eq 'AND') { $left -and $right } else { $left -or $right }))
        }
        return $values.Count -eq 1 -and $values.Pop()
    }
    catch {
        return $false
    }
}

function Invoke-DependencyAdmission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$BaseGraph,
        [Parameter(Mandatory)][object[]]$HeadGraph,
        [Parameter(Mandatory)][hashtable]$Metadata
    )

    $results = foreach ($package in @(Get-ChangedNuGetPackage -BaseGraph $BaseGraph -HeadGraph $HeadGraph)) {
        $key = "$($package.id)/$($package.version)"
        if (-not $Metadata.ContainsKey($key) -or $null -eq $Metadata[$key]) {
            throw "NuGet metadata is missing for changed package: $key"
        }
        $entry = $Metadata[$key]
        $severities = @($entry.vulnerabilities | ForEach-Object { [int]$_.severity })
        $vulnerabilityFailure = @($severities | Where-Object { $_ -in 1, 2, 3 }).Count -gt 0
        $licenseWarning = [string]::IsNullOrWhiteSpace([string]$entry.licenseExpression)
        $licenseFailure = -not $licenseWarning -and -not (Test-SpdxLicenseExpression -Expression $entry.licenseExpression)
        [pscustomobject][ordered]@{
            id = $package.id
            version = $package.version
            previousVersion = $package.previousVersion
            maximumSeverity = if ($severities.Count) { ($severities | Measure-Object -Maximum).Maximum } else { $null }
            licenseExpression = $entry.licenseExpression
            warning = if ($licenseWarning) { 'License metadata is unknown.' } else { $null }
            failed = $vulnerabilityFailure -or $licenseFailure
        }
    }

    $items = @($results)
    return [pscustomobject][ordered]@{
        passed = @($items | Where-Object failed).Count -eq 0
        changedPackageCount = $items.Count
        packages = $items
    }
}

function ConvertTo-DependencyMarkdown {
    param([Parameter(Mandatory)][object]$Result)
    $lines = @('# Dependency Change Admission', '', "Changed packages: $($Result.changedPackageCount)", '', '| Package | Version | Severity | License | Result |', '|---|---:|---:|---|---|')
    foreach ($package in @($Result.packages)) {
        $status = if ($package.failed) { 'Fail' } elseif ($package.warning) { 'Warning' } else { 'Pass' }
        $lines += "| $($package.id) | $($package.version) | $($package.maximumSeverity) | $($package.licenseExpression) | $status |"
    }
    return $lines -join [Environment]::NewLine
}

if ($PSBoundParameters.ContainsKey('BaseGraphPath')) {
    foreach ($requiredPath in @($BaseGraphPath, $HeadGraphPath, $MetadataPath)) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) { throw "Required dependency input is missing: $requiredPath" }
    }
    $base = @(Get-Content -LiteralPath $BaseGraphPath -Raw | ConvertFrom-Json -Depth 100)
    $head = @(Get-Content -LiteralPath $HeadGraphPath -Raw | ConvertFrom-Json -Depth 100)
    $metadataDocument = Get-Content -LiteralPath $MetadataPath -Raw | ConvertFrom-Json -Depth 100
    $metadata = @{}
    foreach ($property in $metadataDocument.PSObject.Properties) { $metadata[$property.Name] = $property.Value }
    $result = Invoke-DependencyAdmission -BaseGraph $base -HeadGraph $head -Metadata $metadata
    if (-not $JsonOutputPath -or -not $MarkdownOutputPath) { throw 'JSON and Markdown output paths are required.' }
    $result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $JsonOutputPath -Encoding utf8NoBOM
    ConvertTo-DependencyMarkdown -Result $result | Set-Content -LiteralPath $MarkdownOutputPath -Encoding utf8NoBOM
    if (-not $result.passed) { exit 1 }
}
