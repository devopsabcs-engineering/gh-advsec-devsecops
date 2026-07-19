[CmdletBinding()]
param([string]$InputPath, [string]$OutputPath)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertFrom-KubesecReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Report)

    $runs = foreach ($resource in $Report) {
        if ($resource.Message -eq 'This resource kind is not supported by kubesec' -or $null -eq $resource.Scoring) { continue }
        $advise = if ($resource.Scoring.PSObject.Properties['Advise']) { @($resource.Scoring.Advise) } else { @() }
        $critical = if ($resource.Scoring.PSObject.Properties['Critical']) { @($resource.Scoring.Critical) } else { @() }
        $findings = @($advise) + @($critical)
        $rules = foreach ($finding in $findings) {
            [ordered]@{
                id = [string]$finding.id
                shortDescription = @{ text = [string]$finding.reason }
                helpUri = 'https://github.com/controlplaneio/kubesec'
                properties = @{ points = [int]$finding.points; 'security-severity' = $(if ([int]$finding.points -lt 0) { '9.0' } else { '5.0' }) }
            }
        }
        $results = foreach ($finding in $findings) {
            [ordered]@{
                ruleId = [string]$finding.id
                level = $(if ([int]$finding.points -lt 0) { 'error' } else { 'warning' })
                message = @{ text = [string]$finding.reason }
                locations = @(@{ physicalLocation = @{ artifactLocation = @{ uri = [string]$resource.FileName }; region = @{ startLine = 1 } } })
                partialFingerprints = @{ primaryLocationLineHash = "kubesec-$($resource.FileName)-$($finding.id)" }
            }
        }
        [ordered]@{ tool = @{ driver = @{ name = 'Kubesec'; rules = @($rules) } }; results = @($results); columnKind = 'utf16CodeUnits' }
    }

    $runArray = @($runs)
    if ($runArray.Count -eq 0) { throw 'Kubesec input produced no supported SARIF runs.' }
    return [ordered]@{ '$schema' = 'https://json.schemastore.org/sarif-2.1.0.json'; version = '2.1.0'; runs = $runArray }
}

if ($PSBoundParameters.ContainsKey('InputPath')) {
    if (-not $OutputPath) { throw 'OutputPath is required.' }
    $report = @(Get-Content -LiteralPath $InputPath -Raw | ConvertFrom-Json -Depth 100)
    ConvertFrom-KubesecReport -Report $report | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM
}
