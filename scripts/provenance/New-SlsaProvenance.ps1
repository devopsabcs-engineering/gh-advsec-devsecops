[CmdletBinding()]
param(
    [string]$ImageDigest,
    [string]$SourceRepository,
    [string]$SourceRevision,
    [string]$SourceRef,
    [string]$BuilderId,
    [string]$BuildUri,
    [string]$BuildId,
    [string]$DefinitionId,
    [string]$YamlPath,
    [string]$SbomDigest,
    [datetime]$StartedOn,
    [datetime]$FinishedOn,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-SlsaProvenanceStatement {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory statement without changing system state.')]
    [CmdletBinding()]
    param([hashtable]$InputData)
    foreach ($name in @('ImageDigest', 'SourceRepository', 'SourceRevision', 'BuilderId', 'BuildUri', 'SbomDigest')) {
        if ([string]::IsNullOrWhiteSpace([string]$InputData[$name])) { throw "Provenance input is required: $name" }
    }
    if ($InputData.ImageDigest -notmatch '^sha256:[a-fA-F0-9]{64}$' -or $InputData.SbomDigest -notmatch '^sha256:[a-fA-F0-9]{64}$') { throw 'Image and SBOM digests must be SHA-256 digests.' }
    return [ordered]@{
        '_type' = 'https://in-toto.io/Statement/v1'
        subject = @(@{ name = 'container-image'; digest = @{ sha256 = $InputData.ImageDigest.Substring(7) } })
        predicateType = 'https://slsa.dev/provenance/v1'
        predicate = [ordered]@{
            buildDefinition = [ordered]@{
                buildType = 'https://dev.azure.com/azure-pipelines/container-image/v1'
                externalParameters = @{ repository = $InputData.SourceRepository; ref = $InputData.SourceRef; yamlPath = $InputData.YamlPath }
                internalParameters = @{ buildId = $InputData.BuildId; definitionId = $InputData.DefinitionId }
                resolvedDependencies = @(@{ uri = "git+$($InputData.SourceRepository)@$($InputData.SourceRevision)"; digest = @{ gitCommit = $InputData.SourceRevision } })
            }
            runDetails = [ordered]@{
                builder = @{ id = $InputData.BuilderId }
                metadata = @{ invocationId = $InputData.BuildUri; startedOn = $InputData.StartedOn.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); finishedOn = $InputData.FinishedOn.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
                byproducts = @(@{ name = 'spdx-sbom'; digest = @{ sha256 = $InputData.SbomDigest.Substring(7) } })
            }
        }
    }
}

if ($PSBoundParameters.ContainsKey('ImageDigest')) {
    $data = @{}; foreach ($key in $PSBoundParameters.Keys) { $data[$key] = $PSBoundParameters[$key] }
    New-SlsaProvenanceStatement $data | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM
}
