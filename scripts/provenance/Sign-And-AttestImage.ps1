[CmdletBinding()]
param(
    [string]$ImageReference,
    [string]$KeyVaultKeyUri,
    [string]$SbomPath,
    [string]$ProvenancePath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$CosignExecutablePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Invoke-ImageSigningAndAttestation {
    [CmdletBinding()]
    param(
        [string]$Image,
        [string]$KeyUri,
        [string]$Sbom,
        [string]$Provenance,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$CosignExecutable
    )
    if ($Image -notmatch '@sha256:[a-fA-F0-9]{64}$') { throw 'Only digest-qualified images can be signed.' }
    if ($KeyUri -notmatch '^azurekms://[a-zA-Z0-9-]+\.vault\.azure\.net/[a-zA-Z0-9-]+$') { throw 'A valid Azure Key Vault Cosign URI is required.' }
    if (-not (Test-Path -LiteralPath $CosignExecutable -PathType Leaf)) { throw "Cosign executable is missing: $CosignExecutable" }
    foreach ($path in @($Sbom, $Provenance)) { if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Evidence file is missing: $path" } }
    & $CosignExecutable sign --yes --key $KeyUri $Image
    if ($LASTEXITCODE -ne 0) { throw 'Image signing failed.' }
    & $CosignExecutable attest --yes --key $KeyUri --type spdxjson --predicate $Sbom $Image
    if ($LASTEXITCODE -ne 0) { throw 'SBOM attestation failed.' }
    $statement = Get-Content -LiteralPath $Provenance -Raw | ConvertFrom-Json -Depth 100
    if ($null -eq $statement.predicate) { throw 'The provenance statement predicate is missing.' }
    $predicatePath = Join-Path ([System.IO.Path]::GetTempPath()) ("slsa-predicate-{0}.json" -f [guid]::NewGuid())
    try {
        $statement.predicate | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $predicatePath -Encoding utf8NoBOM
        & $CosignExecutable attest --yes --key $KeyUri --type slsaprovenance1 --predicate $predicatePath $Image
        if ($LASTEXITCODE -ne 0) { throw 'Provenance attestation failed.' }
    }
    finally {
        Remove-Item -LiteralPath $predicatePath -Force -ErrorAction SilentlyContinue
    }
}

if ($PSBoundParameters.ContainsKey('ImageReference')) {
    Invoke-ImageSigningAndAttestation $ImageReference $KeyVaultKeyUri $SbomPath $ProvenancePath $CosignExecutablePath
}
