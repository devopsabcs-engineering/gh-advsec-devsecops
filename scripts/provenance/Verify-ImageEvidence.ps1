[CmdletBinding()]
param(
    [string]$ImageReference,
    [string]$PublicKeyPath,
    [string]$SbomPath,
    [string]$ProvenancePath,
    [string]$ExpectedRevision,
    [string]$ExpectedBuilderId,
    [string]$ExpectedSbomDigest,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$CosignExecutablePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-JsonSemanticEquality {
    [CmdletBinding()]
    param([AllowNull()][object]$Expected, [AllowNull()][object]$Actual)
    if ($null -eq $Expected -or $null -eq $Actual) { return $null -eq $Expected -and $null -eq $Actual }

    $expectedProperties = @($Expected.PSObject.Properties | Where-Object MemberType -eq 'NoteProperty')
    $actualProperties = @($Actual.PSObject.Properties | Where-Object MemberType -eq 'NoteProperty')
    if ($expectedProperties.Count -gt 0 -or $actualProperties.Count -gt 0) {
        if ($expectedProperties.Count -ne $actualProperties.Count) { return $false }
        foreach ($property in $expectedProperties) {
            $actualProperty = $Actual.PSObject.Properties[$property.Name]
            if ($null -eq $actualProperty -or -not (Test-JsonSemanticEquality $property.Value $actualProperty.Value)) { return $false }
        }
        return $true
    }

    $expectedIsArray = $Expected -is [System.Collections.IEnumerable] -and $Expected -isnot [string]
    $actualIsArray = $Actual -is [System.Collections.IEnumerable] -and $Actual -isnot [string]
    if ($expectedIsArray -or $actualIsArray) {
        if (-not $expectedIsArray -or -not $actualIsArray) { return $false }
        $expectedItems = @($Expected)
        $actualItems = @($Actual)
        if ($expectedItems.Count -ne $actualItems.Count) { return $false }
        for ($index = 0; $index -lt $expectedItems.Count; $index++) {
            if (-not (Test-JsonSemanticEquality $expectedItems[$index] $actualItems[$index])) { return $false }
        }
        return $true
    }

    $expectedType = $Expected.GetType()
    $actualType = $Actual.GetType()
    $numericTypes = @([byte], [sbyte], [short], [ushort], [int], [uint], [long], [ulong], [float], [double], [decimal])
    $expectedIsNumeric = $numericTypes -contains $expectedType
    $actualIsNumeric = $numericTypes -contains $actualType
    if ($expectedIsNumeric -or $actualIsNumeric) {
        if (-not $expectedIsNumeric -or -not $actualIsNumeric) { return $false }
        return [decimal]$Expected -eq [decimal]$Actual
    }
    if ($expectedType -ne $actualType) { return $false }
    return $Expected -eq $Actual
}

function ConvertFrom-CosignEnvelopeOutput {
    [CmdletBinding()]
    param([object[]]$OutputLines)
    $text = (@($OutputLines) | ForEach-Object { [string]$_ }) -join "`n"
    if ([string]::IsNullOrWhiteSpace($text)) { throw 'Cosign returned no verified attestation payload.' }
    try {
        return @($text | ConvertFrom-Json -Depth 100 -ErrorAction Stop)
    }
    catch {
        $envelopes = @()
        foreach ($line in @($OutputLines)) {
            if ([string]::IsNullOrWhiteSpace([string]$line)) { continue }
            try { $envelopes += $line | ConvertFrom-Json -Depth 100 -ErrorAction Stop }
            catch { throw 'Cosign returned malformed verified attestation JSON.' }
        }
        return $envelopes
    }
}

function Get-VerifiedAttestationStatement {
    [CmdletBinding()]
    param([object[]]$OutputLines, [string]$PredicateType, [string]$Digest)
    $envelopes = @(ConvertFrom-CosignEnvelopeOutput $OutputLines)
    if ($envelopes.Count -ne 1) { throw "Expected exactly one verified $PredicateType attestation." }
    $envelope = $envelopes[0]
    if ($envelope.payloadType -ne 'application/vnd.in-toto+json' -or [string]::IsNullOrWhiteSpace([string]$envelope.payload)) {
        throw 'The verified attestation is not a valid in-toto DSSE envelope.'
    }
    try {
        $payloadBytes = [Convert]::FromBase64String([string]$envelope.payload)
        $statement = [Text.Encoding]::UTF8.GetString($payloadBytes) | ConvertFrom-Json -Depth 100 -ErrorAction Stop
    }
    catch { throw 'The verified attestation payload is malformed.' }
    $supportedStatementTypes = @(
        'https://in-toto.io/Statement/v0.1'
        'https://in-toto.io/Statement/v1'
    )
    if ($statement._type -notin $supportedStatementTypes -or $statement.predicateType -ne $PredicateType) {
        throw 'The verified attestation statement type is unexpected.'
    }
    $subjects = @($statement.subject)
    $matchingSubjects = @($subjects | Where-Object { $_.digest.sha256 -eq $Digest.Substring(7) })
    if ($subjects.Count -ne 1 -or $matchingSubjects.Count -ne 1) { throw 'The verified attestation subject does not uniquely match the image digest.' }
    return $statement
}

function Test-SlsaProvenanceStatement {
    [CmdletBinding()]
    param([object]$Statement, [string]$StatementType, [string]$Digest, [string]$Revision, [string]$BuilderId, [string]$SbomDigest)
    if ($Statement._type -ne $StatementType -or $Statement.predicateType -ne 'https://slsa.dev/provenance/v1') { throw 'Unexpected provenance statement or predicate type.' }
    if ($Statement.subject[0].digest.sha256 -ne $Digest.Substring(7)) { throw 'Provenance subject digest does not match the image.' }
    if ($Statement.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit -ne $Revision) { throw 'Provenance source revision does not match.' }
    if ($Statement.predicate.runDetails.builder.id -ne $BuilderId) { throw 'Provenance builder identity does not match.' }
    if ($Statement.predicate.runDetails.byproducts[0].digest.sha256 -ne $SbomDigest.Substring(7)) { throw 'Provenance SBOM binding does not match.' }
    return $true
}

function Invoke-ImageEvidenceVerification {
    [CmdletBinding()]
    param(
        [string]$Image,
        [string]$PublicKey,
        [string]$Sbom,
        [string]$Provenance,
        [string]$Revision,
        [string]$BuilderId,
        [string]$SbomDigest,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$CosignExecutable
    )
    if ($Image -notmatch '@(sha256:[a-fA-F0-9]{64})$') { throw 'Verification requires a digest-qualified image.' }
    $imageDigest = $Matches[1]
    if ($SbomDigest -notmatch '^sha256:[a-fA-F0-9]{64}$') { throw 'The expected SBOM digest must be a SHA-256 digest.' }
    if (-not (Test-Path -LiteralPath $CosignExecutable -PathType Leaf)) { throw "Cosign executable is missing: $CosignExecutable" }
    foreach ($path in @($PublicKey, $Sbom, $Provenance)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Verification input is missing: $path" }
    }

    & $CosignExecutable verify --key $PublicKey $Image | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cosign signature verification failed.' }
    $spdxOutput = @(& $CosignExecutable verify-attestation --key $PublicKey --type spdxjson $Image)
    if ($LASTEXITCODE -ne 0) { throw 'SBOM attestation verification failed.' }
    $slsaOutput = @(& $CosignExecutable verify-attestation --key $PublicKey --type slsaprovenance1 $Image)
    if ($LASTEXITCODE -ne 0) { throw 'Provenance attestation verification failed.' }

    $localSbom = Get-Content -LiteralPath $Sbom -Raw | ConvertFrom-Json -Depth 100 -ErrorAction Stop
    $localProvenance = Get-Content -LiteralPath $Provenance -Raw | ConvertFrom-Json -Depth 100 -ErrorAction Stop
    $actualSbomDigest = 'sha256:' + (Get-FileHash -LiteralPath $Sbom -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSbomDigest -ne $SbomDigest.ToLowerInvariant()) { throw 'The local SBOM file digest does not match the expected digest.' }

    $signedSpdx = Get-VerifiedAttestationStatement $spdxOutput 'https://spdx.dev/Document' $imageDigest
    $signedSlsa = Get-VerifiedAttestationStatement $slsaOutput 'https://slsa.dev/provenance/v1' $imageDigest
    if (-not (Test-JsonSemanticEquality $localSbom $signedSpdx.predicate)) { throw 'The signed SPDX predicate does not match the local SBOM.' }
    if (-not (Test-JsonSemanticEquality $localProvenance.predicate $signedSlsa.predicate)) { throw 'The signed SLSA predicate does not match the local provenance.' }
    Test-SlsaProvenanceStatement $localProvenance 'https://in-toto.io/Statement/v1' $imageDigest $Revision $BuilderId $SbomDigest | Out-Null
    Test-SlsaProvenanceStatement $signedSlsa $signedSlsa._type $imageDigest $Revision $BuilderId $SbomDigest | Out-Null
}

if ($PSBoundParameters.ContainsKey('ImageReference')) {
    Invoke-ImageEvidenceVerification $ImageReference $PublicKeyPath $SbomPath $ProvenancePath $ExpectedRevision $ExpectedBuilderId $ExpectedSbomDigest $CosignExecutablePath
}
