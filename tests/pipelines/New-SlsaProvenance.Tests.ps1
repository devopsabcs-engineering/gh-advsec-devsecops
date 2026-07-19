[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification = 'The file-backed Cosign shim exchanges deterministic fixture state through Pester global scope.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test fixture factories create in-memory objects and do not mutate external state.')]
param()

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$fakeCosignPath = Join-Path $repositoryRoot 'tests\fixtures\fake-cosign.ps1'
. (Join-Path $repositoryRoot 'scripts\provenance\New-SlsaProvenance.ps1')
. (Join-Path $repositoryRoot 'scripts\provenance\Verify-ImageEvidence.ps1') -CosignExecutablePath $fakeCosignPath
. (Join-Path $repositoryRoot 'scripts\provenance\Sign-And-AttestImage.ps1') -CosignExecutablePath $fakeCosignPath

function Get-TestProvenance {
    param([string]$SbomDigest = ('sha256:' + ('b' * 64)))
    $data = @{
        ImageDigest = 'sha256:' + ('a' * 64); SbomDigest = $SbomDigest
        SourceRepository = 'https://dev.azure.com/example/project/_git/repo'; SourceRevision = 'abc123'; SourceRef = 'refs/heads/main'
        BuilderId = 'https://dev.azure.com/example/project/_build/definition/7'; BuildUri = 'vstfs:///Build/Build/9'
        BuildId = '9'; DefinitionId = '7'; YamlPath = '.azuredevops/pipelines/cicd.yml'
        StartedOn = [datetime]'2026-07-16T10:00:00.1234567Z'; FinishedOn = [datetime]'2026-07-16T10:05:00.7654321Z'
    }
    return New-SlsaProvenanceStatement $data
}

function New-TestEnvelope {
    param([object]$Statement)
    $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Statement | ConvertTo-Json -Depth 100 -Compress)))
    return @{ payloadType = 'application/vnd.in-toto+json'; payload = $payload; signatures = @(@{ sig = 'verified-by-fake-cosign' }) } | ConvertTo-Json -Depth 10 -Compress
}

Describe 'Invoke-ImageSigningAndAttestation' {
    It 'rejects mutable image tags before invoking Cosign' {
        $threw = $false
        try { Invoke-ImageSigningAndAttestation 'registry.example/app:latest' 'azurekms://vault.vault.azure.net/key' 'sbom.json' 'provenance.json' $fakeCosignPath } catch { $threw = $true }
        $threw | Should Be $true
    }

    It 'fails closed when the explicit Cosign executable is missing' {
        $sbomPath = Join-Path $TestDrive 'missing-cosign-sbom.json'
        $provenancePath = Join-Path $TestDrive 'missing-cosign-provenance.json'
        '{}' | Set-Content -LiteralPath $sbomPath -Encoding utf8NoBOM
        Get-TestProvenance | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $provenancePath -Encoding utf8NoBOM

        $threw = $false
        try { Invoke-ImageSigningAndAttestation ('registry.example/app@sha256:' + ('a' * 64)) 'azurekms://vault.vault.azure.net/key' $sbomPath $provenancePath (Join-Path $TestDrive 'missing-cosign') } catch { $threw = $true }
        $threw | Should Be $true
    }

    It 'attests only the SLSA predicate instead of nesting the full statement' {
        $sbomPath = Join-Path $TestDrive 'sign-sbom.json'
        $provenancePath = Join-Path $TestDrive 'sign-provenance.json'
        @{ spdxVersion = 'SPDX-2.2'; name = 'webapp01' } | ConvertTo-Json | Set-Content -LiteralPath $sbomPath -Encoding utf8NoBOM
        Get-TestProvenance | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $provenancePath -Encoding utf8NoBOM
        $global:AttestedSlsaPredicate = $null
        $global:CosignInvocations = @()

        Invoke-ImageSigningAndAttestation ('registry.example/app@sha256:' + ('a' * 64)) 'azurekms://vault.vault.azure.net/key' $sbomPath $provenancePath $fakeCosignPath

        $global:AttestedSlsaPredicate.buildDefinition.buildType | Should Be 'https://dev.azure.com/azure-pipelines/container-image/v1'
        ($global:AttestedSlsaPredicate.PSObject.Properties.Name -contains '_type') | Should Be $false
        ($global:AttestedSlsaPredicate.PSObject.Properties.Name -contains 'predicate') | Should Be $false
        $global:CosignInvocations.Count | Should Be 3
        $global:CosignInvocations[2][0] | Should Be 'attest'
        ($global:CosignInvocations[2] -contains 'slsaprovenance1') | Should Be $true
    }
}

Describe 'SLSA provenance contract' {
    It 'creates an in-toto Statement v1 with a SLSA v1 predicate and SBOM binding' {
        $statement = Get-TestProvenance
        $statement._type | Should Be 'https://in-toto.io/Statement/v1'
        $statement.predicateType | Should Be 'https://slsa.dev/provenance/v1'
        $statement.predicate.runDetails.byproducts[0].digest.sha256 | Should Be ('b' * 64)
        $statement.predicate.runDetails.metadata.startedOn | Should Be '2026-07-16T10:00:00Z'
        $statement.predicate.runDetails.metadata.finishedOn | Should Be '2026-07-16T10:05:00Z'
    }

    It 'rejects tampered subject evidence' {
        $statement = Get-TestProvenance
        $statement.subject[0].digest.sha256 = 'c' * 64
        $threw = $false
        try { Test-SlsaProvenanceStatement $statement 'https://in-toto.io/Statement/v1' ('sha256:' + ('a' * 64)) 'abc123' 'https://dev.azure.com/example/project/_build/definition/7' ('sha256:' + ('b' * 64)) | Out-Null } catch { $threw = $true }
        $threw | Should Be $true
    }
}

Describe 'Invoke-ImageEvidenceVerification' {
    BeforeEach {
        $global:ImageReference = 'registry.example/app@sha256:' + ('a' * 64)
        $global:PublicKeyPath = Join-Path $TestDrive 'cosign.pub'
        $global:SbomPath = Join-Path $TestDrive 'spdx-sbom.json'
        $global:ProvenancePath = Join-Path $TestDrive 'slsa-provenance.json'
        Set-Content -LiteralPath $global:PublicKeyPath -Value 'fake-public-key' -Encoding utf8NoBOM
        $global:LocalSbom = [ordered]@{
            spdxVersion = 'SPDX-2.2'
            name = 'webapp01'
            packages = @(@{ name = 'runtime'; versionInfo = '9.0' })
        }
        $global:LocalSbom | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $global:SbomPath -Encoding utf8NoBOM
        $global:SbomDigest = 'sha256:' + (Get-FileHash -LiteralPath $global:SbomPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $global:LocalProvenance = Get-TestProvenance $global:SbomDigest
        $global:LocalProvenance | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $global:ProvenancePath -Encoding utf8NoBOM
        $spdxStatement = [ordered]@{
            '_type' = 'https://in-toto.io/Statement/v1'
            subject = @(@{ name = 'registry.example/app'; digest = @{ sha256 = 'a' * 64 } })
            predicateType = 'https://spdx.dev/Document'
            predicate = $global:LocalSbom
        }
        $global:SpdxEnvelopeOutput = New-TestEnvelope $spdxStatement
        $signedSlsaStatement = $global:LocalProvenance | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100
        $signedSlsaStatement._type = 'https://in-toto.io/Statement/v0.1'
        $global:SlsaEnvelopeOutput = New-TestEnvelope $signedSlsaStatement
    }

    AfterEach {
        foreach ($name in @('ImageReference', 'PublicKeyPath', 'SbomPath', 'ProvenancePath', 'LocalSbom', 'SbomDigest', 'LocalProvenance', 'SpdxEnvelopeOutput', 'SlsaEnvelopeOutput')) {
            Remove-Variable -Name $name -Scope Global -ErrorAction SilentlyContinue
        }
        $global:ImageReference = $null
    }

    It 'binds mixed supported wrapper versions and validates the expected provenance fields' {
        { Invoke-ImageEvidenceVerification $global:ImageReference $global:PublicKeyPath $global:SbomPath $global:ProvenancePath 'abc123' 'https://dev.azure.com/example/project/_build/definition/7' $global:SbomDigest $fakeCosignPath } | Should Not Throw
    }

    It 'rejects an unsupported attestation statement wrapper' {
        $statement = [ordered]@{
            '_type' = 'https://in-toto.io/Statement/v2'
            subject = @(@{ name = 'registry.example/app'; digest = @{ sha256 = 'a' * 64 } })
            predicateType = 'https://spdx.dev/Document'
            predicate = $global:LocalSbom
        }
        $envelope = New-TestEnvelope $statement

        $threw = $false
        try { Get-VerifiedAttestationStatement @($envelope) 'https://spdx.dev/Document' ('sha256:' + ('a' * 64)) | Out-Null } catch { $threw = $true }
        $threw | Should Be $true
    }

    It 'fails closed when the explicit verification executable is missing' {
        $threw = $false
        try { Invoke-ImageEvidenceVerification $global:ImageReference $global:PublicKeyPath $global:SbomPath $global:ProvenancePath 'abc123' 'https://dev.azure.com/example/project/_build/definition/7' $global:SbomDigest (Join-Path $TestDrive 'missing-cosign') } catch { $threw = $true }
        $threw | Should Be $true
    }

    It 'rejects a local SBOM that differs from the signed SPDX predicate' {
        $global:LocalSbom.name = 'substituted-sbom'
        $global:LocalSbom | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $global:SbomPath -Encoding utf8NoBOM
        $tamperedDigest = 'sha256:' + (Get-FileHash -LiteralPath $global:SbomPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $signedSpdx = Get-VerifiedAttestationStatement @($global:SpdxEnvelopeOutput) 'https://spdx.dev/Document' ('sha256:' + ('a' * 64))
        (Test-JsonSemanticEquality (Get-Content -LiteralPath $global:SbomPath -Raw | ConvertFrom-Json) $signedSpdx.predicate) | Should Be $false

        $threw = $false
        try { Invoke-ImageEvidenceVerification $global:ImageReference $global:PublicKeyPath $global:SbomPath $global:ProvenancePath 'abc123' 'https://dev.azure.com/example/project/_build/definition/7' $tamperedDigest $fakeCosignPath } catch { $threw = $true }
        $threw | Should Be $true
    }

    It 'rejects local provenance that differs from the signed SLSA predicate' {
        $global:LocalProvenance.predicate.runDetails.builder.id = 'https://attacker.example/builder'
        $global:LocalProvenance | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $global:ProvenancePath -Encoding utf8NoBOM
        $signedSlsa = Get-VerifiedAttestationStatement @($global:SlsaEnvelopeOutput) 'https://slsa.dev/provenance/v1' ('sha256:' + ('a' * 64))
        (Test-JsonSemanticEquality (Get-Content -LiteralPath $global:ProvenancePath -Raw | ConvertFrom-Json).predicate $signedSlsa.predicate) | Should Be $false

        $threw = $false
        try { Invoke-ImageEvidenceVerification $global:ImageReference $global:PublicKeyPath $global:SbomPath $global:ProvenancePath 'abc123' 'https://dev.azure.com/example/project/_build/definition/7' $global:SbomDigest $fakeCosignPath } catch { $threw = $true }
        $threw | Should Be $true
    }

    It 'rejects duplicate verified attestations for a predicate type' {
        $global:SpdxEnvelopeOutput = @($global:SpdxEnvelopeOutput, $global:SpdxEnvelopeOutput)
        @(ConvertFrom-CosignEnvelopeOutput $global:SpdxEnvelopeOutput).Count | Should Be 2

        $threw = $false
        try { Invoke-ImageEvidenceVerification $global:ImageReference $global:PublicKeyPath $global:SbomPath $global:ProvenancePath 'abc123' 'https://dev.azure.com/example/project/_build/definition/7' $global:SbomDigest $fakeCosignPath } catch { $threw = $true }
        $threw | Should Be $true
    }
}
