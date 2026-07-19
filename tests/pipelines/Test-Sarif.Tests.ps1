$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$scriptPath = Join-Path $repositoryRoot 'scripts\sarif\Test-Sarif.ps1'
$fixtureRoot = Join-Path $repositoryRoot 'tests\fixtures\sarif'
$invalidFixtureRoot = Join-Path $repositoryRoot 'tests\fixtures\sarif-invalid'

function Invoke-SarifValidation {
    param([string]$Path)

    & pwsh -NoProfile -File $scriptPath -Path $Path *> $null
    return $LASTEXITCODE
}

Describe 'Test-Sarif.ps1' {
    It 'accepts SARIF 2.1.0 with at least one run' {
        Invoke-SarifValidation (Join-Path $fixtureRoot 'valid.sarif') | Should Be 0
    }

    It 'rejects malformed JSON' {
        Invoke-SarifValidation (Join-Path $invalidFixtureRoot 'malformed.sarif') | Should Not Be 0
    }

    It 'rejects an empty runs array' {
        Invoke-SarifValidation (Join-Path $invalidFixtureRoot 'empty-runs.sarif') | Should Not Be 0
    }

    It 'validates every SARIF file in a directory' {
        $directory = Join-Path $TestDrive 'multiple'
        New-Item -ItemType Directory -Path $directory | Out-Null
        Copy-Item (Join-Path $fixtureRoot 'valid.sarif') (Join-Path $directory 'a.sarif')
        Copy-Item (Join-Path $invalidFixtureRoot 'empty-runs.sarif') (Join-Path $directory 'b.sarif')

        Invoke-SarifValidation $directory | Should Not Be 0
    }
}
