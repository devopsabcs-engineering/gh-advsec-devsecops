$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repositoryRoot 'scripts\dependencies\Test-DependencyChanges.ps1')

function Get-MetadataFixture {
    param([int]$Severity = 0, [AllowNull()][string]$License = 'MIT')
    return @{ 'changed.package/2.0.0' = [pscustomobject]@{ vulnerabilities = @([pscustomobject]@{ severity = $Severity }); licenseExpression = $License } }
}

Describe 'Get-ChangedNuGetPackage' {
    It 'returns only added and version-changed packages' {
        $base = @([pscustomobject]@{ id = 'unchanged'; version = '1.0.0' }, [pscustomobject]@{ id = 'changed.package'; version = '1.0.0' })
        $head = @([pscustomobject]@{ id = 'unchanged'; version = '1.0.0' }, [pscustomobject]@{ id = 'changed.package'; version = '2.0.0' })

        $changed = @(Get-ChangedNuGetPackage -BaseGraph $base -HeadGraph $head)

        $changed.Count | Should Be 1
        $changed[0].previousVersion | Should Be '1.0.0'
    }
}

Describe 'Get-NuGetRegistrationMetadata' {
    It 'normalizes NuGet registration license and vulnerability metadata' {
        Mock Invoke-RestMethod { [pscustomobject]@{ catalogEntry = [pscustomobject]@{ licenseExpression = 'MIT'; vulnerabilities = @([pscustomobject]@{ severity = 1 }) } } }

        $metadata = Get-NuGetRegistrationRecord 'Example.Package' '2.0.0'

        $metadata.licenseExpression | Should Be 'MIT'
        $metadata.vulnerabilities[0].severity | Should Be 1
        Assert-MockCalled Invoke-RestMethod 1 -ParameterFilter { $Uri -like 'https://api.nuget.org/*/example.package/2.0.0.json' }
    }
}

Describe 'Test-SpdxLicenseExpression' {
    It 'allows approved licenses through Boolean SPDX semantics' {
        Test-SpdxLicenseExpression '(MIT OR BSD-3-Clause) AND Apache-2.0' | Should Be $true
    }

    It 'rejects expressions whose required branch is disallowed' {
        Test-SpdxLicenseExpression 'MIT AND BSD-3-Clause' | Should Be $false
    }
}

Describe 'Invoke-DependencyAdmission' {
    $base = @([pscustomobject]@{ id = 'changed.package'; version = '1.0.0' })
    $head = @([pscustomobject]@{ id = 'changed.package'; version = '2.0.0' })

    It 'passes low severity with an allowed license' {
        (Invoke-DependencyAdmission $base $head (Get-MetadataFixture -Severity 0)).passed | Should Be $true
    }

    It 'fails moderate high and critical severities' {
        foreach ($severity in 1, 2, 3) {
            (Invoke-DependencyAdmission $base $head (Get-MetadataFixture -Severity $severity)).passed | Should Be $false
        }
    }

    It 'warns without failing for unknown licenses' {
        $result = Invoke-DependencyAdmission $base $head (Get-MetadataFixture -License $null)
        $result.passed | Should Be $true
        $result.packages[0].warning | Should Not BeNullOrEmpty
    }

    It 'fails closed when changed-package metadata is missing' {
        $threw = $false
        try { Invoke-DependencyAdmission $base $head @{} | Out-Null } catch { $threw = $true }
        $threw | Should Be $true
    }
}
