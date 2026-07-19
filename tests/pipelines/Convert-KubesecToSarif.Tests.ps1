$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repositoryRoot 'scripts\sarif\Convert-KubesecToSarif.ps1')

Describe 'ConvertFrom-KubesecReport' {
    It 'maps negative scores to error and nonnegative scores to warning' {
        $report = @([pscustomobject]@{
            Valid = $true; FileName = 'manifest.yaml'; Message = ''
            Scoring = [pscustomobject]@{
                Critical = @([pscustomobject]@{ id = 'critical'; reason = 'Unsafe'; selector = 'x'; points = -5 })
                Advise = @([pscustomobject]@{ id = 'advice'; reason = 'Improve'; selector = 'y'; points = 1 })
            }
        })

        $sarif = ConvertFrom-KubesecReport $report

        $sarif.version | Should Be '2.1.0'
        @($sarif.runs[0].results | Where-Object level -eq 'error').Count | Should Be 1
        @($sarif.runs[0].results | Where-Object level -eq 'warning').Count | Should Be 1
    }

    It 'converts usable scoring data even when Kubesec marks the resource invalid' {
        $report = @([pscustomobject]@{
            Valid = $false; FileName = 'manifest.yaml'; Message = 'Invalid resource configuration'
            Scoring = [pscustomobject]@{
                Critical = @([pscustomobject]@{ id = 'critical'; reason = 'Unsafe'; selector = 'x'; points = -5 })
            }
        })

        $sarif = ConvertFrom-KubesecReport $report

        @($sarif.runs).Count | Should Be 1
        @($sarif.runs[0].results).Count | Should Be 1
    }

    It 'rejects reports without supported scoring data' {
        $report = @([pscustomobject]@{
            Valid = $false; FileName = 'manifest.yaml'; Message = 'This resource kind is not supported by kubesec'
            Scoring = $null
        })

        { ConvertFrom-KubesecReport $report } | Should Throw 'Kubesec input produced no supported SARIF runs.'
    }
}
