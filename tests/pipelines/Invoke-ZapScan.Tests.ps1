$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repositoryRoot 'scripts\zap\Invoke-ZapScan.ps1')

Describe 'Get-LinuxHostUser' {
    It 'returns a non-root numeric UID and GID mapping' {
        Mock Invoke-HostIdCommand {
            if ($Argument -eq '-u') { return '1001' }
            return '1002'
        }

        Get-LinuxHostUser | Should Be '1001:1002'
    }

    It 'rejects root or non-numeric identity values' {
        Mock Invoke-HostIdCommand {
            if ($Argument -eq '-u') { return '0' }
            return 'users'
        }
        $threw = $false

        try { Get-LinuxHostUser } catch { $threw = $true }

        $threw | Should Be $true
    }
}

Describe 'Wait-HttpReady' {
    It 'waits between failures and stops waiting after success' {
        $script:readinessRequestCount = 0
        Mock Invoke-WebRequest {
            $script:readinessRequestCount++
            if ($script:readinessRequestCount -lt 3) { throw 'not ready' }
        }
        Mock Wait-RetryDelay { }

        Wait-HttpReady -Uri 'https://example.test' -Attempts 4 | Should Be $true

        Assert-MockCalled Invoke-WebRequest 3 -Exactly -ParameterFilter { $Uri -eq 'https://example.test' }
        Assert-MockCalled Wait-RetryDelay 2 -Exactly -ParameterFilter { $Seconds -eq 2 }
    }

    It 'does not wait after the final failed attempt' {
        Mock Invoke-WebRequest { throw 'not ready' }
        Mock Wait-RetryDelay { }
        $threw = $false

        try { Wait-HttpReady -Uri 'https://final-failure.test' -Attempts 3 -RetryDelaySeconds 1 } catch { $threw = $true }

        $threw | Should Be $true
        Assert-MockCalled Invoke-WebRequest 3 -Exactly -ParameterFilter { $Uri -eq 'https://final-failure.test' }
        Assert-MockCalled Wait-RetryDelay 2 -Exactly -ParameterFilter { $Seconds -eq 1 }
    }
}

Describe 'Invoke-ZapLifecycle' {
    It 'bounds the Docker process and terminates its process tree on timeout' {
        $scriptContent = Get-Content -LiteralPath (Join-Path $repositoryRoot 'scripts\zap\Invoke-ZapScan.ps1') -Raw

        $scriptContent | Should Match 'WaitForExit\(\$TimeoutSeconds \* 1000\)'
        $scriptContent | Should Match '\$process\.Kill\(\$true\)'
        $scriptContent | Should Match 'Docker command timed out after \$TimeoutSeconds seconds'
    }

    It 'runs the scanner with the non-root Linux host UID and GID' {
        Mock Test-LinuxPlatform { return $true }
        Mock Get-LinuxHostUser { return '1001:1002' }
        Mock Wait-HttpReady { return $true }
        Mock Invoke-DockerCommand { }
        Mock Invoke-DockerCommandWithTimeout {
            if ($Arguments -contains 'zap.sh') {
                Set-Content -LiteralPath (Join-Path $TestDrive 'baseline.html') -Value '<html></html>'
                Set-Content -LiteralPath (Join-Path $TestDrive 'baseline.json') -Value '{}'
                Set-Content -LiteralPath (Join-Path $TestDrive 'baseline.sarif') -Value '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"ZAP"}},"results":[]}]}'
            }
        }

        Invoke-ZapLifecycle 'baseline' ('zaproxy/zap-stable@sha256:' + ('a' * 64)) $TestDrive 'https://example.test' $false 'Dockerfile' 18080 2 720

        Assert-MockCalled Invoke-DockerCommand 1 -ParameterFilter {
            $userIndex = [array]::IndexOf($Arguments, '--user')
            $entrypointIndex = [array]::IndexOf($Arguments, '--entrypoint')
            $Arguments[0] -eq 'run' -and $Arguments -contains 'CHOWN' -and $Arguments -contains 'no-new-privileges' -and $userIndex -gt 0 -and $Arguments[$userIndex + 1] -eq '0:0' -and $entrypointIndex -gt 0 -and $Arguments[$entrypointIndex + 1] -eq 'chown' -and $Arguments[-3] -eq '1001:1002' -and $Arguments[-2] -eq '/zap/wrk' -and $Arguments[-1] -eq '/zap/home'
        }
        Assert-MockCalled Invoke-DockerCommandWithTimeout 1 -ParameterFilter {
            $userIndex = [array]::IndexOf($Arguments, '--user')
            $Arguments[0] -eq 'run' -and $userIndex -gt 0 -and $Arguments[$userIndex + 1] -eq '1001:1002' -and $Arguments -contains 'HOME=/zap/home' -and $Arguments -contains 'JAVA_TOOL_OPTIONS=-Duser.home=/zap/home' -and $TimeoutSeconds -eq 720
        }
    }

    It 'mounts and cleans host-owned scanner state outside the report directory' {
        $scriptContent = Get-Content -LiteralPath (Join-Path $repositoryRoot 'scripts\zap\Invoke-ZapScan.ps1') -Raw

        $scriptContent | Should Match 'zap-state-\$runId'
        $scriptContent | Should Match 'HOME=/zap/home'
        $scriptContent | Should Match 'JAVA_TOOL_OPTIONS=-Duser\.home=/zap/home'
        $scriptContent | Should Match '\$stateMount = .*:/zap/home:rw'
        $scriptContent | Should Not Match 'user\.home=/zap/wrk'
        $scriptContent | Should Match 'Remove-Item -LiteralPath \$stateDirectory -Recurse -Force'
    }

    It 'normalizes the ZAP SARIF template JSON suffix' {
        Mock Wait-HttpReady { return $true }
        Mock Invoke-DockerCommand { }
        Mock Invoke-DockerCommandWithTimeout {
            Set-Content -LiteralPath (Join-Path $TestDrive 'baseline.html') -Value '<html></html>'
            Set-Content -LiteralPath (Join-Path $TestDrive 'baseline.json') -Value '{}'
            Set-Content -LiteralPath (Join-Path $TestDrive 'baseline.sarif.json') -Value '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"ZAP"}},"results":[]}]}'
        }

        Invoke-ZapLifecycle 'baseline' ('zaproxy/zap-stable@sha256:' + ('a' * 64)) $TestDrive 'https://example.test' $false 'Dockerfile' 18080 2 720

        Test-Path -LiteralPath (Join-Path $TestDrive 'baseline.sarif') -PathType Leaf | Should Be $true
        Test-Path -LiteralPath (Join-Path $TestDrive 'baseline.sarif.json') | Should Be $false
    }

    It 'limits root to the hardened state initializer and avoids broad chmod workarounds' {
        $scriptContent = Get-Content -LiteralPath (Join-Path $repositoryRoot 'scripts\zap\Invoke-ZapScan.ps1') -Raw

        ([regex]::Matches($scriptContent, "'--user', '0:0'")).Count | Should Be 1
        $scriptContent | Should Match "'--network', 'none'.*'--read-only'.*'--cap-drop', 'ALL'.*'--cap-add', 'CHOWN'.*'no-new-privileges'"
        $scriptContent | Should Not Match '(?i)\bchmod\s+(?:-R\s+)?(?:[0-7]*[2367][0-7]{2}|a\+w|go\+w)\b'
    }

    It 'uses port 8080 and always cleans an ephemeral target' {
        Mock Wait-HttpReady { return $true }
        Mock Invoke-DockerCommand {
        }
        Mock Invoke-DockerCommandWithTimeout {
            Set-Content -LiteralPath (Join-Path $TestDrive 'baseline.html') -Value '<html></html>'
            Set-Content -LiteralPath (Join-Path $TestDrive 'baseline.json') -Value '{}'
            Set-Content -LiteralPath (Join-Path $TestDrive 'baseline.sarif') -Value '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"ZAP"}},"results":[]}]}'
        }

        Invoke-ZapLifecycle 'baseline' ('zaproxy/zap-stable@sha256:' + ('a' * 64)) $TestDrive 'unused' $true 'src/webapp01/Dockerfile' 18080 2 720

        Assert-MockCalled Invoke-DockerCommand 1 -ParameterFilter { $Arguments -contains '127.0.0.1:18080:8080' }
        Assert-MockCalled Invoke-DockerCommand 1 -ParameterFilter { $Arguments[0] -eq 'network' -and $Arguments[1] -eq 'rm' }
        Assert-MockCalled Invoke-DockerCommand 1 -ParameterFilter { $Arguments[0] -eq 'rm' -and $Arguments[1] -eq '--force' }
    }

    It 'names and force-removes the scanner when bounded execution fails' {
        Mock Wait-HttpReady { return $true }
        Mock Invoke-DockerCommand { }
        Mock Invoke-DockerCommandWithTimeout {
            $nameIndex = [array]::IndexOf($Arguments, '--name')
            $script:failedScannerName = $Arguments[$nameIndex + 1]
            throw 'scanner timeout'
        }
        $threw = $false

        try { Invoke-ZapLifecycle 'baseline' ('zaproxy/zap-stable@sha256:' + ('a' * 64)) $TestDrive 'https://example.test' $false 'Dockerfile' 18080 1 721 } catch { $threw = $true }

        $threw | Should Be $true
        Assert-MockCalled Invoke-DockerCommandWithTimeout 1 -Exactly -ParameterFilter {
            $nameIndex = [array]::IndexOf($Arguments, '--name')
            $TimeoutSeconds -eq 721 -and $nameIndex -gt 0 -and $Arguments[$nameIndex + 1] -eq $script:failedScannerName
        }
        Assert-MockCalled Invoke-DockerCommand 1 -Exactly -ParameterFilter {
            $Arguments[0] -eq 'rm' -and $Arguments[1] -eq '--force' -and $Arguments[2] -eq $script:failedScannerName -and $IgnoreExitCode
        }
    }

    It 'rejects a mutable ZAP image before execution' {
        $threw = $false
        try { Invoke-ZapLifecycle 'baseline' 'zaproxy/zap-stable:latest' $TestDrive 'https://example.test' $false 'Dockerfile' 18080 1 720 } catch { $threw = $true }
        $threw | Should Be $true
    }

    It 'rejects an authorization record for another target' {
        $threw = $false

        try {
            Assert-ZapAuthorizationRecord `
                -Record '{"target":"https://other.test","notBeforeUtc":"2026-01-01T00:00:00Z","expiresUtc":"2027-01-01T00:00:00Z","allowedScanTypes":["full"]}' `
                -TargetUri 'https://example.test' `
                -Mode full `
                -Now ([datetimeoffset]'2026-07-16T00:00:00Z')
        }
        catch { $threw = $true }

        $threw | Should Be $true
    }

    It 'rejects an expired authorization window before scanning' {
        $threw = $false

        try {
            Assert-ZapAuthorizationRecord `
                -Record '{"target":"https://example.test","notBeforeUtc":"2025-01-01T00:00:00Z","expiresUtc":"2025-01-01T01:00:00Z","allowedScanTypes":["full"]}' `
                -TargetUri 'https://example.test' `
                -Mode full `
                -Now ([datetimeoffset]'2026-07-16T00:00:00Z')
        }
        catch { $threw = $true }

        $threw | Should Be $true
    }
}
