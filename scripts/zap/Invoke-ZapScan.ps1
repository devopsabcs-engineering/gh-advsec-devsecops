[CmdletBinding()]
param(
    [ValidateSet('baseline', 'full')][string]$ScanType,
    [string]$ZapImage,
    [string]$ResultsPath,
    [string]$Target = 'https://app-juice-shop.azurewebsites.net',
    [switch]$BuildAndStart,
    [string]$DockerfilePath = 'src/webapp01/Dockerfile',
    [int]$HostPort = 18080,
    [int]$ReadinessAttempts = 30,
    [ValidateRange(1, 3600)][int]$ScannerTimeoutSeconds = 1860
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-DockerCommand {
    param([Parameter(Mandatory)][string[]]$Arguments, [switch]$IgnoreExitCode)
    & docker @Arguments
    if (-not $IgnoreExitCode -and $LASTEXITCODE -ne 0) { throw "Docker command failed: docker $($Arguments -join ' ')" }
}

function Invoke-DockerCommandWithTimeout {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [ValidateRange(1, 3600)][int]$TimeoutSeconds
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = 'docker'
    $startInfo.UseShellExecute = $false
    foreach ($argument in $Arguments) { [void]$startInfo.ArgumentList.Add($argument) }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw 'Unable to start the Docker scanner process.' }
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill($true)
            throw "Docker command timed out after $TimeoutSeconds seconds: docker $($Arguments -join ' ')"
        }
        if ($process.ExitCode -ne 0) { throw "Docker command failed: docker $($Arguments -join ' ')" }
    }
    finally { $process.Dispose() }
}

function Test-LinuxPlatform {
    return [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Linux)
}

function Invoke-HostIdCommand {
    param([ValidateSet('-u', '-g')][string]$Argument)
    $value = [string](& id $Argument)
    if ($LASTEXITCODE -ne 0) { throw "Unable to retrieve the host identity with 'id $Argument'." }
    return $value.Trim()
}

function Get-LinuxHostUser {
    $uid = Invoke-HostIdCommand -Argument '-u'
    $gid = Invoke-HostIdCommand -Argument '-g'
    if ($uid -notmatch '^[0-9]+$' -or $gid -notmatch '^[0-9]+$') { throw 'ZAP requires numeric host UID and GID values.' }
    if ($uid -eq '0' -or $gid -eq '0') { return '1000:1000' }
    return "${uid}:${gid}"
}

function Wait-RetryDelay {
    param([ValidateRange(1, 60)][int]$Seconds)
    Start-Sleep -Seconds $Seconds
}

function Wait-HttpReady {
    param([string]$Uri, [int]$Attempts, [ValidateRange(1, 60)][int]$RetryDelaySeconds = 2)
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        try { Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec 5 | Out-Null; return $true } catch { Write-Verbose "Readiness attempt $attempt failed: $($_.Exception.Message)" }
        if ($attempt -lt $Attempts) { Wait-RetryDelay -Seconds $RetryDelaySeconds }
    }
    throw "Target did not become ready after $Attempts attempts: $Uri"
}

function Get-DockerPublishedEndpoint {
    param([Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port)

    if ($env:DOCKER_HOST -match '^tcp://') {
        $daemonUri = [uri]$env:DOCKER_HOST
        return [pscustomobject]@{ Binding = "0.0.0.0:${Port}:8080"; ReadinessUri = "http://$($daemonUri.Host):$Port" }
    }

    return [pscustomobject]@{ Binding = "127.0.0.1:${Port}:8080"; ReadinessUri = "http://127.0.0.1:$Port" }
}

function Test-ZapSarifReport {
    param([Parameter(Mandatory)][string]$LiteralPath)
    try { $sarif = Get-Content -LiteralPath $LiteralPath -Raw | ConvertFrom-Json -Depth 100 } catch { throw "ZAP SARIF is invalid JSON: $($_.Exception.Message)" }
    if ($sarif.version -ne '2.1.0' -or @($sarif.runs).Count -eq 0) { throw 'ZAP SARIF must be version 2.1.0 with at least one run.' }
    return $true
}

function Assert-ZapAuthorizationRecord {
    param(
        [Parameter(Mandatory)][string]$Record,
        [Parameter(Mandatory)][string]$TargetUri,
        [Parameter(Mandatory)][string]$Mode,
        [datetimeoffset]$Now = [datetimeoffset]::UtcNow
    )

    try { $authorization = $Record | ConvertFrom-Json -Depth 20 } catch { throw "ZAP_AUTHORIZATION_RECORD is invalid JSON: $($_.Exception.Message)" }
    foreach ($property in @('target', 'notBeforeUtc', 'expiresUtc', 'allowedScanTypes')) {
        if ($authorization.PSObject.Properties.Name -notcontains $property) { throw "ZAP_AUTHORIZATION_RECORD is missing '$property'." }
    }

    if ([string]$authorization.target -ne $TargetUri) { throw 'ZAP_AUTHORIZATION_RECORD does not match the requested target.' }
    if (@($authorization.allowedScanTypes) -notcontains $Mode) { throw "ZAP_AUTHORIZATION_RECORD does not approve the '$Mode' scan type." }

    try {
        $notBefore = [datetimeoffset]::Parse([string]$authorization.notBeforeUtc).ToUniversalTime()
        $expires = [datetimeoffset]::Parse([string]$authorization.expiresUtc).ToUniversalTime()
    }
    catch { throw "ZAP_AUTHORIZATION_RECORD contains an invalid UTC window: $($_.Exception.Message)" }

    if ($notBefore -ge $expires -or $Now -lt $notBefore -or $Now -gt $expires) { throw 'ZAP_AUTHORIZATION_RECORD is outside its approved UTC scan window.' }
}

function Invoke-ZapLifecycle {
    [CmdletBinding()]
    param([string]$Mode, [string]$Image, [string]$Output, [string]$TargetUri, [bool]$StartTarget, [string]$Dockerfile, [int]$PublishedPort, [int]$Attempts, [int]$ScannerTimeout)
    if ($Image -notmatch '@sha256:[a-fA-F0-9]{64}$') { throw 'ZAP image must be digest-qualified.' }
    $runId = [guid]::NewGuid().ToString('N')
    $network = "zap-$runId"
    $container = "zap-target-$runId"
    $scanner = "zap-scanner-$runId"
    $localImage = "zap-target:$runId"
    $stateDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "zap-state-$runId"
    New-Item -ItemType Directory -Path $Output -Force | Out-Null
    New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
    try {
        if ($StartTarget) {
            $buildContext = Split-Path -Parent $Dockerfile
            if ([string]::IsNullOrWhiteSpace($buildContext)) { $buildContext = '.' }
            $publishedEndpoint = Get-DockerPublishedEndpoint -Port $PublishedPort
            Invoke-DockerCommand @('build', '--file', $Dockerfile, '--tag', $localImage, $buildContext)
            Invoke-DockerCommand @('network', 'create', $network)
            Invoke-DockerCommand @('run', '--detach', '--name', $container, '--network', $network, '--network-alias', 'webapp', '--publish', $publishedEndpoint.Binding, $localImage)
            Wait-HttpReady -Uri $publishedEndpoint.ReadinessUri -Attempts $Attempts | Out-Null
            $TargetUri = 'http://webapp:8080'
        }
        elseif ($Mode -eq 'full') {
            if ([string]::IsNullOrWhiteSpace($env:ZAP_AUTHORIZATION_RECORD)) { throw 'ZAP_AUTHORIZATION_RECORD is required for remote full scans.' }
            Assert-ZapAuthorizationRecord -Record $env:ZAP_AUTHORIZATION_RECORD -TargetUri $TargetUri -Mode $Mode
            Wait-HttpReady -Uri $TargetUri -Attempts $Attempts | Out-Null
        }
        else { Wait-HttpReady -Uri $TargetUri -Attempts $Attempts | Out-Null }

        $mount = "$(Resolve-Path $Output):/zap/wrk:rw"
        $networkArgs = if ($StartTarget) { @('--network', $network) } else { @() }
        $scannerUser = if (Test-LinuxPlatform) { Get-LinuxHostUser } else { $null }
        $userArgs = if ($scannerUser) { @('--user', $scannerUser) } else { @() }
        $plan = "/zap/wrk/$Mode-plan.yaml"
        $stateMount = "$(Resolve-Path $stateDirectory):/zap/home:rw"
        if ($scannerUser) {
            Invoke-DockerCommand @('run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--security-opt', 'no-new-privileges', '--user', '0:0', '--volume', $mount, '--volume', $stateMount, '--entrypoint', 'chown', $Image, $scannerUser, '/zap/wrk', '/zap/home')
        }
        Invoke-DockerCommandWithTimeout -TimeoutSeconds $ScannerTimeout -Arguments (@('run', '--rm', '--name', $scanner) + $networkArgs + $userArgs + @('--env', 'HOME=/zap/home', '--env', 'JAVA_TOOL_OPTIONS=-Duser.home=/zap/home', '--env', "ZAP_TARGET=$TargetUri", '--volume', $mount, '--volume', $stateMount, $Image, 'zap.sh', '-cmd', '-autorun', $plan))
        $generatedSarif = Join-Path $Output "$Mode.sarif.json"
        if (Test-Path -LiteralPath $generatedSarif -PathType Leaf) {
            Move-Item -LiteralPath $generatedSarif -Destination (Join-Path $Output "$Mode.sarif") -Force
        }
        foreach ($extension in @('html', 'json', 'sarif')) {
            if (-not (Test-Path -LiteralPath (Join-Path $Output "$Mode.$extension") -PathType Leaf)) { throw "ZAP did not produce $Mode.$extension." }
        }
        Test-ZapSarifReport -LiteralPath (Join-Path $Output "$Mode.sarif") | Out-Null
    }
    finally {
        Invoke-DockerCommand @('rm', '--force', $scanner) -IgnoreExitCode
        if ($StartTarget) {
            Invoke-DockerCommand @('rm', '--force', $container) -IgnoreExitCode
            Invoke-DockerCommand @('network', 'rm', $network) -IgnoreExitCode
        }
        Remove-Item -LiteralPath $stateDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($PSBoundParameters.ContainsKey('ScanType')) {
    Invoke-ZapLifecycle $ScanType $ZapImage $ResultsPath $Target $BuildAndStart.IsPresent $DockerfilePath $HostPort $ReadinessAttempts $ScannerTimeoutSeconds
}
