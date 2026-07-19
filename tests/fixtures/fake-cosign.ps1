[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification = 'The executable shim exchanges invocation state with its Pester caller through the global test scope.')]
param()

$commandArguments = @($args)
$global:LASTEXITCODE = 0
$global:CosignInvocations = @($global:CosignInvocations) + ,$commandArguments

if ($commandArguments[0] -eq 'verify-attestation') {
    if ($commandArguments -contains 'spdxjson') { $global:SpdxEnvelopeOutput }
    if ($commandArguments -contains 'slsaprovenance1') { $global:SlsaEnvelopeOutput }
}

if ($commandArguments[0] -eq 'attest' -and $commandArguments -contains 'slsaprovenance1') {
    $predicateIndex = [Array]::IndexOf($commandArguments, '--predicate')
    $global:AttestedSlsaPredicate = Get-Content -LiteralPath $commandArguments[$predicateIndex + 1] -Raw | ConvertFrom-Json -Depth 100
}