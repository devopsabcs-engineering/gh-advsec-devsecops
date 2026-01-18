<#
.SYNOPSIS
    Deploys Azure infrastructure using Bicep templates.

.DESCRIPTION
    This script deploys the Azure infrastructure defined in main.bicep
    using the parameters from main.parameters.json.

.PARAMETER ParameterFile
    Path to the parameters file. Defaults to main.parameters.json.

.PARAMETER Location
    Azure region for deployment. Defaults to canadacentral.

.PARAMETER DeploymentName
    Name of the deployment. Defaults to a timestamped name.

.PARAMETER WhatIf
    Performs a what-if operation without actually deploying.

.EXAMPLE
    .\deploy.ps1

.EXAMPLE
    .\deploy.ps1 -Location "eastus" -WhatIf
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ParameterFile = "main.parameters.json",

    [Parameter(Mandatory = $false)]
    [string]$Location = "canadacentral",

    [Parameter(Mandatory = $false)]
    [string]$DeploymentName = "deploy-$(Get-Date -Format 'yyyyMMdd-HHmmss')",

    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

# Get the script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Resolve paths
$BicepFile = Join-Path $ScriptDir "main.bicep"
$ParameterFilePath = Join-Path $ScriptDir $ParameterFile

# Validate files exist
if (-not (Test-Path $BicepFile)) {
    Write-Error "Bicep file not found: $BicepFile"
    exit 1
}

if (-not (Test-Path $ParameterFilePath)) {
    Write-Error "Parameter file not found: $ParameterFilePath"
    exit 1
}

# Check if Azure CLI is installed
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Error "Azure CLI is not installed. Please install it from https://docs.microsoft.com/cli/azure/install-azure-cli"
    exit 1
}

# Check if logged in to Azure
$account = az account show 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Host "Not logged in to Azure. Please log in..." -ForegroundColor Yellow
    az login
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to log in to Azure"
        exit 1
    }
}

Write-Host "=== Azure Infrastructure Deployment ===" -ForegroundColor Cyan
Write-Host "Subscription: $($account.name)" -ForegroundColor Green
Write-Host "Bicep File: $BicepFile" -ForegroundColor Green
Write-Host "Parameters: $ParameterFilePath" -ForegroundColor Green
Write-Host "Location: $Location" -ForegroundColor Green
Write-Host "Deployment: $DeploymentName" -ForegroundColor Green
Write-Host ""

if ($WhatIf) {
    Write-Host "Running What-If analysis..." -ForegroundColor Yellow
    az deployment sub what-if `
        --name $DeploymentName `
        --location $Location `
        --template-file $BicepFile `
        --parameters @$ParameterFilePath
}
else {
    Write-Host "Starting deployment..." -ForegroundColor Yellow
    az deployment sub create `
        --name $DeploymentName `
        --location $Location `
        --template-file $BicepFile `
        --parameters @$ParameterFilePath

    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "Deployment completed successfully!" -ForegroundColor Green
        
        # Show deployment outputs
        Write-Host ""
        Write-Host "Deployment outputs:" -ForegroundColor Cyan
        az deployment sub show `
            --name $DeploymentName `
            --query "properties.outputs" `
            --output table
    }
    else {
        Write-Error "Deployment failed with exit code: $LASTEXITCODE"
        exit $LASTEXITCODE
    }
}
