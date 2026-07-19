// Bicep file to deploy a containerized web app to Azure

@description('The name of the Azure Container Registry')
param acrName string

@description('The SKU of the Azure Container Registry')
param acrSku string = 'Basic'

@description('The name of the App Service Plan')
param appServicePlanName string

@description('The name of the Web App')
param webAppName string

@description('The location for all resources')
param location string

@description('The name of the Resource Group')
param resourceGroupName string = 'rg-webapp01-dev'

@description('The object ID of the identity that uploads documentation content')
param docsDataUploadPrincipalId string = ''

@description('The object ID of the identity that manages documentation static website configuration')
param docsStaticSiteManagementPrincipalId string = ''

@description('The subscription containing the existing signing Key Vault')
param signingKeyVaultSubscriptionId string = subscription().subscriptionId

@description('The resource group containing the existing signing Key Vault')
param signingKeyVaultResourceGroupName string = ''

@description('The name of the existing signing Key Vault')
param signingKeyVaultName string = ''

@description('The name of the existing asymmetric signing key')
param signingKeyName string = ''

@description('The object ID of the pipeline identity that signs artifacts')
param signingPrincipalId string = ''

// Create the resource group at the subscription level
targetScope = 'subscription'

resource resourceGroup 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  name: resourceGroupName
  location: location
}

// Generate unique suffix based on resource group ID for customer-specific uniqueness
var uniqueSuffix = uniqueString(resourceGroup.id)
var signingKeyReferenceConfigured = !empty(signingKeyVaultResourceGroupName) && !empty(signingKeyVaultName) && !empty(signingKeyName)
var assignSigningRole = signingKeyReferenceConfigured && !empty(signingPrincipalId)

// Deploy resources within the resource group
module resourcesInRG './resources.bicep' = {
  name: 'deployResourcesInRG'
  scope: resourceGroup
  params: {
    acrName: '${acrName}${uniqueSuffix}'
    acrSku: acrSku
    appServicePlanName: '${appServicePlanName}-${uniqueSuffix}'
    webAppName: '${webAppName}-${uniqueSuffix}'
    location: location
  }
}

module docsStorageInRG './docs-storage.bicep' = {
  name: 'deployDocsStorageInRG'
  scope: resourceGroup
  params: {
    storageAccountName: 'stdocs${uniqueSuffix}'
    location: location
    dataUploadPrincipalId: docsDataUploadPrincipalId
    staticSiteManagementPrincipalId: docsStaticSiteManagementPrincipalId
  }
}

module signingKeyRole './signing-key-role.bicep' = if (assignSigningRole) {
  name: 'deploySigningKeyRole'
  scope: az.resourceGroup(signingKeyVaultSubscriptionId, signingKeyVaultResourceGroupName)
  params: {
    signingKeyVaultName: signingKeyVaultName
    signingKeyName: signingKeyName
    signingPrincipalId: signingPrincipalId
  }
}

// Expose outputs from the module for use in CI/CD pipelines
output resourceGroupName string = resourceGroup.name
output webAppName string = resourcesInRG.outputs.webAppName
output webAppUrl string = resourcesInRG.outputs.webAppUrl
output acrLoginServer string = resourcesInRG.outputs.acrLoginServer
output webAppPrincipalId string = resourcesInRG.outputs.webAppPrincipalId
output docsStorageAccountName string = docsStorageInRG.outputs.storageAccountName
output docsStorageAccountResourceId string = docsStorageInRG.outputs.storageAccountResourceId
output docsWebContainerResourceId string = docsStorageInRG.outputs.webContainerResourceId
output docsWebEndpoint string = docsStorageInRG.outputs.webEndpoint
output signingKeyVaultResourceId string = signingKeyReferenceConfigured ? resourceId(signingKeyVaultSubscriptionId, signingKeyVaultResourceGroupName, 'Microsoft.KeyVault/vaults', signingKeyVaultName) : ''
output signingKeyResourceId string = signingKeyReferenceConfigured ? resourceId(signingKeyVaultSubscriptionId, signingKeyVaultResourceGroupName, 'Microsoft.KeyVault/vaults/keys', signingKeyVaultName, signingKeyName) : ''
