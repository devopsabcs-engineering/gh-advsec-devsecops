targetScope = 'resourceGroup'

@description('The globally unique name of the documentation storage account')
param storageAccountName string

@description('The location for the documentation storage account')
param location string

@description('The object ID of the identity that uploads documentation content')
param dataUploadPrincipalId string = ''

@description('The object ID of the identity that manages static website configuration')
param staticSiteManagementPrincipalId string = ''

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Enabled'
    supportsHttpsTrafficOnly: true
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2026-04-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
    staticWebsite: {
      enabled: true
      errorDocument404Path: '404.html'
      indexDocument: 'index.html'
    }
  }
}

resource webContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: '$web'
  properties: {
    publicAccess: 'None'
  }
}

resource dataUploadRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(dataUploadPrincipalId)) {
  name: guid(webContainer.id, dataUploadPrincipalId, 'Storage Blob Data Contributor')
  scope: webContainer
  properties: {
    principalId: dataUploadPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
  }
}

resource staticSiteManagementRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(staticSiteManagementPrincipalId)) {
  name: guid(storageAccount.id, staticSiteManagementPrincipalId, 'Storage Account Contributor')
  scope: storageAccount
  properties: {
    principalId: staticSiteManagementPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '17d1049b-9a84-46fb-8f53-869881c3d3ab')
  }
}

output storageAccountName string = storageAccount.name
output storageAccountResourceId string = storageAccount.id
output webContainerResourceId string = webContainer.id
output webEndpoint string = storageAccount.properties.primaryEndpoints.web
