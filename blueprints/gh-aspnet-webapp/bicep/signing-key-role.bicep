targetScope = 'resourceGroup'

@description('The name of the existing signing Key Vault')
param signingKeyVaultName string

@description('The name of the existing asymmetric signing key')
param signingKeyName string

@description('The object ID of the pipeline identity that signs artifacts')
param signingPrincipalId string

resource signingKeyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: signingKeyVaultName
}

resource signingKey 'Microsoft.KeyVault/vaults/keys@2023-07-01' existing = {
  parent: signingKeyVault
  name: signingKeyName
}

resource signingRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(signingKey.id, signingPrincipalId, 'Key Vault Crypto User')
  scope: signingKey
  properties: {
    principalId: signingPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '12338af0-0e69-4776-bea7-57ae8d297424')
  }
}
