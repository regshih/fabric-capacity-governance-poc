targetScope = 'resourceGroup'

@description('Azure region for POC resources.')
param location string = resourceGroup().location

@allowed([
  'existing'
  'create'
])
@description('Create a POC capacity or manage an existing one outside this template.')
param capacityMode string = 'existing'

@description('Explicit safety gate for capacity creation.')
param allowCapacityCreation bool = false

@description('Fabric capacity resource name. Keep blank in safe previews when capacityMode is existing.')
param capacityName string = ''

@allowed([
  'F2'
])
@description('The template intentionally permits automatic creation of F2 only.')
param fabricSku string = 'F2'

@secure()
@description('Capacity administrator UPN or object ID. Supplied only at runtime and never committed.')
param capacityAdmin string = ''

@description('Create or reconcile the Azure Automation account.')
param enableAutomation bool = false

@description('Automation account name. Supplied only in ignored runtime configuration.')
param automationAccountName string = ''

@description('Non-identifying tags applied to POC resources. The deployment wrapper adds a private provenance tag at runtime.')
param tags object = {
  purpose: 'fabric-capacity-governance-poc'
  'managed-by': 'poc'
}

var createCapacity = capacityMode == 'create' && allowCapacityCreation

resource capacity 'Microsoft.Fabric/capacities@2023-11-01' = if (createCapacity) {
  name: capacityName
  location: location
  sku: {
    name: fabricSku
    tier: 'Fabric'
  }
  tags: tags
  properties: {
    administration: {
      members: [
        capacityAdmin
      ]
    }
  }
}

resource automation 'Microsoft.Automation/automationAccounts@2023-11-01' = if (enableAutomation) {
  name: automationAccountName
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    sku: {
      name: 'Basic'
    }
    disableLocalAuth: true
    publicNetworkAccess: true
  }
}

output capacityResourceId string = createCapacity ? capacity.id : ''
output automationResourceId string = enableAutomation ? automation.id : ''
