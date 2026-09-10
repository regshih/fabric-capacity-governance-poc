"""Fabric Capacity Governance POC.

A small, dependency-light toolkit demonstrating three governance controls over
Microsoft Fabric F-SKU capacities:

1. Pause/resume automation via the Azure Resource Manager control plane.
2. Azure RBAC scoping of who may manage a capacity.
3. Azure Policy restriction of which F-SKUs may be deployed.

Nothing in this package stores credentials. Authentication is delegated to
``azure.identity.DefaultAzureCredential`` (typically ``az login`` locally, or a
system-assigned managed identity in Azure Automation).
"""

__version__ = "1.0.0"
