<#
.SYNOPSIS
    Pauses or resumes a Microsoft Fabric F-SKU capacity from Azure Automation.

.DESCRIPTION
    Authenticates with the Automation account's system-assigned managed identity
    and drives a Fabric capacity to the requested state through the Azure
    Resource Manager control plane.

    The runbook is idempotent: it reads the capacity's current state first and
    exits without acting when the capacity is already in the desired state.

    Why Invoke-AzRestMethod rather than the Az.Fabric cmdlets
    ---------------------------------------------------------
    Suspend-AzFabricCapacity and Resume-AzFabricCapacity exist and are GA, but
    Az.Fabric only entered the Az rollup module in August 2025. Automation
    accounts created before that, or pinned to an older Az version, will not
    have it, and the failure appears at run time rather than at deployment.
    Invoke-AzRestMethod needs only Az.Accounts, which is present in every
    Automation sandbox, and it targets a pinned API version so the runbook's
    behaviour does not drift when a module is updated. It also surfaces the raw
    status code and headers, which correct long-running-operation handling
    requires anyway.

    Required permissions on the target capacity (per Microsoft's documented
    prerequisites for pause/resume):
        Microsoft.Fabric/capacities/read
        Microsoft.Fabric/capacities/write
        Microsoft.Fabric/capacities/suspend/action
        Microsoft.Fabric/capacities/resume/action
    Assign the "Fabric Capacity Lifecycle Operator" custom role from this
    repository to the Automation account's managed identity, scoped to the
    individual capacity. Provider-level LRO URLs are outside that resource
    scope, so this runbook falls back to polling the capacity resource itself.

.PARAMETER SubscriptionId
    Subscription containing the Fabric capacity.

.PARAMETER ResourceGroupName
    Resource group containing the Fabric capacity.

.PARAMETER CapacityName
    Name of the Fabric capacity.

.PARAMETER DesiredState
    Pause or Resume.

.PARAMETER TimeoutSeconds
    How long to wait for the operation to complete. Default 900.

.PARAMETER WhatIf
    Report what would happen without changing anything.

.NOTES
    No credentials are stored anywhere in this runbook. Authentication is via
    the system-assigned managed identity only.

    API version 2023-11-01 is the current stable (non-preview) version for
    Microsoft.Fabric/capacities.
    https://learn.microsoft.com/en-us/rest/api/microsoftfabric/fabric-capacities
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $SubscriptionId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $CapacityName,

    [Parameter(Mandatory = $true)]
    [ValidateSet('Pause', 'Resume')]
    [string] $DesiredState,

    [Parameter(Mandatory = $false)]
    [int] $TimeoutSeconds = 900
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Stable API version for Microsoft.Fabric/capacities.
$ApiVersion = '2023-11-01'

# properties.state is a wide enum. Microsoft documents both 'Suspended' and
# 'Paused' as possible values without stating which a suspend settles on, so we
# treat both as paused rather than guessing.
$PausedStates   = @('Paused', 'Suspended')
$RunningStates  = @('Active')
$InFlightStates = @('Suspending', 'Pausing', 'Resuming', 'Scaling', 'Updating',
                    'Provisioning', 'Preparing', 'Deleting')

function Write-Stamp {
    param([string] $Message, [string] $Level = 'INFO')
    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    Write-Output ("{0} {1,-7} {2}" -f $timestamp, $Level, $Message)
}

function Get-NormalizedState {
    param([string] $State)
    if ([string]::IsNullOrWhiteSpace($State)) { return 'unknown' }
    if ($PausedStates   -contains $State) { return 'paused' }
    if ($RunningStates  -contains $State) { return 'running' }
    if ($InFlightStates -contains $State) { return 'in-flight' }
    if ($State -eq 'Failed') { return 'failed' }
    return 'unknown'
}

function Get-CapacityResourceId {
    param([string] $SubscriptionId, [string] $ResourceGroupName, [string] $CapacityName)
    return "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Fabric/capacities/$CapacityName"
}

function Get-FabricCapacity {
    param([string] $ResourceId)

    $path = "${ResourceId}?api-version=$ApiVersion"
    $response = Invoke-AzRestMethod -Method GET -Path $path

    if ($response.StatusCode -eq 404) {
        throw "Fabric capacity not found. Verify the subscription, resource group, and capacity name, and that the managed identity has Microsoft.Fabric/capacities/read on it."
    }
    if ($response.StatusCode -eq 403) {
        throw "Access denied reading the capacity (HTTP 403). The managed identity is missing Microsoft.Fabric/capacities/read on this resource, or a policy blocked the request."
    }
    if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
        throw "Failed to read capacity. HTTP $($response.StatusCode): $($response.Content)"
    }

    return $response.Content | ConvertFrom-Json
}

function Test-TrustedArmUri {
    param([Parameter(Mandatory = $true)] [string] $Uri)

    try { $parsed = [System.Uri] $Uri }
    catch { return $false }

    return $parsed.IsAbsoluteUri `
        -and $parsed.Scheme -eq 'https' `
        -and -not [string]::IsNullOrWhiteSpace($script:ArmHost) `
        -and $parsed.Host -eq $script:ArmHost `
        -and [string]::IsNullOrEmpty($parsed.UserInfo) `
        -and [string]::IsNullOrEmpty($parsed.Fragment)
}

function Wait-ForOperation {
    <#
        Follows an Azure long-running operation to a terminal state.

        Suspend and resume return 200 (already done) or 202 (poll me). The 202
        carries a Location header and, in practice, an Azure-AsyncOperation
        header. Only Location is in the formal response contract, so we prefer
        Azure-AsyncOperation when present and fall back to Location.
    #>
    param(
        [Parameter(Mandatory = $true)] $Response,
        [int] $TimeoutSeconds = 900
    )

    if ($Response.StatusCode -ne 202) {
        return $true
    }

    $pollUrl = $null
    foreach ($headerName in @('Azure-AsyncOperation', 'Location')) {
        if ($Response.Headers -and $Response.Headers.Contains($headerName)) {
            $values = $Response.Headers.GetValues($headerName)
            if ($values -and $values.Count -gt 0) {
                $pollUrl = $values[0]
                break
            }
        }
    }

    if (-not $pollUrl) {
        Write-Stamp "Operation accepted (202) but no pollable header was returned; cannot confirm completion here." 'WARN'
        return $false
    }

    # The URL comes from a response header. Never send the managed identity's
    # ARM credential to another host, even if an unexpected response supplies
    # an absolute Location value.
    if (-not (Test-TrustedArmUri -Uri $pollUrl)) {
        Write-Stamp 'Azure returned an untrusted operation URL; falling back to capacity state polling.' 'WARN'
        return $false
    }

    $intervalSeconds = 10
    if ($Response.Headers -and $Response.Headers.Contains('Retry-After')) {
        $retryValues = $Response.Headers.GetValues('Retry-After')
        if ($retryValues -and $retryValues.Count -gt 0) {
            $parsed = 0
            if ([int]::TryParse($retryValues[0], [ref] $parsed) -and $parsed -gt 0) {
                $intervalSeconds = [Math]::Min($parsed, 60)
            }
        }
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $intervalSeconds

        try {
            $poll = Invoke-AzRestMethod -Method GET -Uri $pollUrl
        }
        catch {
            if ($_.Exception.Message -match '403|AuthorizationFailed') {
                Write-Stamp 'The provider-level operation URL is outside the capacity-scoped RBAC assignment; falling back to capacity state polling.' 'WARN'
                return $false
            }
            throw
        }
        if ($poll.StatusCode -eq 403) {
            Write-Stamp 'The provider-level operation URL is outside the capacity-scoped RBAC assignment; falling back to capacity state polling.' 'WARN'
            return $false
        }
        if ($poll.StatusCode -lt 200 -or $poll.StatusCode -ge 300) {
            Write-Stamp "Poll returned HTTP $($poll.StatusCode); continuing to wait." 'WARN'
            continue
        }

        $body = $null
        if ($poll.Content) { $body = $poll.Content | ConvertFrom-Json }

        $status = $null
        if ($body -and ($body.PSObject.Properties.Name -contains 'status')) {
            $status = $body.status
        }

        if (-not $status) {
            # A Location-style operation that has finished returns the resource.
            if ($poll.StatusCode -eq 200) { return $true }
            continue
        }

        switch ($status) {
            'Succeeded' { return $true }
            'Failed'    { throw "Operation failed: $($poll.Content)" }
            'Canceled'  { throw "Operation was canceled: $($poll.Content)" }
            default     { Write-Stamp "Operation status: $status" 'INFO' }
        }
    }

    throw "Operation did not complete within $TimeoutSeconds seconds. It may still be running; check the capacity state in the Azure portal."
}

function Wait-ForCapacityState {
    param(
        [Parameter(Mandatory = $true)] [string] $ResourceId,
        [Parameter(Mandatory = $true)] [string] $TargetNormalizedState,
        [int] $TimeoutSeconds = 900
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $capacity = Get-FabricCapacity -ResourceId $ResourceId
        $state = Get-NormalizedState -State $capacity.properties.state
        if ($state -eq $TargetNormalizedState) { return $capacity }
        if ($state -eq 'failed') {
            throw "Capacity entered Failed state while waiting for '$TargetNormalizedState'."
        }
        Start-Sleep -Seconds 10
    }
    throw "Capacity did not reach '$TargetNormalizedState' within $TimeoutSeconds seconds."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Stamp "Fabric capacity state runbook starting."
Write-Stamp "Requested state : $DesiredState"
Write-Stamp "Capacity        : $CapacityName"
Write-Stamp "Resource group  : $ResourceGroupName"

# Authenticate with the system-assigned managed identity. No secrets, no
# stored credentials. Disabling the context autosave keeps the sandbox from
# persisting a token to disk.
try {
    Disable-AzContextAutosave -Scope Process | Out-Null
    Write-Stamp "Connecting with system-assigned managed identity..."
    $account = Connect-AzAccount -Identity -ErrorAction Stop
    if (-not $account) { throw "Connect-AzAccount returned no context." }
    $context = Set-AzContext -Subscription $SubscriptionId -ErrorAction Stop
    $script:ArmHost = ([System.Uri] $context.Environment.ResourceManagerUrl).Host
    if ([string]::IsNullOrWhiteSpace($script:ArmHost)) {
        throw 'The selected Azure environment did not provide a trusted Resource Manager host.'
    }
    Write-Stamp "Authenticated. Subscription context set."
}
catch {
    Write-Stamp "Managed identity authentication failed: $($_.Exception.Message)" 'ERROR'
    Write-Stamp "Confirm the Automation account has a system-assigned managed identity enabled, and that it has been granted a role on the target capacity." 'ERROR'
    throw
}

$resourceId = Get-CapacityResourceId -SubscriptionId $SubscriptionId `
                                     -ResourceGroupName $ResourceGroupName `
                                     -CapacityName $CapacityName

$capacity = Get-FabricCapacity -ResourceId $resourceId
$currentState = $capacity.properties.state
$normalized = Get-NormalizedState -State $currentState
$targetNormalized = if ($DesiredState -eq 'Pause') { 'paused' } else { 'running' }

Write-Stamp "Current state   : $currentState (normalized: $normalized)"
Write-Stamp "Current SKU     : $($capacity.sku.name)"

if ($normalized -eq 'in-flight') {
    throw "Capacity is currently '$currentState' - another operation is already in flight. Refusing to issue a $DesiredState. Wait for the current operation to finish and re-run."
}

if ($normalized -eq 'failed') {
    throw "Capacity is in state '$currentState'. Resolve the failure in the Azure portal before issuing a $DesiredState."
}

if ($normalized -eq $targetNormalized) {
    Write-Stamp "No action required. Capacity is already $targetNormalized."
    Write-Output ""
    Write-Output "Requested: $DesiredState"
    Write-Output "Current: $currentState"
    Write-Output ""
    Write-Output "Result:"
    Write-Output "No action required."
    return
}

$operation = if ($DesiredState -eq 'Pause') { 'suspend' } else { 'resume' }
$operationPath = "${resourceId}/${operation}?api-version=$ApiVersion"

if (-not $PSCmdlet.ShouldProcess($CapacityName, "POST $operation")) {
    Write-Stamp "WhatIf: would POST $operation to the capacity. No change made."
    return
}

Write-Stamp "Issuing POST $operation ..."

# Both suspend and resume take no request body.
$response = Invoke-AzRestMethod -Method POST -Path $operationPath

if ($response.StatusCode -eq 403) {
    throw "Access denied (HTTP 403). The managed identity lacks Microsoft.Fabric/capacities/$operation/action (and/or write) on this capacity, or Azure Policy blocked the request. Content: $($response.Content)"
}
if ($response.StatusCode -eq 409) {
    throw "Conflict (HTTP 409). The capacity is mid-operation. Wait and retry. Content: $($response.Content)"
}
if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
    throw "The $operation request failed. HTTP $($response.StatusCode): $($response.Content)"
}

Write-Stamp "Request accepted (HTTP $($response.StatusCode)). Waiting for completion..."
Wait-ForOperation -Response $response -TimeoutSeconds $TimeoutSeconds | Out-Null

$after = Wait-ForCapacityState -ResourceId $resourceId `
                               -TargetNormalizedState $targetNormalized `
                               -TimeoutSeconds $TimeoutSeconds
$afterState = $after.properties.state
$afterNormalized = Get-NormalizedState -State $afterState

Write-Stamp "Final state     : $afterState (normalized: $afterNormalized)"

Write-Output ""
Write-Output "Requested: $DesiredState"
Write-Output "Current: $currentState"
Write-Output ""
Write-Output "Result:"
Write-Output "$currentState -> $afterState"

if ($afterNormalized -ne $targetNormalized) {
    throw "Capacity did not reach the expected state. Expected '$targetNormalized', got '$afterState'."
}

Write-Stamp "Runbook completed successfully."
