# Azure Defender for Servers: Resource-Level Exclusions

## Table of Contents

- [Overview](#overview)
- [Control model](#control-model)
- [Important conditions](#important-conditions)
- [Pilot implementation](#pilot-implementation)
- [Backfill and audit](#backfill-and-audit)
- [Rollback](#rollback)

## Overview

This guide implements resource-level exclusions while retaining Defender for Servers Plan 2 as the subscription-wide default. A Microsoft built-in Azure Policy uses a resource tag to [disable Defender for Servers](https://learn.microsoft.com/en-us/azure/defender-for-cloud/tutorial-enable-servers-plan#disable-the-plan-using-azure-policy-for-resource-tag) on confirmed VDI resources by deploying `pricingTier: Free`. Untagged servers continue to inherit Plan 2. The guide covers the required subscription setting, policy assignment, remediation, validation, and rollback. Plan 1 is not used.

> **Endpoint protection prerequisite:** Disabled VDI resources no longer receive the Defender for Servers entitlement. Do not rely on the [Defender for Endpoint integration in Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/integration-defender-for-endpoint) for their onboarding; establish and validate separate Defender for Endpoint licensing, onboarding, and EDR operations before rollout.

Use this Microsoft built-in policy:

> [**Configure Azure Defender for Servers to be disabled for resources (resource level) with the selected tag**](https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies#security-center---granular-pricing)

| Property | Value |
| --- | --- |
| Policy definition ID | `080fedce-9d4a-4d07-abf0-9f036afbc9c8` |
| Effect | `DeployIfNotExists` |
| Target resources | Azure VMs, VM scale sets, and Azure Arc-enabled servers |
| Deployed configuration | `Microsoft.Security/pricings/VirtualMachines` |
| Pricing setting | `pricingTier: Free` |

## Control model

Azure Policy and Microsoft's `ResourceLevelPricingAtScale.ps1` script both write the [`Microsoft.Security/pricings/virtualMachines` resource](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/pricings/update?view=rest-defenderforcloud-composite-latest) at VM, VMSS, or Arc server scope with API version `2024-01-01`. Microsoft calls this [**granular pricing** or **resource-level pricing**](https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies#security-center---granular-pricing). Policy is the continuous control; the script supports one-time operations.

| Aspect | Built-in Azure Policy | `ResourceLevelPricingAtScale.ps1` |
| --- | --- | --- |
| Style | Declarative and continuous | Imperative and one-shot |
| Trigger | Policy evaluation and remediation | Manual execution |
| Selection | Direct resource tag configured in the definition | `TAG` or `RG` mode |
| Steady state | Self-heals and evaluates new or recreated VDI resources | Must be rerun for new resources |
| Use in this design | Deploy `pricingTier: Free` and remediate existing resources | Audit with `Read`; rollback with `Delete` |
| Rollback | Removing the tag or assignment does not delete deployed configuration | `Delete` removes the resource-level object |
| Requirements | Managed identity with Security Admin | PowerShell 7.4+, Az modules, and an operator with required pricing permissions such as Security Admin |

[At resource scope](https://learn.microsoft.com/en-us/azure/defender-for-cloud/plan-defender-for-servers-select-plan), Plan 1 or Plan 2 can be disabled, but only Plan 1 can be enabled. Plan 2 cannot be enabled there. The script's `Standard` option hardcodes `P1` and is not used. `Free` disables Defender for Servers; it is not a Plan 1 downgrade.

## Important conditions

1. **Check the subscription pricing enforcement setting before deployment.** If `enforce` is already `False`, no change is required. If it is `True`, resource-level exclusions are blocked and Policy remediation will fail. Changing it to `False` keeps Plan 2 as the subscription default while allowing explicit resource-level exceptions. Untagged resources continue inheriting Plan 2. Obtain security-owner approval before making this change.

   Use [`Invoke-AzRestMethod`](https://learn.microsoft.com/en-us/powershell/module/az.accounts/invoke-azrestmethod) from Az PowerShell to inspect the setting with the identity authenticated by `Connect-AzAccount`:

   ```powershell
   Connect-AzAccount
   $subscriptionId = '<subscription-id>'
   Set-AzContext -SubscriptionId $subscriptionId
   $pricingPath = "/subscriptions/$subscriptionId/providers/Microsoft.Security/pricings/VirtualMachines?api-version=2024-01-01"
   $pricing = (Invoke-AzRestMethod -Method GET -Path $pricingPath).Content | ConvertFrom-Json
   $pricing.properties | Select-Object pricingTier, subPlan, enforce
   ```

   The result should show `Standard`, `P2`, and `False`. If `enforce` is `True` and approval is obtained, preserve the current tier, subplan, and extensions while changing only `enforce`:

   ```powershell
   $updateProperties = [ordered]@{
	   pricingTier = $pricing.properties.pricingTier
	   subPlan     = $pricing.properties.subPlan
	   enforce     = 'False'
   }
   if ($null -ne $pricing.properties.extensions) {
	   $updateProperties['extensions'] = $pricing.properties.extensions
   }

   $payload = @{ properties = $updateProperties } | ConvertTo-Json -Depth 20
   Invoke-AzRestMethod -Method PUT -Path $pricingPath -Payload $payload
   ```

   Run the GET block again after the update. Verify `Standard`, `P2`, and `False`, and confirm that all configured Plan 2 extensions remain in their intended state.
2. VDI classification must use an authoritative tag applied directly to the VM or scale set. Resource-group tags are not inherited by this policy.
3. Existing resources need an [Azure Policy remediation task](https://learn.microsoft.com/en-us/azure/governance/policy/how-to/remediate-resources). [New or updated resources are typically reflected around 15 minutes later](https://learn.microsoft.com/en-us/azure/governance/policy/how-to/get-compliance-data#evaluation-triggers); standard reevaluation runs every 24 hours, with no fixed completion time for large scopes. Use an on-demand scan when needed.
4. Check for management-group policies or automation that could overwrite the resource-level setting.
5. Removing the tag or assignment does not delete deployed configuration. Re-inheritance requires an explicit delete.

## Pilot implementation

Use a non-production resource group with one representative VDI machine and one untagged server.

1. Check the subscription pricing enforcement setting in condition 1 and record both machines' pricing, endpoint, and power state.
2. Apply `DefenderForServers=VDI-Disabled` directly to the VDI resource.
3. In **Policy** > **Definitions**, find `080fedce-9d4a-4d07-abf0-9f036afbc9c8` and assign it to the pilot scope with enforcement enabled.
4. Set **Inclusion Tag Name** to `DefenderForServers`, **Inclusion Tag Values** to `VDI-Disabled`, and **Effect** to `DeployIfNotExists`.
5. Create a remediation task with a system-assigned identity granted [**Security Admin**](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/security#security-admin) (`fb1c8493-542b-48eb-b624-b4c8fea62acd`) at the assignment scope. The [`DeployIfNotExists` effect](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effect-deploy-if-not-exists) uses this identity to deploy the configuration.
6. Verify the VDI reports `pricingTier: Free` and `inherited: False`; verify the server still inherits Plan 2.
7. Confirm endpoint protection remains healthy and a newly provisioned VDI receives the tag and reaches compliance.

Roll out one resource group at a time after security owners approve the pilot.

## Backfill and audit

The policy remains authoritative. Use a policy remediation task to backfill confirmed existing VDI resources and leave the policy assigned for continuous evaluation. Use `ResourceLevelPricingAtScale.ps1` only for validation and rollback:

1. Run `Read` mode to audit the effective resource-level pricing objects after remediation.
2. Do not run the script in `Free` mode against policy-managed resources. Azure Policy and the script would become competing writers for the same resource-level pricing objects.
3. Do not use `Standard`; the script enables Plan 1 rather than restoring subscription-level Plan 2 inheritance.

## Rollback

Removing the tag or policy assignment does not delete a resource-level configuration already deployed by `DeployIfNotExists`.

1. Stop applying the VDI classification tag.
2. Disable or delete the policy assignment.
3. Run `ResourceLevelPricingAtScale.ps1` in `Delete` mode, or issue the equivalent supported REST `DELETE`, to remove `Microsoft.Security/pricings/virtualMachines` from affected VDI resources.
4. Verify that each resource again inherits subscription-level Plan 2.

Microsoft provides the [`ResourceLevelPricingAtScale.ps1` management script](https://github.com/Azure/Microsoft-Defender-for-Cloud/tree/main/Powershell%20scripts/Defender%20for%20Servers%20on%20resource%20level) for these one-time operations.
