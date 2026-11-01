# Hummingbird's own policies, beyond the CGE starter set. Each one closes a gap the starter
# leaves open, joins the same initiative (so it inherits to the whole sandbox), starts at an
# audit effect, and is escalated by a reviewed variable change. (CSF: DE.CM, PR.PS)

# --- hbai-dine-blob-access-logs: who read, wrote, or deleted a blob ---
# The starter's cge-dine-storage-diagnostics reports Compliant, but it only routes
# account-level Transaction metrics. Blob access logs live on blobServices/default, and
# nothing collected them (verified 2026-11-01: no diagnostic setting there on the evidence
# store). Compliant, not effective. This policy routes StorageRead/Write/Delete to the GRC
# workspace, so "who touched the evidence" has an answer. (NIST 800-53 AU-2, AU-12)
#
# blast radius: adds one diagnostic setting per storage account's blob service. Changes no
# data, access, or network settings. Cost is Log Analytics ingestion, mostly from the
# Function runtime accounts (lease renewals); the budget alert watches it.
# rollback: set blob_access_logs_effect = "Disabled". Settings already deployed stay until
# removed by hand.

resource "azurerm_policy_definition" "blob_access_logs" {
  name                = "hbai-dine-blob-access-logs"
  display_name        = "Blob services must send access logs to the GRC workspace"
  policy_type         = "Custom"
  mode                = "All" # blobServices has no tags or location, so Indexed would skip it
  management_group_id = azurerm_management_group.sandbox.id

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["DeployIfNotExists", "AuditIfNotExists", "Disabled"]
      defaultValue  = "AuditIfNotExists"
    }
    workspaceId = {
      type     = "String"
      metadata = { displayName = "Log Analytics workspace resource ID" }
    }
  })

  policy_rule = jsonencode({
    if = {
      field  = "type"
      equals = "Microsoft.Storage/storageAccounts/blobServices"
    }
    then = {
      effect = "[parameters('effect')]"
      details = {
        type = "Microsoft.Insights/diagnosticSettings"
        roleDefinitionIds = [
          # Monitoring Contributor (the remediation identity already holds it at mg scope)
          "/providers/Microsoft.Authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa"
        ]
        # Compliant only when all three access-log categories are on and go to our workspace.
        existenceCondition = {
          allOf = [
            { field = "Microsoft.Insights/diagnosticSettings/workspaceId", equals = "[parameters('workspaceId')]" },
            {
              count = {
                field = "Microsoft.Insights/diagnosticSettings/logs[*]"
                where = {
                  allOf = [
                    { field = "Microsoft.Insights/diagnosticSettings/logs[*].category", in = ["StorageRead", "StorageWrite", "StorageDelete"] },
                    { field = "Microsoft.Insights/diagnosticSettings/logs[*].enabled", equals = "true" }
                  ]
                }
              }
              equals = 3
            }
          ]
        }
        deployment = {
          properties = {
            mode = "incremental"
            parameters = {
              resourceName = { value = "[field('fullName')]" } # <account>/default
              workspaceId  = { value = "[parameters('workspaceId')]" }
            }
            template = {
              "$schema"      = "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#"
              contentVersion = "1.0.0.0"
              parameters = {
                resourceName = { type = "string" }
                workspaceId  = { type = "string" }
              }
              resources = [
                {
                  type       = "Microsoft.Storage/storageAccounts/blobServices/providers/diagnosticSettings"
                  apiVersion = "2021-05-01-preview"
                  name       = "[concat(parameters('resourceName'), '/Microsoft.Insights/ds-blob-access-to-grc')]"
                  properties = {
                    workspaceId = "[parameters('workspaceId')]"
                    logs = [
                      { category = "StorageRead", enabled = true },
                      { category = "StorageWrite", enabled = true },
                      { category = "StorageDelete", enabled = true }
                    ]
                  }
                }
              ]
            }
          }
        }
      }
    }
  })
}
