# Drift detector 2 of 2: who is touching reality?
# (Detector 1 is .github/workflows/drift.yml: does reality still match the code?)
#
# Every hour, look for successful write or delete operations in the Activity Log
# (routed to law-grc-sandbox in Lab 02) by any caller other than the remediation
# identity. Every automated change in this pipeline runs as that identity; CI only
# plans. Anything else is a person, or an unknown principal, changing Azure, and it
# should match a merged pull request. The alert names the caller.
#
# Kind: detective. It changes nothing in Azure.
# blast radius: none. It reads the workspace and sends email to the owner.
# rollback: delete this file and apply; the action group and rule are removed.
# Known limit: the owner's own `terraform apply` alerts too (it runs as the owner).
#   That is intended: each alert is checked against the merged PRs.

resource "azurerm_monitor_action_group" "grc_owner" {
  name                = "ag-grc-owner-${var.environment}"
  resource_group_name = azurerm_resource_group.sandbox.name
  short_name          = "grcowner"

  email_receiver {
    name                    = "owner"
    email_address           = var.owner_email
    use_common_alert_schema = true
  }

  tags = {
    env     = var.environment
    purpose = "grc-alerting"
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "out_of_band_writes" {
  name                = "alert-grc-out-of-band-writes-${var.environment}"
  display_name        = "GRC tripwire: Azure changed outside the pipeline"
  description         = "Successful write/delete in the Activity Log by a caller other than the remediation identity. Check it against merged PRs."
  resource_group_name = azurerm_resource_group.sandbox.name
  location            = var.location
  scopes              = [azurerm_log_analytics_workspace.grc.id]
  severity            = 2

  evaluation_frequency = "PT1H"
  window_duration      = "PT1H"

  criteria {
    query = <<-KQL
      AzureActivity
      | where CategoryValue == "Administrative"
      | where ActivityStatusValue in~ ("Success", "Succeeded")
      | where OperationNameValue endswith "/write" or OperationNameValue endswith "/delete"
      | where Caller !in~ ("${azurerm_user_assigned_identity.remediation.principal_id}", "${azurerm_user_assigned_identity.remediation.client_id}")
      | project TimeGenerated, Caller, OperationNameValue, ResourceGroup, _ResourceId
    KQL

    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0

    # One alert per caller, so the email says who.
    dimension {
      name     = "Caller"
      operator = "Include"
      values   = ["*"]
    }

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.grc_owner.id]
  }

  tags = {
    env     = var.environment
    purpose = "grc-alerting"
  }
}
