# TEST ONLY: deliberately non-compliant, to prove the CI gate blocks it. Never merge.
resource "azurerm_storage_account" "gate_test" {
  name                            = "stgrcgatetest001"
  resource_group_name             = "rg-grc-evidence-dev"
  location                        = "eastus2"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
  shared_access_key_enabled       = true
}
