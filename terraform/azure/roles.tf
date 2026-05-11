data azurerm_subscription current_subscription {}

resource "azurerm_role_definition" "example" {
  name        = "my-custom-role"
  scope       = data.azurerm_subscription.current_subscription.id
  description = "This is a custom role created via Terraform"

  permissions {
    actions     = [
      "Microsoft.Compute/*/read",
      "Microsoft.Storage/*/read",
      "Microsoft.Network/*/read"
    ]
    not_actions = []
  }

  assignable_scopes = [
    data.azurerm_subscription.current_subscription.id
  ]
}