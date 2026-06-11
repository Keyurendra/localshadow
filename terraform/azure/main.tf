locals {
  otel_collector_config = templatefile("${path.module}/otel-collector-config.yaml", {
    tenant_id = var.artifact_tenant_id
  })
  cloud_init_config = templatefile("${path.module}/cloud-init.yaml", {
    provider              = "azure"
    artifact_token        = var.artifact_token
    artifact_endpoint     = var.artifact_endpoint
    artifact_label        = var.artifact_label
    artifact_tenant_id    = var.artifact_tenant_id
    omni_additional_flags = var.omni_additional_flags
    enable_telemetry      = var.enable_telemetry
    otel_collector_config = local.otel_collector_config
  })
}

resource "null_resource" "metadata_trigger" {
  triggers = {
    user_data = local.cloud_init_config
  }
}

data "azurerm_subscription" "current" {}

resource "azurerm_role_definition" "omni" {
  name              = "accuknox-omni"
  scope             = data.azurerm_subscription.current.id
  description       = "Permissions required for AccuKnox Omni"
  assignable_scopes = [data.azurerm_subscription.current.id]
  permissions {
    actions = [
      "Microsoft.Compute/virtualMachines/read",
      "Microsoft.Compute/virtualMachines/write",
      "Microsoft.Compute/disks/read",
      "Microsoft.Compute/disks/write",
      "Microsoft.Compute/disks/delete",
      "Microsoft.Compute/disks/beginGetAccess/action",
      "Microsoft.Compute/snapshots/read",
      "Microsoft.Compute/snapshots/write",
      "Microsoft.Compute/snapshots/delete",
      "Microsoft.Network/networkInterfaces/join/action",
      "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action",
    ]
    not_actions = []
  }
}

resource "azurerm_user_assigned_identity" "omni" {
  name                = "accuknox-omni"
  location            = azurerm_resource_group.omni.location
  resource_group_name = azurerm_resource_group.omni.name
}

resource "azurerm_role_assignment" "omni" {
  scope              = data.azurerm_subscription.current.id
  role_definition_id = azurerm_role_definition.omni.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.omni.principal_id
}

resource "azurerm_resource_group" "omni" {
  name     = "accuknox-omni"
  location = var.location
}

resource "azurerm_virtual_network" "omni" {
  name                = "accuknox-omni-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.omni.location
  resource_group_name = azurerm_resource_group.omni.name
}

resource "azurerm_subnet" "omni" {
  name                 = "omni-subnet"
  resource_group_name  = azurerm_resource_group.omni.name
  virtual_network_name = azurerm_virtual_network.omni.name
  address_prefixes     = ["10.0.0.0/24"]
}

resource "azurerm_public_ip" "omni" {
  name                = "accuknox-omni"
  location            = azurerm_resource_group.omni.location
  resource_group_name = azurerm_resource_group.omni.name
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = [var.zone]
}

resource "azurerm_nat_gateway" "omni" {
  count                   = var.enable_public_ip ? 0 : 1
  name                    = "accuknox-omni"
  location                = azurerm_resource_group.omni.location
  resource_group_name     = azurerm_resource_group.omni.name
  sku_name                = "Standard"
  idle_timeout_in_minutes = 10
}

resource "azurerm_nat_gateway_public_ip_association" "omni" {
  count                = var.enable_public_ip ? 0 : 1
  nat_gateway_id       = azurerm_nat_gateway.omni[0].id
  public_ip_address_id = azurerm_public_ip.omni.id
}

resource "azurerm_subnet_nat_gateway_association" "omni" {
  count          = var.enable_public_ip ? 0 : 1
  subnet_id      = azurerm_subnet.omni.id
  nat_gateway_id = azurerm_nat_gateway.omni[0].id
}

resource "azurerm_network_interface" "omni" {
  name                = "accuknox-omni-nic"
  location            = azurerm_resource_group.omni.location
  resource_group_name = azurerm_resource_group.omni.name
  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.omni.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = var.enable_public_ip ? azurerm_public_ip.omni.id : null
  }
}

resource "azurerm_network_security_group" "omni" {
  name                = "omni-subnet-nsg"
  location            = azurerm_resource_group.omni.location
  resource_group_name = azurerm_resource_group.omni.name
  security_rule {
    name                       = "AllowAllOutbound"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "Internet"
  }
  security_rule {
    name                       = "DefaultDenyAllInbound"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  dynamic "security_rule" {
    for_each = var.enable_public_ip ? [1] : []
    content {
      name                       = "AllowSSH"
      priority                   = 100
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "22"
      source_address_prefix      = "*"
      destination_address_prefix = "*"
    }
  }
}

resource "azurerm_subnet_network_security_group_association" "omni" {
  subnet_id                 = azurerm_subnet.omni.id
  network_security_group_id = azurerm_network_security_group.omni.id
}

resource "azurerm_linux_virtual_machine" "omni" {
  name                            = "accuknox-omni"
  resource_group_name             = azurerm_resource_group.omni.name
  location                        = azurerm_resource_group.omni.location
  size                            = "Standard_B2s"
  zone                            = var.zone
  network_interface_ids           = [azurerm_network_interface.omni.id]
  disable_password_authentication = true
  admin_username                  = "ubuntu"
  admin_ssh_key {
    username   = "ubuntu"
    public_key = file(var.public_key_path)
  }
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
  source_image_reference {
    publisher = "canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.omni.id]
  }
  custom_data = base64encode(local.cloud_init_config)
  lifecycle {
    replace_triggered_by = [null_resource.metadata_trigger]
  }
}
