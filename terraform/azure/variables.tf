variable "subscription_id" {
  description = "Azure Subscription ID"
  type        = string
}

variable "location" {
  description = "Azure Location"
  type        = string
  default     = "East US"
}
variable "zone" {
  description = "Azure Availability Zone"
  type        = string
  default     = "1"
}
variable "enable_public_ip" {
  description = "Enable public IP"
  type        = bool
  default     = false
}

variable "public_key_path" {
  description = "Path to your SSH public key"
  type        = string
}

variable "vm_size" {
  description = "Azure VM Size"
  type        = string
  default     = "Standard_B2s"
}

variable "artifact_token" {
  description = "AccuKnox Artifact API JWT Token"
  type        = string
  sensitive   = true
  nullable    = false
}

variable "artifact_endpoint" {
  description = "AccuKnox Artifact API Endpoint"
  type        = string
  default     = "https://cspm.accuknox.com/api/v1/artifact/"
  validation {
    condition     = can(regex("^https?://", var.artifact_endpoint))
    error_message = "artifact_endpoint must start with https:// or http://"
  }
}

variable "artifact_label" {
  description = "AccuKnox Artifact Label"
  type        = string
  nullable    = false
}

variable "artifact_tenant_id" {
  description = "AccuKnox Artifact Tenant ID"
  type        = number
  nullable    = false
}

variable "omni_additional_flags" {
  description = "Additional flags for omni service"
  type        = map(string)
  default     = {}
}

variable "enable_telemetry" {
  description = "Enable telemetry"
  type        = bool
  default     = true
}
