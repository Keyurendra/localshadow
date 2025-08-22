variable "region" {
  description = "AWS Region"
  type        = string
  default     = "us-east-1"
  validation {
    condition     = can(regex("^[a-z]+-[a-z]+-[0-9]+$", var.region))
    error_message = "Region must be in the format like us-east-1."
  }
}

variable "availability_zone" {
  description = "AWS Availability Zone"
  type        = string
  default     = "us-east-1a"
  validation {
    condition     = can(regex("^[a-z]+-[a-z]+-[0-9]+[a-z]$", var.availability_zone))
    error_message = "zone must be in the format like us-east-1a."
  }
}

variable "instance_type" {
  description = "EC2 Instance Type"
  type        = string
  default     = "t3.medium"
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
