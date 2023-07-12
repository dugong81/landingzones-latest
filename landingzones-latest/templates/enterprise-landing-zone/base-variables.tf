# -----------------------------------------------------------------------------
# Common Variables 
# -----------------------------------------------------------------------------
variable "tenancy_ocid" {
  type        = string
  description = "The OCID of tenancy"
}

variable "region" {
  type        = string
  description = "The OCI region"
}

variable "resource_label" {
  type        = string
  default     = ""
  description = "A prefix used to avoid naming conflicts if multiple Landing Zones are deployed."
}

# -----------------------------------------------------------------------------
# Compartment Variables
# -----------------------------------------------------------------------------
variable "home_compartment_name" {
  type        = string
  default     = "OCI-ELZ-CMP-HOME"
  description = "The name of the Landing Zone home compartment."
}

variable "enable_compartment_delete" {
  type        = bool
  description = "Set to true to allow the compartments to delete on terraform destroy."
  default     = true
}

# -----------------------------------------------------------------------------
# Identity Variables
# -----------------------------------------------------------------------------
variable "break_glass_user_email_list" {
  type        = list(string)
  description = "Unique list of break glass user email addresses that do not exist in the tenancy. These users are added to the Administrator group."
  default     = []
  validation {
    condition     = alltrue([for i in var.break_glass_user_email_list : can(regex("^[^\\s@]+@([^\\s@\\.,]+.)+[^\\s@\\.,]{2,}$", i))])
    error_message = "Must be a list of valid email addresses."
  }
}

variable "domain_license_type" {
  type        =  string
  description = "Identity Domain License Type."
  default     = "premium"
}

# -----------------------------------------------------------------------------
# Security Variables
# -----------------------------------------------------------------------------
variable "enable_cloud_guard" {
  type        = bool
  default     = false
  description = "true if you don't have cloud guard enabled, false if you've already have cloud guard enabled."
}

variable "cloud_guard_target_tenancy" {
  type        = bool
  default     = false
  description = "true if cloud guard targets to tenancy, false if cloud guard targets to Landing Zone home compartment"
}

# -----------------------------------------------------------------------------
# Monitoring Variables
# -----------------------------------------------------------------------------
variable "is_create_alarms" {
  type        = bool
  default     = false
  description = "Enable Alarms Creation in all Compartment"
}

variable "is_service_connector_limit" {
  type        = bool
  default     = true
  description = "Restrict Number of Service Connector Deployment in Tenancy if limit is two"
}

variable "onboard_log_analytics" {
  type        = bool
  description = "Set to true to onboard the tenancy to logging analytics. "
  default     = true
}
