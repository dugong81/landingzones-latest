# -----------------------------------------------------------------------------
# IAM Variables
# -----------------------------------------------------------------------------
variable "newenv_domain_admin_email" {
  type        = string
  description = "The email address for the newenv identity domain admin."
}

variable "newenv_environment_prefix" {
  type        = string
  default     = "P"
  description = "Environment Prefix - P for newenv, N for Nonnewenv etc."
}

variable "newenv_network_admin_group_name" {
  type        = string
  default     = ""
  description = "The group name for the OCI Landing Zone Network Administrators Group. Defaults to OCI-ELZ-UGP-P-NET-ADMIN if blank or not provided."
}

variable "newenv_security_admin_group_name" {
  type        = string
  default     = ""
  description = "The group name for the OCI Landing Zone Security Administrators Group. Defaults to OCI-ELZ-UGP-P-SEC-ADMIN if blank or not provided."
}

variable "newenv_iam_admin_group_name" {
  type        = string
  default     = ""
  description = "The group name for the OCI Landing Zone IAM Administrators Group. Defaults to OCI-ELZ-UGP-P-IDP-ADMIN if blank or not provided."
}

variable "newenv_platform_admin_group_name" {
  type        = string
  default     = ""
  description = "The group name for the OCI Landing Zone Platform Administrators Group. Defaults to OCI-ELZ-UGP-P-PLT-ADMIN if blank or not provided."
}

variable "newenv_ops_admin_group_name" {
  type        = string
  default     = ""
  description = "The group name for the OCI Landing Zone Ops Administrators Group. Defaults to OCI-ELZ-UGP-P-OPS-ADMIN if blank or not provided."
}

variable "newenv_enable_shared_tools" {
  type        = bool
  description = "Set to true to enable a management tools compartment which hosts few of the tools that are used to manage workloads across the environments."
  default     = false
}

# -----------------------------------------------------------------------------
# Security Variables
# -----------------------------------------------------------------------------
# variable "newenv_bastion_client_cidr_block_allow_list" {
#   type        = list(string)
#   description = "A list of address ranges in CIDR notation that you want to allow to connect to sessions hosted by this bastion."
# }

# variable "newenv_enable_bastion" {
#   type        = bool
#   description = "Option to enable bastion service"
# }

variable "newenv_vault_type" {
  type        = string
  description = "The type of vault to create. "
  default     = "DEFAULT"
}

variable "newenv_vault_replica_region" {
  type        = string
  description = "the region to be created replica to. Required *if* newenv_enable_vault_replication is true."
  default     = ""
}

variable "newenv_enable_vault_replication" {
  type        = bool
  description = "Option to enable vault replication"
  default     = false
}

variable "newenv_create_master_encryption_key" {
  type        = bool
  description = "Option create master encryption key"
  default     = true
}

# -----------------------------------------------------------------------------
# Budget Variables
# -----------------------------------------------------------------------------
variable "newenv_enable_budget" {
  type        = bool
  default     = false
  description = "newenvuction Enable Budget."
}

variable "newenv_budget_amount" {
  description = "The amount of the budget expressed as a whole number in the currency of the customer's rate card. Required *if* newenv_enable_budget is true."
  type        = string
  default     = ""
}

variable "newenv_budget_alert_rule_threshold" {
  description = "The threshold for the budget alert. Required *if* newenv_enable_budget is true."
  type        = string
  default     = ""
}

variable "newenv_budget_alert_rule_message" {
  description = "The alert message for budget alerts. Required *if* newenv_enable_budget is true."
  type        = string
  default     = ""
}

variable "newenv_budget_alert_rule_recipients" {
  description = "The delimited list of email addresses to receive the alert when it triggers. Delimiter characters can be a comma, space, TAB, or semicolon. Required *if* newenv_enable_budget is true."
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# Network Variables
# -----------------------------------------------------------------------------
variable "newenv_enable_internet_gateway_hub" {
  type        = string
  description = "Option to enable TRUE and Disable false."
  default     = "false"
}

variable "newenv_enable_nat_gateway_hub" {
  type        = string
  description = "Option to enable TRUE and Disable false."
  default     = "false"
}

variable "newenv_enable_service_gateway_hub" {
  type        = string
  description = "Option to enable TRUE and Disable false."
  default     = "false"
}

variable "newenv_igw_hub_check" {
  type    = list(string)
  default = [""]
}

variable "newenv_nat_gw_hub_check" {
  type    = list(string)
  default = [""]
}

variable "newenv_service_gw_hub_check" {
  type    = list(string)
  default = [""]
}

variable "newenv_hub_vcn_cidr_block" {
  type        = string
  description = "newenvuction Enivornment HUB VCN CIDR Block."
}

variable "newenv_hub_public_subnet_cidr_block" {
  type        = string
  description = "newenvuction Enivornment HUB Public Subnet CIDR Block."
}

variable "newenv_hub_private_subnet_cidr_block" {
  type        = string
  description = "newenvuction Enivornment HUB Private Subnet CIDR Block."
}

# -----------------------------------------------------------------------------
# Tagging Variables
# -----------------------------------------------------------------------------
variable "newenv_enable_tagging" {
  type        = bool
  default     = false
  description = "Option to enable Tagging gateway in newenvuction environment"
}

variable "newenv_cost_center_tagging" {
  type        = string
  description = "newenvuction Cost Center."
}

variable "newenv_geo_location_tagging" {
  type        = string
  description = "newenvuction Geo Center."
}

# -----------------------------------------------------------------------------
# Monitoring Variables
# -----------------------------------------------------------------------------
variable "newenv_network_topic_endpoints" {
  type        = list(string)
  default     = []
  description = "List of email addresses for Network Warning and Critical notifications."
  validation {
    condition = length(
      [for e in var.newenv_network_topic_endpoints :
      e if length(regexall("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", e)) > 0]
    ) == length(var.newenv_network_topic_endpoints)
    error_message = "Validation failed: invalid email address."
  }
}

variable "newenv_secops_topic_endpoints" {
  type        = list(string)
  default     = []
  description = "List of email addresses for Secops Warning and Critical notifications."
  validation {
    condition = length(
      [for e in var.newenv_secops_topic_endpoints :
      e if length(regexall("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", e)) > 0]
    ) == length(var.newenv_secops_topic_endpoints)
    error_message = "Validation failed: invalid email address."
  }
}

variable "newenv_platform_topic_endpoints" {
  type        = list(string)
  default     = []
  description = "List of email addresses for Platform notifications."
  validation {
    condition = length(
      [for e in var.newenv_platform_topic_endpoints :
      e if length(regexall("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", e)) > 0]
    ) == length(var.newenv_platform_topic_endpoints)
    error_message = "Validation failed: invalid email address."
  }
}

variable "newenv_identity_topic_endpoints" {
  type        = list(string)
  default     = []
  description = "List of email addresses for Identity notifications."
  validation {
    condition = length(
      [for e in var.newenv_identity_topic_endpoints :
      e if length(regexall("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", e)) > 0]
    ) == length(var.newenv_identity_topic_endpoints)
    error_message = "Validation failed: invalid email address."
  }
}

variable "newenv_enable_security_monitoring_alarms" {
  type        = bool
  default     = false
  description = "Enable Security Monitoring Alarms in newenvuction Security Compartment"
}

variable "newenv_enable_network_monitoring_alarms" {
  type        = bool
  default     = false
  description = "Enable Network Monitoring Alarms in newenvuction Network Compartment"
}

variable "newenv_workload_compartment_names" {
  type        = list(string)
  default     = []
  description = "The names of the workload compartments to update policies for the Admin Groups"
}

variable "newenv_additional_workload_subnets_cidr_blocks" {
  type        = list(string)
  default     = []
  description = "A list of subnets cidr blocks in additional workload stack in newenv"
}
