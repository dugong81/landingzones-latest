# -----------------------------------------------------------------------------
# IAM Variables
# -----------------------------------------------------------------------------
variable "prod_domain_admin_email" {
  type        = string
  description = "The email address for the prod identity domain admin."
}

variable "prod_environment_prefix" {
  type        = string
  default     = "P"
  description = "Environment Prefix - P for prod, N for Nonprod etc."
}

variable "prod_network_admin_group_name" {
  type        = string
  default     = ""
  description = "The group name for the OCI Landing Zone Network Administrators Group. Defaults to OCI-ELZ-UGP-P-NET-ADMIN if blank or not provided."
}

variable "prod_security_admin_group_name" {
  type        = string
  default     = ""
  description = "The group name for the OCI Landing Zone Security Administrators Group. Defaults to OCI-ELZ-UGP-P-SEC-ADMIN if blank or not provided."
}

variable "prod_iam_admin_group_name" {
  type        = string
  default     = ""
  description = "The group name for the OCI Landing Zone IAM Administrators Group. Defaults to OCI-ELZ-UGP-P-IDP-ADMIN if blank or not provided."
}

variable "prod_platform_admin_group_name" {
  type        = string
  default     = ""
  description = "The group name for the OCI Landing Zone Platform Administrators Group. Defaults to OCI-ELZ-UGP-P-PLT-ADMIN if blank or not provided."
}

variable "prod_ops_admin_group_name" {
  type        = string
  default     = ""
  description = "The group name for the OCI Landing Zone Ops Administrators Group. Defaults to OCI-ELZ-UGP-P-OPS-ADMIN if blank or not provided."
}

variable "prod_enable_shared_tools" {
  type        = bool
  description = "Set to true to enable a management tools compartment which hosts few of the tools that are used to manage workloads across the environments."
  default     = false
}

# -----------------------------------------------------------------------------
# Security Variables
# -----------------------------------------------------------------------------
# variable "prod_bastion_client_cidr_block_allow_list" {
#   type        = list(string)
#   description = "A list of address ranges in CIDR notation that you want to allow to connect to sessions hosted by this bastion."
# }

# variable "prod_enable_bastion" {
#   type        = bool
#   description = "Option to enable bastion service"
# }

variable "prod_vault_type" {
  type        = string
  description = "The type of vault to create. "
  default     = "DEFAULT"
}

variable "prod_vault_replica_region" {
  type        = string
  description = "the region to be created replica to. Required *if* prod_enable_vault_replication is true."
  default     = ""
}

variable "prod_enable_vault_replication" {
  type        = bool
  description = "Option to enable vault replication"
  default     = false
}

variable "prod_create_master_encryption_key" {
  type        = bool
  description = "Option create master encryption key"
  default     = true
}

# -----------------------------------------------------------------------------
# Budget Variables
# -----------------------------------------------------------------------------
variable "prod_enable_budget" {
  type        = bool
  default     = false
  description = "production Enable Budget."
}

variable "prod_budget_amount" {
  description = "The amount of the budget expressed as a whole number in the currency of the customer's rate card. Required *if* prod_enable_budget is true."
  type        = string
  default     = ""
}

variable "prod_budget_alert_rule_threshold" {
  description = "The threshold for the budget alert. Required *if* prod_enable_budget is true."
  type        = string
  default     = ""
}

variable "prod_budget_alert_rule_message" {
  description = "The alert message for budget alerts. Required *if* prod_enable_budget is true."
  type        = string
  default     = ""
}

variable "prod_budget_alert_rule_recipients" {
  description = "The delimited list of email addresses to receive the alert when it triggers. Delimiter characters can be a comma, space, TAB, or semicolon. Required *if* prod_enable_budget is true."
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# Network Variables
# -----------------------------------------------------------------------------
variable "prod_enable_internet_gateway_hub" {
  type        = string
  description = "Option to enable TRUE and Disable false."
  default     = "false"
}

variable "prod_enable_nat_gateway_hub" {
  type        = string
  description = "Option to enable TRUE and Disable false."
  default     = "false"
}

variable "prod_enable_service_gateway_hub" {
  type        = string
  description = "Option to enable TRUE and Disable false."
  default     = "false"
}

variable "prod_igw_hub_check" {
  type    = list(string)
  default = [""]
}

variable "prod_nat_gw_hub_check" {
  type    = list(string)
  default = [""]
}

variable "prod_service_gw_hub_check" {
  type    = list(string)
  default = [""]
}

variable "prod_hub_vcn_cidr_block" {
  type        = string
  description = "production Enivornment HUB VCN CIDR Block."
}

variable "prod_hub_public_subnet_cidr_block" {
  type        = string
  description = "production Enivornment HUB Public Subnet CIDR Block."
}

variable "prod_hub_private_subnet_cidr_block" {
  type        = string
  description = "production Enivornment HUB Private Subnet CIDR Block."
}

# -----------------------------------------------------------------------------
# Tagging Variables
# -----------------------------------------------------------------------------
variable "prod_enable_tagging" {
  type        = bool
  default     = false
  description = "Option to enable Tagging gateway in production environment"
}

variable "prod_cost_center_tagging" {
  type        = string
  description = "production Cost Center."
}

variable "prod_geo_location_tagging" {
  type        = string
  description = "production Geo Center."
}

# -----------------------------------------------------------------------------
# Monitoring Variables
# -----------------------------------------------------------------------------
variable "prod_network_topic_endpoints" {
  type        = list(string)
  default     = []
  description = "List of email addresses for Network Warning and Critical notifications."
  validation {
    condition = length(
      [for e in var.prod_network_topic_endpoints :
      e if length(regexall("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", e)) > 0]
    ) == length(var.prod_network_topic_endpoints)
    error_message = "Validation failed: invalid email address."
  }
}

variable "prod_secops_topic_endpoints" {
  type        = list(string)
  default     = []
  description = "List of email addresses for Secops Warning and Critical notifications."
  validation {
    condition = length(
      [for e in var.prod_secops_topic_endpoints :
      e if length(regexall("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", e)) > 0]
    ) == length(var.prod_secops_topic_endpoints)
    error_message = "Validation failed: invalid email address."
  }
}

variable "prod_platform_topic_endpoints" {
  type        = list(string)
  default     = []
  description = "List of email addresses for Platform notifications."
  validation {
    condition = length(
      [for e in var.prod_platform_topic_endpoints :
      e if length(regexall("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", e)) > 0]
    ) == length(var.prod_platform_topic_endpoints)
    error_message = "Validation failed: invalid email address."
  }
}

variable "prod_identity_topic_endpoints" {
  type        = list(string)
  default     = []
  description = "List of email addresses for Identity notifications."
  validation {
    condition = length(
      [for e in var.prod_identity_topic_endpoints :
      e if length(regexall("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", e)) > 0]
    ) == length(var.prod_identity_topic_endpoints)
    error_message = "Validation failed: invalid email address."
  }
}

variable "prod_enable_security_monitoring_alarms" {
  type        = bool
  default     = false
  description = "Enable Security Monitoring Alarms in production Security Compartment"
}

variable "prod_enable_network_monitoring_alarms" {
  type        = bool
  default     = false
  description = "Enable Network Monitoring Alarms in production Network Compartment"
}

variable "prod_workload_compartment_names" {
  type        = list(string)
  default     = []
  description = "The names of the workload compartments to update policies for the Admin Groups"
}

variable "prod_additional_workload_subnets_cidr_blocks" {
  type        = list(string)
  default     = []
  description = "A list of subnets cidr blocks in additional workload stack in prod"
}
