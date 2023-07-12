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

variable "environment_prefix" {
  type        = string
  description = "the 1 character string representing the environment eg. P (prod), N (non-prod), D, T, U"
}

variable "resource_label" {
  type        = string
  description = "A prefix used to avoid naming conflicts if multiple Landing Zones are deployed."
}

# variable "home_compartment_id" {
#   type        = string
#   description = "the OCID of the compartment where the environment will be created. In general, this should be the Landing zone parent compartment."
# }

# -----------------------------------------------------------------------------
# Compartment Variables
# -----------------------------------------------------------------------------
variable "enable_compartment_delete" {
  type        = bool
  description = "Set to true to allow the compartments to delete on terraform destroy."
  default     = true
}

variable "environment_compartment_id" {
  type        = string
  description = "the OCID of the compartment where the environment will be created. In general, this should be the Landing zone parent compartment."
}

variable "security_compartment_id" {
  type        = string
  description = "the OCID of the compartment where the environment will be created. In general, this should be the Landing zone parent compartment."
}

variable "network_compartment_id" {
  type        = string
  description = "the OCID of the compartment where the environment will be created. In general, this should be the Landing zone parent compartment."
}

variable "workload_name" {
  type        = string
  description = "The name of the workload."
  default     = "W"
}

variable "workload_compartment_name" {
  type        = string
  description = "The name of the workload compartment by default OCI-ELZ-<Workload Name>-<Region>."
  default     = ""
}

# -----------------------------------------------------------------------------
# Monitoring Variables
# -----------------------------------------------------------------------------
variable "workload_topic_endpoints" {
  type        = list(string)
  default     = []
  description = "List of email addresses for Workload notifications."
  validation {
    condition = length(
      [for e in var.workload_topic_endpoints :
      e if length(regexall("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", e)) > 0]
    ) == length(var.workload_topic_endpoints)
    error_message = "Validation failed: invalid email address."
  }
}

variable "network_topic_endpoints" {
  type        = list(string)
  default     = []
  description = "List of email addresses for Network Warning and Critical notifications."
  validation {
    condition = length(
      [for e in var.network_topic_endpoints :
      e if length(regexall("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", e)) > 0]
    ) == length(var.network_topic_endpoints)
    error_message = "Validation failed: invalid email address."
  }
}

variable "secops_topic_endpoints" {
  type        = list(string)
  default     = []
  description = "List of email addresses for Secops Warning and Critical notifications."
  validation {
    condition = length(
      [for e in var.secops_topic_endpoints :
      e if length(regexall("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", e)) > 0]
    ) == length(var.secops_topic_endpoints)
    error_message = "Validation failed: invalid email address."
  }
}
variable "is_create_alarms" {
  type        = bool
  description = "Enable Alarms Creation in all Compartment"
  default     = true
}

variable "default_log_group_id" {
  type        = string
  description = "Default Log Group ID"
}

# -----------------------------------------------------------------------------
# Workload Expansion Variables
# -----------------------------------------------------------------------------
variable "customer_onprem_ip_cidr" {
  type    = list(string)
  default = []
}
variable "enable_vpn_on_environment" {
  type    = bool
  default = false
}
variable "enable_vpn_or_fastconnect" {
  type    = string
  default = "NONE"
}
variable "ipsec_connection_static_routes" {
  type    = list(string)
  default = [""]
}

variable "enable_workload_monitoring_alarms" {
  type        = bool
  description = "Enable Workload Monitoring Alarms in Workload Compartment"
  default     = false
  validation {
    condition     = can(regex("^([t][r][u][e]|[f][a][l][s][e])$", var.enable_workload_monitoring_alarms))
    error_message = "The enable_workload_monitoring_alarms variable must be either true or false."
  }
}

# -----------------------------------------------------------------------------
# Identity Variables
# -----------------------------------------------------------------------------
variable "security_compartment_name" {
  type        = string
  description = "Security Compartment Name."
  default     = ""
}

variable "environment_compartment_name" {
  type        = string
  description = "the name of the compartment where the environment was created."
  default     = ""
}

# variable "identity_domain_id" {
#   type        = string
#   description = "the ocid of identity domain"
#   default     = "ocid1.domain."
#   validation {
#     condition     = can(regex("^domain$", split(".", var.identity_domain_id)[1]))
#     error_message = "Only Domain are OCID is allowed."
#   }
# }

variable "identity_domain_name" {
  type        = string
  description = "identity domain name"
  default     = ""
}

variable "identity_domain_url" {
  type        = string
  description = "identity domain url"
}

variable "workload_admin_group_name" {
  type        = string
  description = "the name of workload admin group"
  default     = ""
}

variable "application_admin_group_name" {
  type        = string
  description = "the name of workload application admin group"
  default     = ""
}

variable "database_admin_group_name" {
  type        = string
  description = "the name of workload database admin group"
  default     = ""
}

variable "network_admin_group_name" {
  type        = string
  description = "the name of landing zone Network admin group"
  default     = ""
}
# variable "security_admin_group_name" {
#   type        = string
#   description = "the name of landing zone Security admin group"
#   default     = ""
# }
variable "prod_workload_admin_group_name" {
  type        = string
  default     = ""
  description = "The group name for the OCI Workload Administrators Group. Defaults to OCI-ELZ-UGP-P-WRK-ADMIN if blank or not provided."
}
variable "prod_application_admin_group_name" {
  type        = string
  default     = ""
  description = "The group name for the OCI Application Administrators Group. Defaults to OCI-ELZ-UGP-P-APP-ADMIN if blank or not provided."
}
variable "prod_database_admin_group_name" {
  type        = string
  default     = ""
  description = "The group name for the OCI Database Logging Administrators Group. Defaults to OCI-ELZ-UGP-P-DB-ADMIN if blank or not provided."
}

variable "enable_bastion" {
  type        = bool
  description = "Option to enable bastion service"
}

variable "bastion_client_cidr_block_allow_list" {
  type        = list(string)
  description = "A list of address ranges in CIDR notation that you want to allow to connect to sessions hosted by this bastion."
}

variable "enable_datasafe" {
  type        = bool
  description = "Enable DataSafe related IAM Group and Policies"
  default     = false
}

variable "datasafe_admin_group_name" {
  type        = string
  description = "the name of datasafe admin group"
  default     = ""
}

variable "datasafe_reports_group_name" {
  type        = string
  description = "the name of datasafe reports group"
  default     = ""
}

# -----------------------------------------------------------------------------
# Network Variables
# -----------------------------------------------------------------------------
variable "hub_vcn_id" {
  description = "OCID of Hub VCN."
  type        = string
}

variable "workload_private_spoke_subnet_web_cidr_block" {
  type        = string
  description = "Workload Enivornment Spoke VCN CIDR Block."
  validation {
    condition     = can(cidrhost(var.workload_private_spoke_subnet_web_cidr_block, 0))
    error_message = "Must be valid IPv4 CIDR."
  }
}

variable "workload_private_spoke_subnet_app_cidr_block" {
  type        = string
  description = "Workload Enivornment Spoke VCN CIDR Block."
  validation {
    condition     = can(cidrhost(var.workload_private_spoke_subnet_app_cidr_block, 0))
    error_message = "Must be valid IPv4 CIDR."
  }
}

variable "workload_private_spoke_subnet_db_cidr_block" {
  type        = string
  description = "Workload Enivornment Spoke VCN CIDR Block."
  validation {
    condition     = can(cidrhost(var.workload_private_spoke_subnet_db_cidr_block, 0))
    error_message = "Must be valid IPv4 CIDR."
  }
}

variable "workload_spoke_vcn_cidr" {
  description = "IPv4 CIDR blocks the VCN will use."
  type        = string
}

variable "enable_nat_gateway_spoke" {
  type    = bool
  default = false
  validation {
    condition     = can(regex("^([t][r][u][e]|[f][a][l][s][e])$", var.enable_nat_gateway_spoke))
    error_message = "The variable must be either true or false."
  }
}

variable "enable_service_gateway_spoke" {
  type    = bool
  default = false
  validation {
    condition     = can(regex("^([t][r][u][e]|[f][a][l][s][e])$", var.enable_service_gateway_spoke))
    error_message = "The variable must be either true or false."
  }
}

variable "vcn_dns_label" {
  description = "A DNS label for the VCN, used in conjunction with the VNIC's hostname and subnet's DNS label to form a fully qualified domain name (FQDN) for each VNIC within this subnet"
  type        = string
  default     = "spokelabel"
  validation {
    condition     = length(var.vcn_dns_label) < 16
    error_message = "DNS Label : Max 15 alphanumeric characters allowed."
  }
}

variable "enable_internet_gateway_spoke" {
  type    = bool
  default = false
  validation {
    condition     = can(regex("^([t][r][u][e]|[f][a][l][s][e])$", var.enable_internet_gateway_spoke))
    error_message = "The enable_internet_gateway_spoke variable must be either true or false."
  }
}


variable "workload_private_spoke_subnet_web_dns_label" {
  description = "A DNS label for the VCN Subnet, used in conjunction with the VNIC's hostname and subnet's DNS label to form a fully qualified domain name (FQDN) for each VNIC within this subnet"
  type        = string
  default     = "webdnslabel"
  validation {
    condition     = length(var.workload_private_spoke_subnet_web_dns_label) < 16
    error_message = "DNS Label : Max 15 alphanumeric characters allowed."
  }
}

variable "workload_private_spoke_subnet_app_dns_label" {
  description = "A DNS label for the VCN Subnet, used in conjunction with the VNIC's hostname and subnet's DNS label to form a fully qualified domain name (FQDN) for each VNIC within this subnet"
  type        = string
  default     = "appdnslabel"
  validation {
    condition     = length(var.workload_private_spoke_subnet_app_dns_label) < 16
    error_message = "DNS Label : Max 15 alphanumeric characters allowed."
  }
}

variable "workload_private_spoke_subnet_db_dns_label" {
  description = "A DNS label for the VCN Subnet, used in conjunction with the VNIC's hostname and subnet's DNS label to form a fully qualified domain name (FQDN) for each VNIC within this subnet"
  type        = string
  default     = "dbdnslabel"
  validation {
    condition     = length(var.workload_private_spoke_subnet_db_dns_label) < 16
    error_message = "DNS Label : Max 15 alphanumeric characters allowed."
  }
}

variable "nat_gateway_display_name" {
  description = "(Updatable) Name of NAT Gateway. Does not have to be unique."
  type        = string
  default     = "ngw"
}

variable "service_gateway_display_name" {
  description = "(Updatable) Name of Service Gateway. Does not have to be unique."
  type        = string
  default     = "sgw"
}

variable "nat_gw_spoke_check" {
  type    = list(string)
  default = [""]
}

variable "service_gw_spoke_check" {
  type    = list(string)
  default = [""]
}

variable "workload_prefix" {
  type        = string
  description = "Atleast 4 Alphanumeric Charater to Describe the Workload : WRK1"
  default     = "WRK1"
}

variable "vcn_display_name" {
  type        = string
  description = "Workload Expansion Spoke VCN Display Name"
  default     = ""
}

variable "workload_private_spoke_subnet_web_display_name" {
  type        = string
  description = "Workload Expansion Spoke Web Subnet Display Name."
  default     = ""
}

variable "workload_private_spoke_subnet_app_display_name" {
  type        = string
  description = "Workload Expansion Spoke App Subnet Display Name."
  default     = ""
}

variable "workload_private_spoke_subnet_db_display_name" {
  type        = string
  description = "Workload Expansion Spoke Db Subnet Display Name."
  default     = ""
}

variable "route_table_display_name" {
  type        = string
  description = "Workload Expansion Spoke Route Table Name Disply Name."
  default     = ""
}

variable "security_list_display_name" {
  type        = string
  description = "Workload Expansion Spoke Security List Name Disly Name."
  default     = ""
}

variable "drg_id" {
  type = string
  validation {
    condition     = can(regex("^drg$", split(".", var.drg_id)[1]))
    error_message = "Only Compartment OCID is allowed."
  }
}

variable "hub_public_subnet_cidr_block" {
  type    = string
  default = "10.1.1.0/24"
  validation {
    condition     = can(cidrhost(var.hub_public_subnet_cidr_block, 0))
    error_message = "Must be valid IPv4 CIDR."
  }
}

variable "hub_private_subnet_cidr_block" {
  type    = string
  default = "10.1.2.0/24"
  validation {
    condition     = can(cidrhost(var.hub_private_subnet_cidr_block, 0))
    error_message = "Must be valid IPv4 CIDR."
  }
}
