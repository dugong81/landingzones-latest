
locals {
  vcn_flow_log = {
    log_display_name    = "${var.resource_label}-OCI-ELZ-VCN-FLOW-LOG-${var.environment_prefix}-${var.workload_name}"
    log_type            = "SERVICE"
    log_source_category = "all"
    log_source_service  = "flowlogs"
    log_source_type     = "OCISERVICE"
  }

  workload_private_spoke_subnet_web_display_name = var.workload_private_spoke_subnet_web_display_name != "" ? var.workload_private_spoke_subnet_web_display_name : "OCI-ELZ-${var.workload_prefix}-EXP-SPK-SUB-${local.region_key[0]}-WEB"
  workload_private_spoke_subnet_app_display_name = var.workload_private_spoke_subnet_app_display_name != "" ? var.workload_private_spoke_subnet_app_display_name : "OCI-ELZ-${var.workload_prefix}-EXP-SPK-SUB-${local.region_key[0]}-APP"
  workload_private_spoke_subnet_db_display_name  = var.workload_private_spoke_subnet_db_display_name != "" ? var.workload_private_spoke_subnet_db_display_name : "OCI-ELZ-${var.workload_prefix}-EXP-SPK-SUB-${local.region_key[0]}-DB"

  subnets_map = {
    SPK1 : module.workload_expansion_spoke.subnets[local.workload_private_spoke_subnet_web_display_name]
    SPK2 : module.workload_expansion_spoke.subnets[local.workload_private_spoke_subnet_app_display_name]
    SPK3 : module.workload_expansion_spoke.subnets[local.workload_private_spoke_subnet_db_display_name]
  }
}

module "vcn_flow_log" {
  source = "../../modules/service-log"

  service_log_map     = local.subnets_map
  log_display_name    = local.vcn_flow_log.log_display_name
  log_type            = local.vcn_flow_log.log_type
  log_group_id        = var.default_log_group_id
  log_source_category = local.vcn_flow_log.log_source_category
  log_source_service  = local.vcn_flow_log.log_source_service
  log_source_type     = local.vcn_flow_log.log_source_type
}
