
output "workload" {
  value = {
    environment_prefix        = var.environment_prefix
    workload_compartment_name = local.workload_compartment.name
    workload_compartment_id   = module.workload_compartment.compartment_id
    spoke_vcn                 = module.workload_expansion_spoke.spoke_vcn
    subnets                   = module.workload_expansion_spoke.subnets
    bastion_id                = var.enable_bastion ? module.bastion[0].bastion_ocid : null
    workload_web_cidr         = var.workload_private_spoke_subnet_web_cidr_block
    workload_app_cidr         = var.workload_private_spoke_subnet_app_cidr_block
    workload_db_cidr          = var.workload_private_spoke_subnet_db_cidr_block
  }
}
