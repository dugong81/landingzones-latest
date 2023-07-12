
output "workload" {
  value = {
    environment_prefix        = var.environment_prefix
    workload_compartment_name = local.workload_compartment.name
    workload_compartment_id   = module.workload_compartment.compartment_id
    spoke_vcn                 = module.exadata_workload_expansion_spoke.spoke_vcn
    subnets                   = module.exadata_workload_expansion_spoke.subnets
    bastion_id                = var.enable_bastion ? module.bastion[0].bastion_ocid : null
    workload_lb_cidr          = var.workload_private_spoke_subnet_lb_cidr_block
    workload_app_cidr         = var.workload_private_spoke_subnet_app_cidr_block
    workload_client_cidr      = var.workload_private_spoke_subnet_client_cidr_block
    workload_backup_cidr      = var.workload_private_spoke_subnet_backup_cidr_block
  }
}
