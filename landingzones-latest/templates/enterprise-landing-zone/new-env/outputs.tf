
output "newenv_environment" {
  value = {
    environment_prefix      = var.newenv_environment_prefix
    compartments            = module.newenv_environment.compartment
    subnets                 = module.newenv_environment.subnets
    hub_vcn_id              = module.newenv_environment.vcn
    hub_vcn_cidr            = module.newenv_environment.hub_vcn_cidr
    hub_public_subnet_cidr  = module.newenv_environment.hub_public_subnet_cidr
    hub_private_subnet_cidr = module.newenv_environment.hub_private_subnet_cidr
    drg_id                  = module.newenv_environment.drg_id
    identity_domain         = module.newenv_environment.identity_domain
    default_log_group_id    = module.newenv_environment.default_log_group_id
  }
}

output "dynamic_group_detail_newenv" {
  value = module.osms_dynamic_group_newenv
}
