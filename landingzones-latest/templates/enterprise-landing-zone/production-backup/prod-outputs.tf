
output "prod_environment" {
  value = {
    environment_prefix      = var.prod_environment_prefix
    compartments            = module.prod_environment.compartment
    subnets                 = module.prod_environment.subnets
    hub_vcn_id              = module.prod_environment.vcn
    hub_vcn_cidr            = module.prod_environment.hub_vcn_cidr
    hub_public_subnet_cidr  = module.prod_environment.hub_public_subnet_cidr
    hub_private_subnet_cidr = module.prod_environment.hub_private_subnet_cidr
    drg_id                  = module.prod_environment.drg_id
    identity_domain         = module.prod_environment.identity_domain
    default_log_group_id    = module.prod_environment.default_log_group_id
  }
}

output "dynamic_group_detail_prod" {
  value = module.osms_dynamic_group_prod
}
