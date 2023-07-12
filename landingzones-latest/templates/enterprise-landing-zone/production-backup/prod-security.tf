locals {
  osms_dynamic_group_prod = {
    dynamic_group_name        = "${var.resource_label}-OCI-ELZ-P-DG"
    dynamic_group_description = "OCI ELZ Dynamic Group - Production"

    general_matching_rule = <<EOT
    Any {
      instance.compartment.id = '${module.prod_environment.compartment.security.id}',
      instance.compartment.id = '${module.prod_environment.compartment.network.id}',
      instance.compartment.id = '${module.prod_environment.compartment.logging.id}'
    }
    EOT
  }
}

module "osms_dynamic_group_prod" {
  source        = "../../modules/dynamic-group"
  tenancy_ocid  = var.tenancy_ocid
  description   = local.osms_dynamic_group_prod.dynamic_group_description
  name          = local.osms_dynamic_group_prod.dynamic_group_name
  matching_rule = local.osms_dynamic_group_prod.general_matching_rule

  depends_on = [module.prod_environment, module.home_compartment]
}