locals {
  osms_dynamic_group_newenv = {
    dynamic_group_name        = "${var.resource_label}-OCI-ELZ-environmentprefix-DG"
    dynamic_group_description = "OCI ELZ Dynamic Group - newenvuction"

    general_matching_rule = <<EOT
    Any {
      instance.compartment.id = '${module.newenv_environment.compartment.security.id}',
      instance.compartment.id = '${module.newenv_environment.compartment.network.id}',
      instance.compartment.id = '${module.newenv_environment.compartment.logging.id}'
    }
    EOT
  }
}

module "osms_dynamic_group_newenv" {
  source        = "../../modules/dynamic-group"
  tenancy_ocid  = var.tenancy_ocid
  description   = local.osms_dynamic_group_newenv.dynamic_group_description
  name          = local.osms_dynamic_group_newenv.dynamic_group_name
  matching_rule = local.osms_dynamic_group_newenv.general_matching_rule

  depends_on = [module.newenv_environment, module.home_compartment]
}
