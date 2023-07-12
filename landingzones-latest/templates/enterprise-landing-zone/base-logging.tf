locals {
  service_connector_policy_base = {
    name        = "${var.resource_label}-OCI-ELZ-SC-Policy-Base"
    description = "OCI ELZ Service Connector Base Policy"
    statements = [
      "Allow any-user to read log-content in compartment id ${module.home_compartment.compartment_id} where all {request.principal.type='serviceconnector'}",
      "Allow any-user to read log-groups in compartment id ${module.home_compartment.compartment_id} where all {request.principal.type='serviceconnector'}"
    ]
  }

  archive_log_bucket = {
    name                                = "${var.resource_label}_logs_archive"
  }

  service_connector_archive_policy = {
    name        = "${var.resource_label}-OCI-ELZ-SC-ARC-Policy"
    description = "OCI ELZ Service Connector Policy For Archive"
    statements = [
      "Allow any-user to read log-content in compartment id ${module.home_compartment.compartment_id} where all {request.principal.type='serviceconnector'}",
      "Allow any-user to read log-groups in compartment id ${module.home_compartment.compartment_id} where all {request.principal.type='serviceconnector'}",
      "Allow any-user to {STREAM_READ, STREAM_CONSUME} in compartment id ${module.home_compartment.compartment_id} where all {request.principal.type='serviceconnector'}",
      "Allow any-user to manage objects in compartment id ${module.home_compartment.compartment_id} where all {request.principal.type='serviceconnector', target.bucket.name='${local.archive_log_bucket.name}'}"
    ]
  }

}

module "service_connector_policy" {
  source           = "../../modules/policies"
  compartment_ocid = module.home_compartment.compartment_id
  policy_name      = local.service_connector_policy_base.name
  description      = local.service_connector_policy_base.description
  statements       = local.service_connector_policy_base.statements

  depends_on = [module.home_compartment]
}

module "service_connector_archive_policy" {
  source           = "../../modules/policies"
  compartment_ocid = module.home_compartment.compartment_id
  policy_name      = local.service_connector_archive_policy.name
  description      = local.service_connector_archive_policy.description
  statements       = local.service_connector_archive_policy.statements

  depends_on = [module.home_compartment]
#  depends_on = [module.prod_environment]
}
