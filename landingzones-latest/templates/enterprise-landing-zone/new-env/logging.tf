locals {
  newenv_service_connector_policy = {
    name        = "${var.resource_label}-OCI-ELZ-environmentprefix-SC-Policy"
    description = "OCI ELZ Service Connector Policy - newenv"
    statements = [
      "Allow any-user to {STREAM_READ, STREAM_CONSUME} in compartment id ${module.newenv_environment.compartment.security.id} where all {request.principal.type='serviceconnector', target.stream.id='${module.newenv_environment.stream_id}', request.principal.compartment.id='${module.newenv_environment.compartment.security.id}'}",
      "Allow any-user to manage objects in compartment id ${module.newenv_environment.compartment.logging.id} where all {request.principal.type='serviceconnector', target.bucket.name='*_standard', request.principal.compartment.id='${module.newenv_environment.compartment.security.id}'}",
      "Allow any-user to manage objects in compartment id ${module.newenv_environment.compartment.logging.id} where all {request.principal.type='serviceconnector', any{target.bucket.name='${var.resource_label}_${var.newenv_environment_prefix}_auditLogs_standard', target.bucket.name='${var.resource_label}_${var.newenv_environment_prefix}_defaultLogs_standard', target.bucket.name='${var.resource_label}_${var.newenv_environment_prefix}_serviceEvents_standard'}, request.principal.compartment.id='${module.newenv_environment.compartment.security.id}'}",
    ]
  }

  newenv_archive_log_bucket = {
    name                                = "${var.resource_label}_environmentprefix_logs_archive"
    description                         = "Archive Log bucket"
    retention_rule_display_name         = "archive log bucket retention rule"
    retention_policy_duration_amount    = var.archive_log_retention_policy_duration_amount
    retention_policy_duration_time_unit = var.archive_log_retention_policy_duration_time_unit
    bucket_storage_tier                 = "Archive"
  }

  newenv_key_archive_policy = {
    name        = "${var.resource_label}-OCI-ELZ-environmentprefix-KEY-ARC-Policy"
    description = "OCI Enterprise Landing Zone Key Policy For Archive - newenv"

    statements = [
      "Allow service objectstorage-${var.region} to use keys in compartment id ${module.newenv_environment.compartment.security.id}",
      "Allow service blockstorage,FssOc1Prod, OKE, streaming to use keys in compartment id ${module.newenv_environment.compartment.security.id}"
    ]
  }

  newenv_archive_audit_log_service_connector = {
    display_name  = "${var.resource_label}_schAuditLog_archive_${var.newenv_environment_prefix}"
    source_kind   = "logging"
    target_kind   = "objectStorage"
    log_group_id  = "_Audit_Include_Subcompartment"
    target_bucket = module.newenv_archive_bucket.bucket.name
  }

  newenv_archive_default_log_service_connector = {
    display_name  = "${var.resource_label}_schDefaultLog_archive_${var.newenv_environment_prefix}"
    source_kind   = "logging"
    target_kind   = "objectStorage"
    target_bucket = module.newenv_archive_bucket.bucket.name
  }

  newenv_archive_service_events_service_connector = {
    display_name  = "${var.resource_label}_schServiceEvents_archive_${var.newenv_environment_prefix}"
    source_kind   = "streaming"
    target_kind   = "objectStorage"
    target_bucket = module.newenv_archive_bucket.bucket.name
    cursor_kind   = "TRIM_HORIZON"
  }

  newenv_archive_key = {
    name            = "${var.resource_label}-OCI-ELZ-ARC-KEY-${var.newenv_environment_prefix}"
    shape_algorithm = "AES"
    shape_length    = 32
    protection_mode = "SOFTWARE"
  }

  newenv_group_names = {
    newenv_platform_admin_group_name : var.newenv_platform_admin_group_name != "" ? var.newenv_platform_admin_group_name : "OCI-ELZ-UGP-${var.newenv_environment_prefix}-PLT-ADMIN",
  }

  newenv_platform_admin_policy = {
    name        = "OCI-ELZ-UGP-${var.newenv_environment_prefix}-PLT-ADMIN-POLICY-ARCHIVE"
    description = "OCI Landing Zone Platform Admin Group Policy To Manage Archive Bucket"

    statements = [
      "Allow group ${local.newenv_group_names["newenv_platform_admin_group_name"]} to manage buckets in compartment ${module.home_compartment.compartment_name}",
      "Allow group ${local.newenv_group_names["newenv_platform_admin_group_name"]} to manage objects in compartment ${module.home_compartment.compartment_name}"
    ]
  }

}

module "newenv_service_connector_policy" {
  source           = "../../modules/policies"
  compartment_ocid = module.home_compartment.compartment_id
  policy_name      = local.newenv_service_connector_policy.name
  description      = local.newenv_service_connector_policy.description
  statements       = local.newenv_service_connector_policy.statements

  depends_on = [module.newenv_environment]
}

module "newenv_archive_key" {
  source              = "../../modules/key"
  compartment_ocid    = module.newenv_environment.compartment.security.id
  display_name        = local.newenv_archive_key.name
  shape_algorithm     = local.newenv_archive_key.shape_algorithm
  shape_length        = local.newenv_archive_key.shape_length
  protection_mode     = local.newenv_archive_key.protection_mode
  management_endpoint = module.newenv_environment.vault_id

  depends_on = [module.newenv_environment]
}

module "newenv_key_archive_policy" {
  source           = "../../modules/policies"
  compartment_ocid = module.home_compartment.compartment_id
  policy_name      = local.newenv_key_archive_policy.name
  description      = local.newenv_key_archive_policy.description
  statements       = local.newenv_key_archive_policy.statements

  depends_on = [module.newenv_environment]
}

module "newenv_archive_bucket" {
  source                              = "../../modules/bucket"
  tenancy_ocid                        = var.tenancy_ocid
  compartment_id                      = module.home_compartment.compartment_id
  name                                = local.newenv_archive_log_bucket.name
  kms_key_id                          = module.newenv_archive_key.key_ocid
  storage_tier                        = local.newenv_archive_log_bucket.bucket_storage_tier
  retention_rule_display_name         = local.newenv_archive_log_bucket.retention_rule_display_name
  retention_policy_duration_amount    = local.newenv_archive_log_bucket.retention_policy_duration_amount
  retention_policy_duration_time_unit = local.newenv_archive_log_bucket.retention_policy_duration_time_unit
  namespace                           = data.oci_objectstorage_namespace.ns.namespace

  depends_on = [module.newenv_environment, module.newenv_archive_key, module.newenv_key_archive_policy]
}

module "newenv_archive_audit_log_service_connector" {
  count = var.is_service_connector_limit ? 0 : 1

  source                = "../../modules/service-connector"
  tenancy_ocid          = var.tenancy_ocid
  compartment_id        = module.newenv_environment.compartment.security.id
  source_compartment_id = module.home_compartment.compartment_id
  display_name          = local.newenv_archive_audit_log_service_connector.display_name
  source_kind           = local.newenv_archive_audit_log_service_connector.source_kind
  target_kind           = local.newenv_archive_audit_log_service_connector.target_kind
  log_group_id          = local.newenv_archive_audit_log_service_connector.log_group_id
  target_bucket         = local.newenv_archive_audit_log_service_connector.target_bucket

  depends_on = [module.newenv_archive_bucket, module.service_connector_archive_policy]
}

module "newenv_archive_default_log_service_connector" {
  count  = var.is_service_connector_limit ? 0 : 1
  source = "../../modules/service-connector"

  tenancy_ocid          = var.tenancy_ocid
  compartment_id        = module.newenv_environment.compartment.security.id
  source_compartment_id = module.newenv_environment.compartment.security.id
  display_name          = local.newenv_archive_default_log_service_connector.display_name
  source_kind           = local.newenv_archive_default_log_service_connector.source_kind
  target_kind           = local.newenv_archive_default_log_service_connector.target_kind
  log_group_id          = module.newenv_environment.default_group_id
  target_bucket         = local.newenv_archive_default_log_service_connector.target_bucket

  depends_on = [module.newenv_archive_bucket, module.service_connector_archive_policy]
}

module "newenv_archive_service_events_service_connector" {
  source                = "../../modules/service-connector"
  tenancy_ocid          = var.tenancy_ocid
  compartment_id        = module.newenv_environment.compartment.security.id
  source_compartment_id = module.newenv_environment.compartment.security.id
  display_name          = local.newenv_archive_service_events_service_connector.display_name
  source_kind           = local.newenv_archive_service_events_service_connector.source_kind
  target_kind           = local.newenv_archive_service_events_service_connector.target_kind
  stream_id             = module.newenv_environment.stream_id
  cursor_kind           = local.newenv_archive_service_events_service_connector.cursor_kind
  target_bucket         = local.newenv_archive_service_events_service_connector.target_bucket

  depends_on = [module.newenv_archive_bucket, module.service_connector_archive_policy]
}

module "newenv_platform_admin_policy" {
  source           = "../../modules/policies"
  compartment_ocid = module.home_compartment.compartment_id
  policy_name      = local.newenv_platform_admin_policy.name
  description      = local.newenv_platform_admin_policy.description
  statements       = local.newenv_platform_admin_policy.statements

  depends_on = [module.home_compartment]
}
