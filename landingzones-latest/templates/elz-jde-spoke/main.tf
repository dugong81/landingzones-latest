######################################################################
#     Workload | Workload Expansion Spoke Network Configuration      #
######################################################################
locals {
  workload_nat_gw_spoke_check     = var.enable_nat_gateway_spoke == true ? var.nat_gw_spoke_check : []
  workload_service_gw_spoke_check = var.enable_service_gateway_spoke == true ? var.service_gw_spoke_check : []

  ipsec_connection_static_routes = var.enable_vpn_or_fastconnect == "VPN" && var.enable_vpn_on_environment ? var.ipsec_connection_static_routes : []
  customer_onprem_ip_cidr        = var.enable_vpn_or_fastconnect == "FASTCONNECT" ? var.customer_onprem_ip_cidr : []
  # cidr_subnet_P                  = var.environment_prefix == "P" ? var.workload_private_spoke_subnet_web_cidr_block : ""
  #cidr_subnet_N                  = var.environment_prefix == "N" ? var.workload_private_spoke_subnet_web_cidr_block = { data "oci_core_subnet" "prod_websubnet"
  #                                                                                                                      compartment_id =                                             
  #}

  security_list_display_name_ssh                     = "${var.security_list_display_name}-SSH"
  security_list_display_name_RDP                     = "${var.security_list_display_name}-RDP"
  security_list_display_name_dbapp                   = "${var.security_list_display_name}-dbapp"
  security_list_display_name_dbweb                   = "${var.security_list_display_name}-dbweb"
  security_list_display_name_jdeapp                  = "${var.security_list_display_name}-jdeapp"
  security_list_display_name_jdeweb                  = "${var.security_list_display_name}-jdeweb"
  security_list_display_name_oneclickport            = "${var.security_list_display_name}-oneclickport"
  security_list_display_name_smport                  = "${var.security_list_display_name}-smport"
  security_list_display_name_oneclick_jmx            = "${var.security_list_display_name}-oneclick_jmx"
  security_list_display_name_oneclick_validationport = "${var.security_list_display_name}-oneclick_validationport"
  security_list_display_name_oneclick_winrm          = "${var.security_list_display_name}-oneclick_winrm"

  spoke_route_rules_options = {
    route_rules_default = {
      "spoke-public-subnet" = {
        network_entity_id = var.drg_id
        destination       = var.hub_public_subnet_cidr_block
        destination_type  = "CIDR_BLOCK"
      }
      "spoke-private-subnet" = {
        network_entity_id = var.drg_id
        destination       = var.hub_private_subnet_cidr_block
        destination_type  = "CIDR_BLOCK"
      }
      "spoke-route-target" = {
        network_entity_id = var.drg_id
        destination       = var.workload_spoke_vcn_cidr
        destination_type  = "CIDR_BLOCK"
      }
    }
    route_rules_nat_spoke = {
      for index, route in local.workload_nat_gw_spoke_check : "nat-gw-rule-${index}" => {
        network_entity_id = module.workload-spoke-nat-gateway[0].nat_gw_id
        destination       = "0.0.0.0/0"
        destination_type  = "CIDR_BLOCK"
      }
    }
    route_rules_srvc_gw_spoke = {
      for index, route in local.workload_service_gw_spoke_check : "service-gw-rule-${index}" => {
        network_entity_id = module.workload-spoke-service-gateway[0].service_gw_id
        destination       = data.oci_core_services.service_gateway.services[0]["cidr_block"]
        destination_type  = "SERVICE_CIDR_BLOCK"

      }
    }
    route_rules_vpn = {
      for index, route in local.ipsec_connection_static_routes : "cpe-rule-${index}" => {
        network_entity_id = var.drg_id
        destination       = route
        destination_type  = "CIDR_BLOCK"
      }
    }
    route_rules_fastconnect = {
      for index, route in local.customer_onprem_ip_cidr : "fc-rule-${index}" => {
        network_entity_id = var.drg_id
        destination       = route
        destination_type  = "CIDR_BLOCK"
      }
    }
  }
  spoke_route_rules = {
    route_rules = merge(local.spoke_route_rules_options.route_rules_default, local.spoke_route_rules_options.route_rules_nat_spoke, local.spoke_route_rules_options.route_rules_srvc_gw_spoke, local.spoke_route_rules_options.route_rules_fastconnect, local.spoke_route_rules_options.route_rules_vpn)
  }
  workload_expansion_subnet_map = {
    Workload-Spoke-Web-Subnet = {
      name                       = var.workload_private_spoke_subnet_web_display_name
      description                = "Web Subnet"
      dns_label                  = var.workload_private_spoke_subnet_web_dns_label
      cidr_block                 = var.workload_private_spoke_subnet_web_cidr_block
      prohibit_public_ip_on_vnic = true
    }
    Workload-Spoke-App-Subnet = {
      name                       = var.workload_private_spoke_subnet_app_display_name
      description                = "App Subnet"
      dns_label                  = var.workload_private_spoke_subnet_app_dns_label
      cidr_block                 = var.workload_private_spoke_subnet_app_cidr_block
      prohibit_public_ip_on_vnic = true
    }
    Workload-Spoke-Db-Subnet = {
      name                       = var.workload_private_spoke_subnet_db_display_name
      description                = "DB Subnet"
      dns_label                  = var.workload_private_spoke_subnet_db_dns_label
      cidr_block                 = var.workload_private_spoke_subnet_db_cidr_block
      prohibit_public_ip_on_vnic = true
    }
  }
  ip_protocols = {
    ICMP   = "1"
    TCP    = "6"
    UDP    = "17"
    ICMPv6 = "58"
  }

  security_list_egress = {
    egress_destination      = "0.0.0.0/0"
    egress_protocol         = "all"
    egress_description      = "All Traffic For All Port"
    egress_destination_type = "CIDR_BLOCK"
  }

  security_list_ingress = {
    ingress_protocol    = local.ip_protocols.ICMP
    ingress_source      = "0.0.0.0/0"
    ingress_description = "All ICMP Taffic"
    ingress_source_type = "CIDR_BLOCK"
    icmp_type           = 3
    icmp_code           = 4
  }
  security_list_ingress_ssh = {
    ingress_protocol             = local.ip_protocols.TCP
    ingress_source               = "0.0.0.0/0"
    ingress_description          = "SSH Traffic"
    ingress_source_type          = "CIDR_BLOCK"
    ingress_destination_port_min = 22
    ingress_destination_port_max = 22
  }

  security_list_ingress_RDP = {
    ingress_protocol             = local.ip_protocols.TCP
    ingress_source               = "0.0.0.0/0"
    ingress_description          = "SSH Traffic"
    ingress_source_type          = "CIDR_BLOCK"
    ingress_destination_port_min = 3389
    ingress_destination_port_max = 3389
  }

  security_list_ingress_dbapp = {
    ingress_protocol             = local.ip_protocols.TCP
    ingress_source               = var.workload_private_spoke_subnet_app_cidr_block
    ingress_description          = "App Subnet Traffic To DB Port"
    ingress_source_type          = "CIDR_BLOCK"
    ingress_destination_port_min = 1521
    ingress_destination_port_max = 1521
  }
  security_list_ingress_dbweb = {
    ingress_protocol             = local.ip_protocols.TCP
    ingress_source               = var.workload_private_spoke_subnet_web_cidr_block
    ingress_description          = "Web Subnet Traffic To DB Port"
    ingress_source_type          = "CIDR_BLOCK"
    ingress_destination_port_min = 1521
    ingress_destination_port_max = 1521
  }
  security_list_ingress_jdeapp = {
    ingress_protocol             = local.ip_protocols.TCP
    ingress_source               = var.workload_private_spoke_subnet_web_cidr_block
    ingress_description          = "web subnet Traffic To ENT Port"
    ingress_source_type          = "CIDR_BLOCK"
    ingress_destination_port_min = 6017
    ingress_destination_port_max = 6027
  }
  security_list_ingress_jdeweb = {
    ingress_protocol             = local.ip_protocols.TCP
    ingress_source               = var.hub_private_subnet_cidr_block
    ingress_description          = "Web Access to onprem"
    ingress_source_type          = "CIDR_BLOCK"
    ingress_destination_port_min = 8000
    ingress_destination_port_max = 8010
  }

  security_list_ingress_oneclickport = {
    ingress_protocol             = local.ip_protocols.TCP
    ingress_source               = var.hub_private_subnet_cidr_block
    ingress_description          = "One Click access to onprem"
    ingress_source_type          = "CIDR_BLOCK"
    ingress_destination_port_min = 3000
    ingress_destination_port_max = 3000
  }

  security_list_ingress_smport = {
    ingress_protocol             = local.ip_protocols.TCP
    ingress_source               = var.hub_private_subnet_cidr_block
    ingress_description          = "SM Console Access to onprem"
    ingress_source_type          = "CIDR_BLOCK"
    ingress_destination_port_min = 8998
    ingress_destination_port_max = 8998
  }
  security_list_ingress_oneclick_jmx = {
    ingress_protocol             = local.ip_protocols.TCP
    ingress_source               = var.workload_private_spoke_subnet_web_cidr_block
    ingress_description          = "Access to JMX ports "
    ingress_source_type          = "CIDR_BLOCK"
    ingress_destination_port_min = 14501
    ingress_destination_port_max = 14520
  }
  security_list_ingress_oneclick_validationport = {
    ingress_protocol             = local.ip_protocols.TCP
    ingress_source               = var.workload_private_spoke_subnet_web_cidr_block
    ingress_description          = "Access to validation port"
    ingress_source_type          = "CIDR_BLOCK"
    ingress_destination_port_min = 5150
    ingress_destination_port_max = 5150
  }

  security_list_ingress_oneclick_winrm = {
    ingress_protocol             = local.ip_protocols.TCP
    ingress_source               = var.workload_private_spoke_subnet_web_cidr_block
    ingress_description          = "Access to validation port"
    ingress_source_type          = "CIDR_BLOCK"
    ingress_destination_port_min = 5985
    ingress_destination_port_max = 5985
  }
}

#Get Service Gateway For Region .
data "oci_core_services" "service_gateway" {
  filter {
    name   = "name"
    values = [".*Object.*Storage"]
    regex  = true
  }
}

######################################################################
#                  Create Workload VCN Spoke                         #
######################################################################
module "workload_spoke_vcn" {
  source = "../../modules/vcn"

  vcn_cidrs           = [var.workload_spoke_vcn_cidr]
  compartment_ocid_id = var.workload_compartment_id
  vcn_display_name    = var.vcn_display_name
  vcn_dns_label       = var.vcn_dns_label
  enable_ipv6         = false

  providers = {
    oci = oci.home_region
  }
}
######################################################################
#          Create Workload VCN Spoke Security List                   #
######################################################################

module "workload_spoke_web_security_list" {
  source = "../../modules/security-lists"

  compartment_id                   = var.workload_compartment_id
  vcn_id                           = module.workload_spoke_vcn.vcn_id
  spoke_security_list_display_name = var.security_list_display_name
  egress_rules                     = [local.security_list_egress]
  ingress_rules                    = [local.security_list_ingress, local.security_list_ingress_ssh, local.security_list_ingress_jdeweb, local.security_list_ingress_oneclick_jmx, local.security_list_ingress_oneclick_validationport, local.security_list_ingress_oneclick_winrm]
}
module "workload_spoke_app_security_list" {
  source = "../../modules/security-lists"

  compartment_id                   = var.workload_compartment_id
  vcn_id                           = module.workload_spoke_vcn.vcn_id
  spoke_security_list_display_name = var.security_list_display_name
  egress_rules                     = [local.security_list_egress]
  ingress_rules                    = [local.security_list_ingress, local.security_list_ingress_ssh, local.security_list_ingress_RDP, local.security_list_ingress_jdeapp, local.security_list_ingress_oneclickport, local.security_list_ingress_smport, local.security_list_ingress_oneclick_jmx, local.security_list_ingress_oneclick_validationport, local.security_list_ingress_oneclick_winrm]
}
module "workload_spoke_db_security_list" {
  source = "../../modules/security-lists"

  compartment_id                   = var.workload_compartment_id
  vcn_id                           = module.workload_spoke_vcn.vcn_id
  spoke_security_list_display_name = var.security_list_display_name
  egress_rules                     = [local.security_list_egress]
  ingress_rules                    = [local.security_list_ingress, local.security_list_ingress_ssh, local.security_list_ingress_dbapp, local.security_list_ingress_dbweb, local.security_list_ingress_oneclick_jmx, local.security_list_ingress_oneclick_validationport, local.security_list_ingress_oneclick_winrm]
}

######################################################################
#          Create Workload VCN Spoke Subnet                          #
######################################################################
module "workload_spoke_web_subnet" {
  source                = "../../modules/subnet"
  subnet_map            = { Workload-Spoke-Web-Subnet = local.workload_expansion_subnet_map.Workload-Spoke-Web-Subnet }
  compartment_id        = var.workload_compartment_id
  vcn_id                = module.workload_spoke_vcn.vcn_id
  subnet_route_table_id = module.workload_spoke_route_table.route_table_id
  subnet_security_list_id = toset([
    module.workload_spoke_web_security_list.security_list_id
  ])
}
module "workload_spoke_app_subnet" {
  source                = "../../modules/subnet"
  subnet_map            = { Workload-Spoke-App-Subnet = local.workload_expansion_subnet_map.Workload-Spoke-App-Subnet }
  compartment_id        = var.workload_compartment_id
  vcn_id                = module.workload_spoke_vcn.vcn_id
  subnet_route_table_id = module.workload_spoke_route_table.route_table_id
  subnet_security_list_id = toset([
    module.workload_spoke_app_security_list.security_list_id
  ])
}
module "workload_spoke_db_subnet" {
  source                = "../../modules/subnet"
  subnet_map            = { Workload-Spoke-Db-Subnet = local.workload_expansion_subnet_map.Workload-Spoke-Db-Subnet }
  compartment_id        = var.workload_compartment_id
  vcn_id                = module.workload_spoke_vcn.vcn_id
  subnet_route_table_id = module.workload_spoke_route_table.route_table_id
  subnet_security_list_id = toset([
    module.workload_spoke_db_security_list.security_list_id
  ])
}
######################################################################
#          Create Workload VCN Spoke Gateway                         #
######################################################################
module "workload-spoke-nat-gateway" {
  source                   = "../../modules/nat-gateway"
  count                    = var.enable_nat_gateway_spoke ? 1 : 0
  nat_gateway_display_name = var.nat_gateway_display_name
  network_compartment_id   = var.workload_compartment_id
  vcn_id                   = module.workload_spoke_vcn.vcn_id
}

module "workload-spoke-service-gateway" {
  source                       = "../../modules/service-gateway"
  count                        = var.enable_service_gateway_spoke ? 1 : 0
  network_compartment_id       = var.workload_compartment_id
  service_gateway_display_name = var.service_gateway_display_name
  vcn_id                       = module.workload_spoke_vcn.vcn_id
}
######################################################################
#          Create Workload VCN Spoke Route Table                     #
######################################################################
module "workload_spoke_route_table" {
  source                   = "../../modules/route-table"
  compartment_id           = var.workload_compartment_id
  vcn_id                   = module.workload_spoke_vcn.vcn_id
  route_table_display_name = var.route_table_display_name
  route_rules              = local.spoke_route_rules.route_rules
}
######################################################################
#          Attach Workload Spoke VCN to DRG                          #
######################################################################
module "workload_spoke_vcn_drg_attachment" {
  source                        = "../../modules/drg-attachment"
  drg_id                        = var.drg_id
  vcn_id                        = module.workload_spoke_vcn.vcn_id
  drg_attachment_type           = "VCN"
  drg_attachment_vcn_route_type = "VCN_CIDRS"
}
