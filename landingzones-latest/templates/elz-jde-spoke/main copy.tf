/*
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
  security_list_ingress = {
    protocol    = local.ip_protocols.ICMP
    source      = "0.0.0.0/0"
    description = "All ICMP Taffic"
    source_type = "CIDR_BLOCK"
  }
  security_list_ingress_ssh = {
    protocol         = local.ip_protocols.TCP
    source           = "0.0.0.0/0"
    description      = "SSH Traffic"
    source_type      = "CIDR_BLOCK"
    destination_port = 22
  }

  security_list_ingress_RDP = {
    protocol         = local.ip_protocols.TCP
    source           = "0.0.0.0/0"
    description      = "SSH Traffic"
    source_type      = "CIDR_BLOCK"
    destination_port = 3389
  }

  security_list_egress = {
    destination      = "0.0.0.0/0"
    protocol         = "all"
    description      = "All Traffic For All Port"
    destination_type = "CIDR_BLOCK"
  }
  security_list_ingress_dbapp = {
    protocol         = local.ip_protocols.TCP
    source           = var.workload_private_spoke_subnet_app_cidr_block
    description      = "App Subnet Traffic To DB Port"
    source_type      = "CIDR_BLOCK"
    destination_port = 1521
  }
  security_list_ingress_dbweb = {
    protocol         = local.ip_protocols.TCP
    source           = var.workload_private_spoke_subnet_web_cidr_block
    description      = "Web Subnet Traffic To DB Port"
    source_type      = "CIDR_BLOCK"
    destination_port = 1521
  }
  security_list_ingress_jdeapp = {
    protocol    = local.ip_protocols.TCP
    source      = var.workload_private_spoke_subnet_web_cidr_block
    description = "web subnet Traffic To ENT Port"
    source_type = "CIDR_BLOCK"
    tcp_options = {
      min = 6017
      max = 6027
    }
  }
  security_list_ingress_jdeweb = {
    protocol    = local.ip_protocols.TCP
    source      = var.hub_private_subnet_cidr_block
    description = "Web Access to onprem"
    source_type = "CIDR_BLOCK"
    tcp_options = {
      min = 8000
      max = 8010
    }
  }

  security_list_ingress_oneclickport = {
    protocol         = local.ip_protocols.TCP
    source           = var.hub_private_subnet_cidr_block
    description      = "One Click access to onprem"
    source_type      = "CIDR_BLOCK"
    destination_port = 3000
  }

  security_list_ingress_smport = {
    protocol         = local.ip_protocols.TCP
    source           = var.hub_private_subnet_cidr_block
    description      = "SM Console Access to onprem"
    source_type      = "CIDR_BLOCK"
    destination_port = 8998
  }
  security_list_ingress_oneclick_jmx = {
    protocol    = local.ip_protocols.TCP
    source      = var.workload_private_spoke_subnet_web_cidr_block
    description = "Access to JMX ports "
    source_type = "CIDR_BLOCK"
    tcp_options = {
      min = 14501
      max = 14520
    }
  }
  security_list_ingress_oneclick_validationport = {
    protocol         = local.ip_protocols.TCP
    source           = var.workload_private_spoke_subnet_web_cidr_block
    description      = "Access to validation port"
    source_type      = "CIDR_BLOCK"
    destination_port = 5150
  }

  security_list_ingress_oneclick_winrm = {
    protocol         = local.ip_protocols.TCP
    source           = var.workload_private_spoke_subnet_web_cidr_block
    description      = "Access to validation port"
    source_type      = "CIDR_BLOCK"
    destination_port = 5985
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
module "workload_spoke_security_list" {
  source = "../../modules/security-list"

  compartment_id                        = var.workload_compartment_id
  vcn_id                                = module.workload_spoke_vcn.vcn_id
  spoke_security_list_display_name      = var.security_list_display_name
  security_list_egress_destination      = local.security_list_egress.destination
  security_list_egress_protocol         = local.security_list_egress.protocol
  security_list_egress_description      = local.security_list_egress.description
  security_list_egress_destination_type = local.security_list_egress.destination_type

  security_list_ingress_protocol    = local.security_list_ingress.protocol
  security_list_ingress_source      = local.security_list_ingress.source
  security_list_ingress_description = local.security_list_ingress.description
  security_list_ingress_source_type = local.security_list_ingress.source_type

}
module "workload_spoke_security_list_ssh" {
  source = "../../modules/security-list"

  compartment_id                        = var.workload_compartment_id
  vcn_id                                = module.workload_spoke_vcn.vcn_id
  spoke_security_list_display_name      = local.security_list_display_name_ssh
  security_list_egress_destination      = local.security_list_egress.destination
  security_list_egress_protocol         = local.security_list_egress.protocol
  security_list_egress_description      = local.security_list_egress.description
  security_list_egress_destination_type = local.security_list_egress.destination_type

  security_list_ingress_protocol         = local.security_list_ingress_ssh.protocol
  security_list_ingress_source           = local.security_list_ingress_ssh.source
  security_list_ingress_description      = local.security_list_ingress_ssh.description
  security_list_ingress_source_type      = local.security_list_ingress_ssh.source_type
  tcp_options_destination_port_range_min = local.security_list_ingress_ssh.destination_port
}

module "workload_spoke_security_list_RDP" {
  source = "../../modules/security-list"

  compartment_id                        = var.workload_compartment_id
  vcn_id                                = module.workload_spoke_vcn.vcn_id
  spoke_security_list_display_name      = local.security_list_display_name_RDP
  security_list_egress_destination      = local.security_list_egress.destination
  security_list_egress_protocol         = local.security_list_egress.protocol
  security_list_egress_description      = local.security_list_egress.description
  security_list_egress_destination_type = local.security_list_egress.destination_type

  security_list_ingress_protocol         = local.security_list_ingress_RDP.protocol
  security_list_ingress_source           = local.security_list_ingress_RDP.source
  security_list_ingress_description      = local.security_list_ingress_RDP.description
  security_list_ingress_source_type      = local.security_list_ingress_RDP.source_type
  tcp_options_destination_port_range_min = local.security_list_ingress_RDP.destination_port
}

module "workload_spoke_security_list_dbapp" {
  source = "../../modules/security-list"

  compartment_id                        = var.workload_compartment_id
  vcn_id                                = module.workload_spoke_vcn.vcn_id
  spoke_security_list_display_name      = local.security_list_display_name_dbapp
  security_list_egress_destination      = local.security_list_egress.destination
  security_list_egress_protocol         = local.security_list_egress.protocol
  security_list_egress_description      = local.security_list_egress.description
  security_list_egress_destination_type = local.security_list_egress.destination_type

  security_list_ingress_protocol         = local.security_list_ingress_dbapp.protocol
  security_list_ingress_source           = local.security_list_ingress_dbapp.source
  security_list_ingress_description      = local.security_list_ingress_dbapp.description
  security_list_ingress_source_type      = local.security_list_ingress_dbapp.source_type
  tcp_options_destination_port_range_min = local.security_list_ingress_dbapp.destination_port
}

module "workload_spoke_security_list_dbweb" {
  source = "../../modules/security-list"

  compartment_id                        = var.workload_compartment_id
  vcn_id                                = module.workload_spoke_vcn.vcn_id
  spoke_security_list_display_name      = local.security_list_display_name_dbweb
  security_list_egress_destination      = local.security_list_egress.destination
  security_list_egress_protocol         = local.security_list_egress.protocol
  security_list_egress_description      = local.security_list_egress.description
  security_list_egress_destination_type = local.security_list_egress.destination_type

  security_list_ingress_protocol         = local.security_list_ingress_dbweb.protocol
  security_list_ingress_source           = local.security_list_ingress_dbweb.source
  security_list_ingress_description      = local.security_list_ingress_dbweb.description
  security_list_ingress_source_type      = local.security_list_ingress_dbweb.source_type
  tcp_options_destination_port_range_min = local.security_list_ingress_dbweb.destination_port
}

module "workload_spoke_security_list_jdeapp" {
  source = "../../modules/security-list"

  compartment_id                        = var.workload_compartment_id
  vcn_id                                = module.workload_spoke_vcn.vcn_id
  spoke_security_list_display_name      = local.security_list_display_name_jdeapp
  security_list_egress_destination      = local.security_list_egress.destination
  security_list_egress_protocol         = local.security_list_egress.protocol
  security_list_egress_description      = local.security_list_egress.description
  security_list_egress_destination_type = local.security_list_egress.destination_type

  security_list_ingress_protocol         = local.security_list_ingress_jdeapp.protocol
  security_list_ingress_source           = local.security_list_ingress_jdeapp.source
  security_list_ingress_description      = local.security_list_ingress_jdeapp.description
  security_list_ingress_source_type      = local.security_list_ingress_jdeapp.source_type
  tcp_options_destination_port_range_min = local.security_list_ingress_jdeapp.tcp_options.min
  tcp_options_destination_port_range_max = local.security_list_ingress_jdeapp.tcp_options.max
}

module "workload_spoke_security_list_jdeweb" {
  source = "../../modules/security-list"

  compartment_id                        = var.workload_compartment_id
  vcn_id                                = module.workload_spoke_vcn.vcn_id
  spoke_security_list_display_name      = local.security_list_display_name_jdeweb
  security_list_egress_destination      = local.security_list_egress.destination
  security_list_egress_protocol         = local.security_list_egress.protocol
  security_list_egress_description      = local.security_list_egress.description
  security_list_egress_destination_type = local.security_list_egress.destination_type

  security_list_ingress_protocol         = local.security_list_ingress_jdeweb.protocol
  security_list_ingress_source           = local.security_list_ingress_jdeweb.source
  security_list_ingress_description      = local.security_list_ingress_jdeweb.description
  security_list_ingress_source_type      = local.security_list_ingress_jdeweb.source_type
  tcp_options_destination_port_range_min = local.security_list_ingress_jdeweb.tcp_options.min
  tcp_options_destination_port_range_max = local.security_list_ingress_jdeweb.tcp_options.max
}

module "workload_spoke_security_list_oneclickport" {
  source = "../../modules/security-list"

  compartment_id                        = var.workload_compartment_id
  vcn_id                                = module.workload_spoke_vcn.vcn_id
  spoke_security_list_display_name      = local.security_list_display_name_oneclickport
  security_list_egress_destination      = local.security_list_egress.destination
  security_list_egress_protocol         = local.security_list_egress.protocol
  security_list_egress_description      = local.security_list_egress.description
  security_list_egress_destination_type = local.security_list_egress.destination_type

  security_list_ingress_protocol         = local.security_list_ingress_oneclickport.protocol
  security_list_ingress_source           = local.security_list_ingress_oneclickport.source
  security_list_ingress_description      = local.security_list_ingress_oneclickport.description
  security_list_ingress_source_type      = local.security_list_ingress_oneclickport.source_type
  tcp_options_destination_port_range_min = local.security_list_ingress_oneclickport.destination_port
}

module "workload_spoke_security_list_smport" {
  source = "../../modules/security-list"

  compartment_id                        = var.workload_compartment_id
  vcn_id                                = module.workload_spoke_vcn.vcn_id
  spoke_security_list_display_name      = local.security_list_display_name_smport
  security_list_egress_destination      = local.security_list_egress.destination
  security_list_egress_protocol         = local.security_list_egress.protocol
  security_list_egress_description      = local.security_list_egress.description
  security_list_egress_destination_type = local.security_list_egress.destination_type

  security_list_ingress_protocol         = local.security_list_ingress_smport.protocol
  security_list_ingress_source           = local.security_list_ingress_smport.source
  security_list_ingress_description      = local.security_list_ingress_smport.description
  security_list_ingress_source_type      = local.security_list_ingress_smport.source_type
  tcp_options_destination_port_range_min = local.security_list_ingress_smport.destination_port
}

module "workload_spoke_security_list_oneclick_jmx" {
  source = "../../modules/security-list"

  compartment_id                        = var.workload_compartment_id
  vcn_id                                = module.workload_spoke_vcn.vcn_id
  spoke_security_list_display_name      = local.security_list_display_name_oneclick_jmx
  security_list_egress_destination      = local.security_list_egress.destination
  security_list_egress_protocol         = local.security_list_egress.protocol
  security_list_egress_description      = local.security_list_egress.description
  security_list_egress_destination_type = local.security_list_egress.destination_type

  security_list_ingress_protocol         = local.security_list_ingress_oneclick_jmx.protocol
  security_list_ingress_source           = local.security_list_ingress_oneclick_jmx.source
  security_list_ingress_description      = local.security_list_ingress_oneclick_jmx.description
  security_list_ingress_source_type      = local.security_list_ingress_oneclick_jmx.source_type
  tcp_options_destination_port_range_min = local.security_list_ingress_oneclick_jmx.tcp_options.min
  tcp_options_destination_port_range_max = local.security_list_ingress_oneclick_jmx.tcp_options.max
}

module "workload_spoke_security_list_oneclick_validationport" {
  source = "../../modules/security-list"

  compartment_id                        = var.workload_compartment_id
  vcn_id                                = module.workload_spoke_vcn.vcn_id
  spoke_security_list_display_name      = local.security_list_display_name_oneclick_validationport
  security_list_egress_destination      = local.security_list_egress.destination
  security_list_egress_protocol         = local.security_list_egress.protocol
  security_list_egress_description      = local.security_list_egress.description
  security_list_egress_destination_type = local.security_list_egress.destination_type

  security_list_ingress_protocol         = local.security_list_ingress_oneclick_validationport.protocol
  security_list_ingress_source           = local.security_list_ingress_oneclick_validationport.source
  security_list_ingress_description      = local.security_list_ingress_oneclick_validationport.description
  security_list_ingress_source_type      = local.security_list_ingress_oneclick_validationport.source_type
  tcp_options_destination_port_range_min = local.security_list_ingress_oneclick_validationport.destination_port
}

module "workload_spoke_security_list_oneclick_winrm" {
  source = "../../modules/security-list"

  compartment_id                        = var.workload_compartment_id
  vcn_id                                = module.workload_spoke_vcn.vcn_id
  spoke_security_list_display_name      = local.security_list_display_name_oneclick_winrm
  security_list_egress_destination      = local.security_list_egress.destination
  security_list_egress_protocol         = local.security_list_egress.protocol
  security_list_egress_description      = local.security_list_egress.description
  security_list_egress_destination_type = local.security_list_egress.destination_type

  security_list_ingress_protocol         = local.security_list_ingress_oneclick_winrm.protocol
  security_list_ingress_source           = local.security_list_ingress_oneclick_winrm.source
  security_list_ingress_description      = local.security_list_ingress_oneclick_winrm.description
  security_list_ingress_source_type      = local.security_list_ingress_oneclick_winrm.source_type
  tcp_options_destination_port_range_min = local.security_list_ingress_oneclick_winrm.destination_port
}
######################################################################
#          Create Workload VCN Spoke Subnet                          #
######################################################################
module "workload_spoke_subnet" {
  source = "../../modules/subnet"

  subnet_map            = local.workload_expansion_subnet_map
  compartment_id        = var.workload_compartment_id
  vcn_id                = module.workload_spoke_vcn.vcn_id
  subnet_route_table_id = module.workload_spoke_route_table.route_table_id
  subnet_security_list_id = toset([
    module.workload_spoke_security_list_ssh.security_list_id,
    module.workload_spoke_security_list_RDP.security_list_id,
    module.workload_spoke_security_list_dbapp.security_list_id,
    module.workload_spoke_security_list_dbweb.security_list_id,
    module.workload_spoke_security_list_jdeapp.security_list_id,
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
*/
