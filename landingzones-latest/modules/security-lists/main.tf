terraform {
  required_providers {
    oci = {
      source = "oracle/oci"
    }
  }
}

######################################################################
#                    Create Security List                            #
######################################################################

resource "oci_core_security_list" "security_list_spoke" {
  compartment_id = var.compartment_id
  vcn_id         = var.vcn_id
  display_name   = var.spoke_security_list_display_name

  dynamic "egress_security_rules" {
    iterator = egress_security_rules
    for_each = var.egress_rules
    content {
      destination      = egress_security_rules.value.egress_destination
      protocol         = egress_security_rules.value.egress_protocol
      description      = egress_security_rules.value.egress_description
      destination_type = egress_security_rules.value.egress_destination_type
    }
  }

  dynamic "ingress_security_rules" {
    iterator = ingress_security_rules
    for_each = var.ingress_rules
    content {
      protocol    = ingress_security_rules.value.ingress_protocol
      source      = ingress_security_rules.value.ingress_source
      description = ingress_security_rules.value.ingress_description
      source_type = ingress_security_rules.value.ingress_source_type

      dynamic "icmp_options" {
        iterator = icmp_options
        for_each = (ingress_security_rules.value.icmp_type == null) ? [] : [ingress_security_rules.value.icmp_type]
        content {
          type = icmp_options.value
          code = (ingress_security_rules.value.icmp_code != 0) ? ingress_security_rules.value.icmp_code : null
        }
      }

      dynamic "tcp_options" {
        iterator = tcp_options
        for_each = (ingress_security_rules.value.ingress_destination_port_min == null) ? [] : [ingress_security_rules.value.ingress_destination_port_min]
        content {
          min = tcp_options.value
          max = (ingress_security_rules.value.ingress_destination_port_max != null) ? ingress_security_rules.value.ingress_destination_port_max : tcp_options.value
          dynamic "source_port_range" {
            iterator = source_port_range
            for_each = (ingress_security_rules.value.ingress_source_port_min == null) ? [] : [ingress_security_rules.value.ingress_source_port_min]
            content {
              min = source_port_range.value
              max = (ingress_security_rules.value.ingress_source_port_max != null) ? ingress_security_rules.value.ingress_source_port_max : source_port_range.value
            }
          }
        }
      }

    }
  }
}
