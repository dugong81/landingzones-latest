variable "egress_rules" {
  type = list(object({
    egress_destination      = string,
    egress_protocol         = string,
    egress_description      = string,
    egress_destination_type = string,
  }))
}

variable "ingress_rules" {
  type = list(object({
    ingress_protocol             = string,
    ingress_source               = string,
    ingress_description          = string,
    ingress_source_type          = string,
    ingress_source_port_min      = optional(number),
    ingress_source_port_max      = optional(number),
    ingress_destination_port_min = optional(number),
    ingress_destination_port_max = optional(number),
    icmp_type                    = optional(number),
    icmp_code                    = optional(number)
  }))
}

/*
variable "security_list_egress_destination" {
  type        = string
  description = "Egress: Security List Protocol"
}

variable "security_list_egress_protocol" {
  type        = string
  description = "Ingress: Security List Protocol"
}

variable "security_list_egress_description" {
  type        = string
  description = "Ingress: Security List Rule Description"
}

variable "security_list_egress_destination_type" {
  type        = string
  description = "Ingress: Security List Rule Source Type"
}

variable "security_list_ingress_protocol" {
  type        = string
  description = "Egress: Security List Rule Description"
}

variable "security_list_ingress_source" {
  type        = string
  description = "Egress: Security List Rule Protocol"
}

variable "security_list_ingress_description" {
  type        = string
  description = "Egress: Security List Rule Description"
}

variable "security_list_ingress_source_type" {
  type        = string
  description = "Egress: Security List Rule Destination Type"
}
*/

variable "compartment_id" {
  type        = string
  description = "Compartment OCID ID"
}
variable "vcn_id" {
  type        = string
  description = "VCN OCID ID"
}
variable "spoke_security_list_display_name" {
  type        = string
  description = "VCN OCID ID"
}
/*
variable "tcp_options_destination_port_range_min" {
  type        = number
  description = "Destination Port Min"
  default     = 0
}
variable "tcp_options_destination_port_range_max" {
  type        = number
  description = "Destination Port Max"
  default     = 0
}
variable "tcp_options_source_port_range_min" {
  type        = number
  description = "Source Port Min"
  default     = 0
}
variable "tcp_options_source_port_range_max" {
  type        = number
  description = "Source Port Max"
  default     = 0
}

variable "icmp_options_type" {
  type        = number
  description = "ICMP type"
  default     = 0
}
variable "icmp_options_code" {
  type        = number
  description = "ICMP code"
  default     = 0
}
*/
