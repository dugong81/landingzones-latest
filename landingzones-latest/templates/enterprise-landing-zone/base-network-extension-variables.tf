variable "enable_vpn_or_fastconnect" {
  type        = string
  description = "Option to enable VPN or FASTCONNECT service. Options are NONE, VPN, FASTCONNECT."
  default     = "NONE"
}

variable "fastconnect_provider" {
  type        = string
  description = "Fastconnect provider. Please choose from: AT&T, Azure, Megaport, QTS, CEintro, Cologix, CoreSite, Digitial Realty, EdgeConneX, Epsilon, Equinix, InterCloud, Lumen, Neutrona, OMCS, OracleL2ItegDeployment, OracleL3ItegDeployment, Orange, Verizon, Zayo"
  default     = ""
}

variable "virtual_circuit_bandwidth_shape" {
  type        = string
  description = "The provisioned data rate of the connection"
  default     = "1500"
}

variable "virtual_circuit_display_name" {
  type        = string
  description = "The display name of this virtual circuit. Recommendation: OCI-ELZ-FCN-P-HUB-[REGION] 001"
  default     = ""
}

variable "provider_service_key_name" {
  type        = string
  description = "The provider service key that the provider gives you when you set up a virtual circuit connection from the provider to OCI"
  default     = ""
}

variable "fastconnect_routing_policy" {
  type        = list(string)
  description = "Available FastConnect routing policies: ORACLE_SERVICE_NETWORK, REGIONAL, MARKET_LEVEL, GLOBAL"
  default     = []
}

variable "virtual_circuit_type" {
  type        = string
  description = "The type of IP addresses used in this virtual circuit. PRIVATE or PUBLIC"
  default     = ""
}

variable "customer_primary_bgp_peering_ip" {
  type        = string
  description = "The primary BGP IPv4 address of the customer's router"
  default     = ""

}

variable "oracle_primary_bgp_peering_ip" {
  type        = string
  description = "The primary BGP IPv4 address for Oracle's end of the BGP session"
  default     = ""
}

variable "customer_secondary_bgp_peering_ip" {
  type        = string
  description = "[Optional] The secondary BGP IPv4 address of the customer's router"
  default     = ""
}

variable "oracle_secondary_bgp_peering_ip" {
  type        = string
  description = "[Optional] Secondary IPv4 address for Oracle's end of the BGP session"
  default     = ""
}

variable "virtual_circuit_customer_asn" {
  type        = string
  description = "The BGP ASN of the network at the other end of the BGP session from Oracle"
  default     = 0
}

variable "virtual_circuit_is_bfd_enabled" {
  type        = bool
  description = "Set to true to enable BFD for IPv4 BGP peering, or set to false to disable BFD"
  default     = false
}

variable "bgp_md5auth_key" {
  type        = string
  description = "The key for BGP MD5 authentication. Only applicable if your system requires MD5 authentication"
  default     = ""
}

variable "customer_onprem_ip_cidr" {
  type    = list(string)
  default = []
}
