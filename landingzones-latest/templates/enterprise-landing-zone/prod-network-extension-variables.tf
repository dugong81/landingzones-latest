variable "prod_enable_vpn" {
  type        = bool
  description = "Enable VPN in prod environment"
  default     = false
}

variable "prod_cpe_display_name" {
  type        = string
  description = "Customer Premises Equipment name. Recommendation: OCI-ELZ-CPE-[Environment]-HUB-[Region] 001"
  default     = ""
}

variable "prod_cpe_ip_address" {
  type        = string
  description = "Customer Premises Equipment (CPE) IP address"
  default     = ""
}

variable "prod_ipsec_display_name" {
  type        = string
  description = "IPsec display name. Recommendation: OCI-ELZ-IPS-[Environment]-HUB-[Region] 001"
  default     = ""
}

variable "prod_ipsec_connection_static_routes" {
  type        = list(string)
  description = ""
  default     = [""]
}

variable "prod_cpe_vendor" {
  type        = number
  description = "Type corresponding number as your CPE vendor: Yamaha-RTX1210 0, Other 1, Cisco-9.7.1-or-later 2, Yamaha-RTX830 3, Libreswan 4, Fortinet 5, NEC 6, Cisco-8.5+ 7, Cisco-IOS 8, WatchGuard 9, Juniper-MX 10, Juniper-SRX 11, Furukawa 12, Check_Point 13, Palo_Alto 14"
  default     = 0
}

variable "prod_ipsec_routing_type" {
  type        = string
  description = "BGP dynamic routing, STATIC routing. Type BGP or STATIC"
  default     = "STATIC"
}

variable "prod_tunnel_a_display_name" {
  type        = string
  description = "Tunnel A display name. Recommendation: "
  default     = ""
}

variable "prod_customer_bgp_asn" {
  type        = string
  description = "ASN is required and used for the tunnel's BGP session"
  default     = ""
}

variable "prod_bgp_cust_tunnela_ip" {
  type        = string
  description = "The IP address for the CPE end of the inside tunnel interface."
  default     = ""
}

variable "prod_bgp_oci_tunnela_ip" {
  type        = string
  description = "The IP address for the Oracle end of the inside tunnel interface."
  default     = ""

}

variable "prod_shared_secret" {
  type        = string
  description = "The shared secret (pre-shared key) to use for the IPSec tunnel"
  default     = "example"

}

variable "prod_tunnel_b_display_name" {
  type        = string
  description = "Tunnel B display name. Recommendation: "
  default     = ""
}
variable "prod_enable_fastconnect" {
  type        = bool
  default     = true
  description = "[Please don't change this value] Enable fastconnect in prod environment."
}
