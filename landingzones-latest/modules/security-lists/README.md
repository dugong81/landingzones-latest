<!-- BEGIN_TF_DOCS -->
## Requirements

No requirements.

## Providers

| Name | Version |
|------|---------|
| <a name="provider_oci"></a> [oci](#provider\_oci) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [oci_core_security_list.security_list_spoke](https://registry.terraform.io/providers/oracle/oci/latest/docs/resources/core_security_list) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_compartment_id"></a> [compartment\_id](#input\_compartment\_id) | Compartment OCID ID | `string` | n/a | yes |
| <a name="input_egress_rules"></a> [egress\_rules](#input\_egress\_rules) | n/a | <pre>list(object({<br>    egress_destination      = string,<br>    egress_protocol         = string,<br>    egress_description      = string,<br>    egress_destination_type = string,<br>  }))</pre> | n/a | yes |
| <a name="input_ingress_rules"></a> [ingress\_rules](#input\_ingress\_rules) | n/a | <pre>list(object({<br>    ingress_protocol             = string,<br>    ingress_source               = string,<br>    ingress_description          = string,<br>    ingress_source_type          = string,<br>    ingress_source_port_min      = optional(number),<br>    ingress_source_port_max      = optional(number),<br>    ingress_destination_port_min = optional(number),<br>    ingress_destination_port_max = optional(number),<br>    icmp_type                    = optional(number),<br>    icmp_code                    = optional(number)<br>  }))</pre> | n/a | yes |
| <a name="input_spoke_security_list_display_name"></a> [spoke\_security\_list\_display\_name](#input\_spoke\_security\_list\_display\_name) | VCN OCID ID | `string` | n/a | yes |
| <a name="input_vcn_id"></a> [vcn\_id](#input\_vcn\_id) | VCN OCID ID | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_security_list_id"></a> [security\_list\_id](#output\_security\_list\_id) | The OCID of the Security List |
<!-- END_TF_DOCS -->    