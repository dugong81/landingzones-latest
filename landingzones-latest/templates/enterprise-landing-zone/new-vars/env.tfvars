
// newenv-start
# iam
newenv_environment_prefix = "environmentprefix"
newenv_domain_admin_email = "noreply@oracle.com"
# newenv_enable_shared_tools = false
# budget
newenv_enable_budget = false
# newenv_budget_alert_rule_message    = "[PRD] budget 70% alert."
# newenv_budget_alert_rule_threshold  = 7000
# newenv_budget_amount                = 10000
# newenv_budget_alert_rule_recipients = ""

# network
newenv_enable_internet_gateway_hub = "true"
newenv_enable_nat_gateway_hub      = "true"
newenv_enable_service_gateway_hub  = "true"

newenv_hub_vcn_cidr_block            = "10.1.0.0/16"
newenv_hub_public_subnet_cidr_block  = "10.1.1.0/24"
newenv_hub_private_subnet_cidr_block = "10.1.2.0/24"

# network extension
newenv_enable_vpn = false

#monitoring
newenv_network_topic_endpoints  = []
newenv_secops_topic_endpoints   = []
newenv_platform_topic_endpoints = []
newenv_identity_topic_endpoints = []

#tagging
newenv_enable_tagging       = false
newenv_cost_center_tagging  = "p_cost_tag"
newenv_geo_location_tagging = "p_geo_tag"

#workload expansions
newenv_workload_compartment_names              = []
newenv_additional_workload_subnets_cidr_blocks = []

// newenv-end
