resource "null_resource" "groups" {
  count = length(var.group_names) != 0 ? 1 : 0

  triggers = {
    domain_id   = var.identity_domain_id
    group_names = "${join(" ", var.group_names)}"
  }

  provisioner "local-exec" {
    working_dir = path.module
    command     = "pip3 install -r scripts/requirements.txt"
    on_failure  = continue
  }

  provisioner "local-exec" {
    working_dir = path.module
    command     = "python3 scripts/manage_identity_domain.py -a 'create' -d ${self.triggers.domain_id} -g ${self.triggers.group_names}"
    on_failure  = continue
  }

  provisioner "local-exec" {
    working_dir = path.module
    when        = destroy
    command     = "python3 scripts/manage_identity_domain.py -a 'delete' -d ${self.triggers.domain_id} -g ${self.triggers.group_names}"
    on_failure  = continue
  }
}
