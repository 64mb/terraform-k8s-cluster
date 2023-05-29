resource "yandex_vpc_security_group" "sg" {
  name       = var.name
  network_id = var.network_id

  dynamic "ingress" {
    for_each = var.security_rules.ingress

    content {
      protocol          = ingress.value.proto
      description       = ingress.value.desc
      v4_cidr_blocks    = ingress.value.cidr_v4 != null ? ingress.value.cidr_v4 : []
      v6_cidr_blocks    = ingress.value.cidr_v6 != null ? ingress.value.cidr_v6 : []
      predefined_target = ingress.value.target != null ? ingress.value.target : null
      port              = ingress.value.port
      from_port         = ingress.value.from_port
      to_port           = ingress.value.to_port
    }
  }

  dynamic "egress" {
    for_each = var.security_rules.egress

    content {
      protocol          = egress.value.proto
      description       = egress.value.desc
      v4_cidr_blocks    = egress.value.cidr_v4 != null ? egress.value.cidr_v4 : []
      v6_cidr_blocks    = egress.value.cidr_v6 != null ? egress.value.cidr_v6 : []
      predefined_target = egress.value.target != null ? egress.value.target : null
      port              = egress.value.port
      from_port         = egress.value.from_port
      to_port           = egress.value.to_port
    }
  }
}
