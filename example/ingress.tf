locals {
  ingress_group = "main-ingress-group"

  sg_id        = "..."
  subnet_id    = "..."
  cert_id      = "..."
  ip_v4        = "..."
  domain       = "..."
  service_name = "..."
  service_port = 0
}

resource "yandex_vpc_address" "k8s_alb_ingress_ip" {
  name = "k8s-alb-ingress-ip"

  external_ipv4_address {
    zone_id = "ru-central1-a"
  }
}

resource "kubernetes_ingress_v1" "k8s_ingress" {
  metadata {
    name = "k8s-ingress"
    annotations = {
      "ingress.alb.yc.io/subnets"               = local.subnet_id
      "ingress.alb.yc.io/security-groups"       = local.sg_id
      "ingress.alb.yc.io/external-ipv4-address" = local.ip_v4
      "ingress.alb.yc.io/group-name"            = local.ingress_group
    }
  }

  spec {
    tls {
      hosts       = [local.domain]
      secret_name = "yc-certmgr-cert-id-${local.cert_id}"
    }

    rule {
      host = local.domain
      http {
        path {
          backend {
            service {
              name = local.service_name
              port {
                number = local.service_port
              }
            }
          }

          path = "/"
        }
      }
    }
  }
}
