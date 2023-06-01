
resource "yandex_logging_group" "k8s_logging_group" {
  name      = "k8s-logging-group"
  folder_id = local.folder_id
}

resource "yandex_kms_symmetric_key" "k8s_kms_key" {
  name              = "k8s-kms-key"
  default_algorithm = "AES_256"
}

resource "yandex_iam_service_account" "k8s_sa_master" {
  name = "k8s-sa-master"
}

resource "yandex_resourcemanager_folder_iam_member" "k8s_sa_master_role_k8s_cluster_agent" {
  folder_id = local.folder_id
  role      = "k8s.clusters.agent"
  member    = "serviceAccount:${yandex_iam_service_account.k8s_sa_master.id}"
}

resource "yandex_resourcemanager_folder_iam_member" "k8s_sa_master_role_k8s_tunnel_cluster_agent" {
  folder_id = local.folder_id
  role      = "k8s.tunnelClusters.agent"
  member    = "serviceAccount:${yandex_iam_service_account.k8s_sa_master.id}"
}

resource "yandex_resourcemanager_folder_iam_member" "k8s_sa_master_role_vpc_public_admin" {
  folder_id = local.folder_id
  role      = "vpc.publicAdmin"
  member    = "serviceAccount:${yandex_iam_service_account.k8s_sa_master.id}"
}

resource "yandex_resourcemanager_folder_iam_member" "k8s_sa_master_role_load_balancer_admin" {
  folder_id = local.folder_id
  role      = "load-balancer.admin"
  member    = "serviceAccount:${yandex_iam_service_account.k8s_sa_master.id}"
}


resource "yandex_iam_service_account" "k8s_sa_node" {
  name = "k8s-sa-node"
}

resource "yandex_resourcemanager_folder_iam_member" "k8s_sa_node_role_container_registry_images_puller" {
  folder_id = local.folder_id
  role      = "container-registry.images.puller"
  member    = "serviceAccount:${yandex_iam_service_account.k8s_sa_node.id}"
}

resource "yandex_vpc_gateway" "k8s_gateway_nat" {
  name = "k8s-gateway-nat"
  shared_egress_gateway {}
}


resource "yandex_vpc_route_table" "k8s_rt_nat" {
  name       = "k8s-rt-nat"
  network_id = local.network_id

  static_route {
    destination_prefix = "0.0.0.0/0"
    gateway_id         = yandex_vpc_gateway.k8s_gateway_nat.id
  }
}

resource "yandex_vpc_subnet" "k8s_subnet" {
  name           = "k8s-subnet"
  v4_cidr_blocks = ["10.16.0.0/16"]
  # v6_cidr_blocks = ["..."]
  zone           = "ru-central1-a"
  network_id     = local.network_id
  route_table_id = yandex_vpc_route_table.k8s_rt_nat.id
}

module "k8s_sg" {
  source = "./module/security-group"

  name       = "k8s-sg"
  network_id = local.network_id
  security_rules = {
    ingress = [
      { target = "loadbalancer_healthchecks", from_port = 0, to_port = 65535, proto = "TCP" },
      { target = "self_security_group", from_port = 0, to_port = 65535, proto = "ANY" },
      { cidr_v4 = yandex_vpc_subnet.k8s_subnet.v4_cidr_blocks, from_port = 0, to_port = 65535, proto = "ANY" },
      { cidr_v4 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], from_port = 0, to_port = 65535, proto = "ICMP" },
      { cidr_v4 = local.allowed_ip, from_port = 30000, to_port = 32767, proto = "TCP" },
      { cidr_v4 = local.allowed_ip, port = 22, proto = "TCP" },
      { cidr_v4 = local.allowed_ip, port = 443, proto = "TCP" },
      { cidr_v4 = local.allowed_ip, port = 6443, proto = "TCP" },
    ]
    egress = [
      { cidr_v4 = ["0.0.0.0/0"], from_port = 0, to_port = 65535, proto = "ANY" },
    ]
  }
}

resource "yandex_kubernetes_cluster" "k8s_cluster" {
  name = "k8s-cluster"

  network_id = local.network_id

  master {
    version = local.k8s_version
    zonal {
      zone      = yandex_vpc_subnet.k8s_subnet.zone
      subnet_id = yandex_vpc_subnet.k8s_subnet.id
    }

    public_ip = true

    security_group_ids = [module.k8s_sg.id]

    maintenance_policy {
      auto_upgrade = true
    }

    master_logging {
      enabled                    = true
      log_group_id               = yandex_logging_group.k8s_logging_group.id
      kube_apiserver_enabled     = true
      cluster_autoscaler_enabled = true
      events_enabled             = true
    }
  }

  service_account_id      = yandex_iam_service_account.k8s_sa_master.id
  node_service_account_id = yandex_iam_service_account.k8s_sa_node.id

  release_channel         = "REGULAR"
  network_policy_provider = "CALICO"

  kms_provider {
    key_id = yandex_kms_symmetric_key.k8s_kms_key.id
  }

  depends_on = [
    yandex_iam_service_account.k8s_sa_master,
    yandex_iam_service_account.k8s_sa_node,
  ]
}

resource "yandex_kubernetes_node_group" "k8s_node_group" {
  cluster_id = yandex_kubernetes_cluster.k8s_cluster.id
  name       = "k8s-node-group"
  version    = local.k8s_version

  instance_template {
    platform_id = "standard-v2"

    network_interface {
      nat                = false
      subnet_ids         = ["${yandex_vpc_subnet.k8s_subnet.id}"]
      security_group_ids = [module.k8s_sg.id]
    }

    resources {
      memory = 4
      cores  = 2
      # core_fraction = 100
      core_fraction = 50
    }

    metadata = {
      ssh-keys = "${local.k8s_node_user}:${local.k8s_node_ssh_key}"
    }

    boot_disk {
      type = "network-ssd"
      size = 32
    }

    scheduling_policy {
      preemptible = true
    }

    container_runtime {
      type = "containerd"
    }
  }

  scale_policy {
    # auto_scale {
    #   min     = 1
    #   max     = 2
    #   initial = 1
    # }

    fixed_scale {
      size = 1
    }
  }

  deploy_policy {
    max_expansion   = 1
    max_unavailable = 1
  }

  allocation_policy {
    location {
      zone = yandex_vpc_subnet.k8s_subnet.zone
    }
  }

  maintenance_policy {
    auto_upgrade = true
    auto_repair  = true
  }
}

module "k8s_static_key" {
  source = "./module/k8s-static-key"

  service_account_key_file = local.service_account_key_file
  cloud_id                 = local.cloud_id
  folder_id                = local.folder_id

  k8s_cluster_id = yandex_kubernetes_cluster.k8s_cluster.id

  depends_on = [
    yandex_kubernetes_cluster.k8s_cluster,
    module.k8s_sg,
  ]
}

resource "yandex_lockbox_secret" "k8s_admin_token" {
  name       = "k8s-admin-token"
  kms_key_id = yandex_kms_symmetric_key.k8s_kms_key.id
}

resource "yandex_lockbox_secret_version" "k8s_admin_token_version" {
  secret_id = yandex_lockbox_secret.k8s_admin_token.id

  entries {
    key        = "token"
    text_value = module.k8s_static_key.token
  }
}

locals {
  k8s_cluster_endpoint       = yandex_kubernetes_cluster.k8s_cluster.master[0].external_v4_endpoint
  k8s_cluster_ip_v4          = replace(local.k8s_cluster_endpoint, "https://", "")
  k8s_cluster_ca_certificate = yandex_kubernetes_cluster.k8s_cluster.master[0].cluster_ca_certificate

  k8s_lockbox_entries = yandex_lockbox_secret_version.k8s_admin_token_version.entries
  k8s_token           = local.k8s_lockbox_entries[index(local.k8s_lockbox_entries.*.key, "token")].text_value
}

resource "yandex_dns_recordset" "k8s_dns_k8s_record" {
  zone_id = local.dns_zone_id
  name    = "k8s.${local.dns_zone}"
  type    = "A"
  data    = [local.k8s_cluster_ip_v4]
  ttl     = 600
}

resource "helm_release" "helm_external_secrets" {
  name = "external-secrets"

  repository = "https://charts.external-secrets.io"
  chart      = "external-secrets"

  namespace        = "external-secrets"
  create_namespace = true

  depends_on = [
    local.k8s_token,
  ]
}

resource "yandex_iam_service_account" "k8s_sa_eso" {
  name = "k8s-sa-eso"
}

resource "yandex_iam_service_account_key" "k8s_sa_eso_auth_key" {
  service_account_id = yandex_iam_service_account.k8s_sa_eso.id
  key_algorithm      = "RSA_4096"
}

resource "yandex_resourcemanager_folder_iam_member" "k8s_sa_eso_role_lockbox_payload_viewer" {
  folder_id = local.folder_id
  role      = "lockbox.payloadViewer"
  member    = "serviceAccount:${yandex_iam_service_account.k8s_sa_eso.id}"
}

resource "yandex_resourcemanager_folder_iam_member" "k8s_sa_eso_role_kms_keys_encrypter_decrypter" {
  folder_id = local.folder_id
  role      = "kms.keys.encrypterDecrypter"
  member    = "serviceAccount:${yandex_iam_service_account.k8s_sa_eso.id}"
}

resource "kubernetes_secret" "k8s_eso_yc_auth" {
  metadata {
    name      = "yc-auth"
    namespace = "external-secrets"
  }

  data = {
    authorized-key = jsonencode({
      id                 = yandex_iam_service_account_key.k8s_sa_eso_auth_key.id
      service_account_id = yandex_iam_service_account.k8s_sa_eso.id
      created_at         = yandex_iam_service_account_key.k8s_sa_eso_auth_key.created_at
      key_algorithm      = "RSA_4096"
      public_key         = yandex_iam_service_account_key.k8s_sa_eso_auth_key.public_key
      private_key        = yandex_iam_service_account_key.k8s_sa_eso_auth_key.private_key
    })
  }

  type = "kubernetes.io/generic"
}

resource "kubernetes_manifest" "k8s_secret_store" {
  manifest = {
    "apiVersion" = "external-secrets.io/v1alpha1"
    "kind"       = "SecretStore"
    "metadata" = {
      "name"      = "secret-store"
      "namespace" = "external-secrets"
    }
    "spec" = {
      "provider" = {
        "yandexlockbox" = {
          "auth" = {
            "authorizedKeySecretRef" = {
              "name" = "yc-auth"
              "key"  = "authorized-key"
            }
          }
        }
      }
    }
  }

  depends_on = [
    local.k8s_token,
  ]
}

resource "yandex_iam_service_account" "k8s_sa_alb_ingress" {
  name = "k8s-sa-alb-ingress"
}

resource "yandex_iam_service_account_key" "k8s_sa_alb_ingress_auth_key" {
  service_account_id = yandex_iam_service_account.k8s_sa_alb_ingress.id
  key_algorithm      = "RSA_4096"
}

resource "yandex_resourcemanager_folder_iam_member" "k8s_sa_alb_ingress_role_alb_editor" {
  folder_id = local.folder_id
  role      = "alb.editor"
  member    = "serviceAccount:${yandex_iam_service_account.k8s_sa_alb_ingress.id}"
}

resource "yandex_resourcemanager_folder_iam_member" "k8s_sa_alb_ingress_role_vpc_public_admin" {
  folder_id = local.folder_id
  role      = "vpc.publicAdmin"
  member    = "serviceAccount:${yandex_iam_service_account.k8s_sa_alb_ingress.id}"
}

resource "yandex_resourcemanager_folder_iam_member" "k8s_sa_alb_ingress_role_certificate_manager" {
  folder_id = local.folder_id
  role      = "certificate-manager.certificates.downloader"
  member    = "serviceAccount:${yandex_iam_service_account.k8s_sa_alb_ingress.id}"
}

resource "yandex_resourcemanager_folder_iam_member" "k8s_sa_alb_ingress_role_compute_viewer" {
  folder_id = local.folder_id
  role      = "compute.viewer"
  member    = "serviceAccount:${yandex_iam_service_account.k8s_sa_alb_ingress.id}"
}

resource "helm_release" "helm_alb_ingress" {
  name = "yc-alb-ingress-controller"

  repository = "oci://cr.yandex/yc-marketplace/yandex-cloud/yc-alb-ingress"
  chart      = "yc-alb-ingress-controller-chart"
  version    = "v0.1.16"

  namespace        = "alb-ingress"
  create_namespace = true

  values = [yamlencode({
    folderId  = local.folder_id
    clusterId = yandex_kubernetes_cluster.k8s_cluster.id
    saKeySecretKey = jsonencode({
      id                 = yandex_iam_service_account_key.k8s_sa_alb_ingress_auth_key.id
      service_account_id = yandex_iam_service_account.k8s_sa_alb_ingress.id
      created_at         = yandex_iam_service_account_key.k8s_sa_alb_ingress_auth_key.created_at
      key_algorithm      = "RSA_4096"
      public_key         = yandex_iam_service_account_key.k8s_sa_alb_ingress_auth_key.public_key
      private_key        = yandex_iam_service_account_key.k8s_sa_alb_ingress_auth_key.private_key
    })
  })]


  depends_on = [
    local.k8s_token,
  ]
}

resource "helm_release" "helm_argo_cd" {
  name = "ci"

  repository = "oci://cr.yandex/yc-marketplace/yandex-cloud/argo/chart"
  chart      = "argo-cd"
  version    = "5.4.3-7"

  namespace        = "argo-cd"
  create_namespace = true

  depends_on = [
    local.k8s_token,
  ]
}

data "yandex_dns_zone" "k8s_dns_zone" {
  dns_zone_id = local.dns_zone_id
}

locals {
  k8s_ingress_group = "k8s-service-alb"
  dns_zone          = data.yandex_dns_zone.k8s_dns_zone.zone
  domain            = trim(local.dns_zone, ".")
  domain_argo_cd    = "argo-cd.${local.domain}"
  ip_v4_address     = yandex_vpc_address.k8s_alb_ingress_ip.external_ipv4_address[0].address
}

resource "yandex_vpc_address" "k8s_alb_ingress_ip" {
  name = "k8s-alb-ingress-ip"

  external_ipv4_address {
    zone_id = "ru-central1-a"
  }
}

resource "yandex_cm_certificate" "k8s_argo_cd_cert" {
  name    = "k8s-cert-argo-cd"
  domains = [local.domain_argo_cd]

  managed {
    challenge_type  = "DNS_CNAME"
    challenge_count = 1
  }
}

resource "yandex_dns_recordset" "k8s_cert_dns_challenge" {
  count   = yandex_cm_certificate.k8s_argo_cd_cert.managed[0].challenge_count
  zone_id = local.dns_zone_id
  name    = yandex_cm_certificate.k8s_argo_cd_cert.challenges[count.index].dns_name
  type    = yandex_cm_certificate.k8s_argo_cd_cert.challenges[count.index].dns_type
  data    = [yandex_cm_certificate.k8s_argo_cd_cert.challenges[count.index].dns_value]
  ttl     = 600
}

resource "yandex_dns_recordset" "k8s_dns_argo_cd_record" {
  zone_id = local.dns_zone_id
  name    = "argo-cd.${local.dns_zone}"
  type    = "A"
  data    = [local.ip_v4_address]
  ttl     = 600
}

resource "kubernetes_service" "k8s_argo_cd_service" {
  metadata {
    name      = "argo-cd-np"
    namespace = "argo-cd"
  }
  spec {
    selector = {
      "app.kubernetes.io/instance" = "ci"
      "app.kubernetes.io/name"     = "argocd-server"
    }
    # session_affinity = "ClientIP"
    port {
      name        = "https"
      port        = 443
      target_port = "server"
      protocol    = "TCP"
    }
    type = "NodePort"
  }

  depends_on = [
    local.k8s_token,
  ]
}


resource "kubernetes_ingress_v1" "k8s_ingress" {
  metadata {
    name      = "k8s-ingress"
    namespace = "argo-cd"
    annotations = {
      "ingress.alb.yc.io/subnets"               = yandex_vpc_subnet.k8s_subnet.id
      "ingress.alb.yc.io/security-groups"       = module.k8s_sg.id
      "ingress.alb.yc.io/external-ipv4-address" = local.ip_v4_address
      "ingress.alb.yc.io/group-name"            = local.k8s_ingress_group
      "ingress.alb.yc.io/transport-security"    = "tls"
    }
  }

  spec {
    tls {
      hosts       = [local.domain_argo_cd]
      secret_name = "yc-certmgr-cert-id-${yandex_cm_certificate.k8s_argo_cd_cert.id}"
    }

    rule {
      host = local.domain_argo_cd
      http {
        path {
          backend {
            service {
              name = "argo-cd-np"
              port {
                name = "https"
              }
            }
          }

          path_type = "Prefix"
          path      = "/"
        }
      }
    }
  }
}

