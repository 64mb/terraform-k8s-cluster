locals {
  service_account_key_file        = "${path.module}/${var.service_account_key_file}"
  service_account_static_key_file = "${path.module}/${var.service_account_static_key_file}"
  config_file                     = "${path.module}/${var.config_file}"
}

data "external" "sa_json" {
  program = [
    "jq",
    "-f",
    "${local.service_account_static_key_file}"
  ]
}

data "external" "config_json" {
  program = [
    "jq",
    "-f",
    "${local.config_file}"
  ]
}

data "http" "ip" {
  url = "https://ipv4.icanhazip.com"
}

locals {
  ip      = chomp(data.http.ip.response_body)
  ip_cidr = "${chomp(data.http.ip.response_body)}/32"
}

resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

locals {
  k8s_version      = data.external.config_json.result.k8s_version
  k8s_node_user    = data.external.config_json.result.k8s_node_user
  k8s_node_ssh_key = tls_private_key.ssh_key.public_key_openssh
}

locals {
  provider_endpoint = data.external.sa_json.result.provider_endpoint
  storage_endpoint  = data.external.sa_json.result.storage_endpoint

  sa_access_key = data.external.sa_json.result.static_access_key
  sa_secret_key = data.external.sa_json.result.static_secret_key

  cloud_id   = data.external.config_json.result.cloud_id
  folder_id  = data.external.config_json.result.folder_id
  network_id = data.external.config_json.result.network_id

  domain = data.external.config_json.result.domain
}

