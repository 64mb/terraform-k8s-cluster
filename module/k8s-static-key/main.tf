variable "cloud_id" {
  type = string
}

variable "folder_id" {
  type = string
}

variable "service_account_key_file" {
  type = string
}

variable "k8s_cluster_id" {
  type = string
}

data "external" "k8s_sa_token" {
  program = [
    "${path.module}/.k8s-static-key.sh",
    "${var.cloud_id}",
    "${var.folder_id}",
    "${var.service_account_key_file}",
    "${var.k8s_cluster_id}",
    "${path.module}",
  ]
}

output "token" {
  value     = data.external.k8s_sa_token.result.token
  sensitive = true
}
