terraform {
  required_providers {
    yandex = {
      source  = "yandex-cloud/yandex"
      version = "0.89.0"
    }
    kubernetes = {
      source = "hashicorp/kubernetes"
    }
    helm = {
      source = "hashicorp/helm"
    }
  }
  backend "s3" {
    region = "us-east-1"

    skip_metadata_api_check     = true
    skip_credentials_validation = true
  }
  required_version = ">= 1.3.0"
}

provider "yandex" {
  cloud_id  = local.cloud_id
  folder_id = local.folder_id

  endpoint         = local.provider_endpoint
  storage_endpoint = local.storage_endpoint

  service_account_key_file = local.service_account_key_file
  storage_access_key       = local.sa_access_key
  storage_secret_key       = local.sa_secret_key
}

provider "kubernetes" {
  host                   = local.k8s_cluster_endpoint
  cluster_ca_certificate = local.k8s_cluster_ca_certificate

  token = local.k8s_token
}

provider "helm" {
  kubernetes {
    host                   = local.k8s_cluster_endpoint
    cluster_ca_certificate = local.k8s_cluster_ca_certificate

    token = local.k8s_token
  }

  registry {
    url      = "oci://cr.yandex"
    username = "json_key"
    password = file(local.service_account_key_file)
  }
}

