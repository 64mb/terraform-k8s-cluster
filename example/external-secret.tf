resource "kubernetes_manifest" "k8s_external_secret" {
  manifest = {
    "apiVersion" = "external-secrets.io/v1alpha1"
    "kind"       = "ExternalSecret"
    "metadata" = {
      "name"      = "external-secret"
      "namespace" = "external-secrets"
    }
    "spec" = {
      "refreshInterval" = "1h0m0s"
      "secretStoreRef" = {
        "name" = "secret-store"
        "kind" = "SecretStore"
      }
      "target" = {
        "name" = "k8s-secret"
      }
      "data" = [
        {
          "secretKey" = "password"
          "remoteRef" = {
            "key"      = "${yandex_lockbox_secret.secret.id}"
            "property" = "password"
          }
        }
      ]
    }
  }
}
