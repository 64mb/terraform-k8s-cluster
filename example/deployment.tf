resource "kubernetes_deployment" "nginx" {
  metadata {
    name = "scalable-nginx"
    labels = {
      app = "app-nginx"
    }
  }

  spec {
    replicas = 1
    selector {
      match_labels = {
        app = "app-nginx"
      }
    }
    template {
      metadata {
        labels = {
          app = "app-nginx"
        }
      }
      spec {
        container {
          image = "nginx:1.7.8"
          name  = "app-nginx"

          port {
            container_port = 80
          }

          resources {
            limits = {
              cpu    = "0.5"
              memory = "512Mi"
            }
            requests = {
              cpu    = "250m"
              memory = "50Mi"
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
