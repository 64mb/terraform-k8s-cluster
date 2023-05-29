
resource "kubernetes_service" "nginx_service" {
  metadata {
    name = "nginx-np"
  }
  spec {
    selector = {
      app = "app-nginx"
    }
    # session_affinity = "ClientIP"
    port {
      name        = "http"
      port        = 8080
      target_port = 80
      protocol    = "TCP"
      node_port   = 30081
    }
    type = "NodePort"
  }

  depends_on = [
    local.k8s_token,
  ]
}
