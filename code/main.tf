resource "kubernetes_service" "fizzbuzz_service" {
  metadata {
    name = "fizzbuzz-service"
  }
  spec {
    selector = {
      app = "${kubernetes_deployment.fizzbuzz_deployment.spec.0.template.0.metadata.0.labels.app}"
    }
    port {
      port        = "8080"
      target_port = "8080"
    }

    type = "NodePort"
  }
}

resource "kubernetes_deployment" "fizzbuzz_deployment" {
  metadata {
    name = "fizzbuzz-blog"
  }

  spec {
    replicas = "2"

    selector {
      match_labels = {
        app = "fizzbuzz-blog"
      }
    }

    template {
      metadata {
        labels = {
          app = "fizzbuzz-blog"
        }
      }

      spec {
        container {
          name  = "fizzbuzz"
          image = "carlpaton/fizzpuzz:v1.0.0"
          port {
            container_port = "8080"
          }
        }
      }
    }
  }
}
