# CIS AMAZON EKS BENCHMARK - SECTION 4

# 4.1 RBAC and Service Accounts

# ❌ CIS 4.1.3
# Wildcard RBAC

resource "kubernetes_cluster_role" "dangerous_cluster_role" {
  metadata {
    name = "dangerous-cluster-role"
  }

  rule {
    api_groups = ["*"]
    resources  = ["*"]
    verbs      = ["*"]
  }
}

# 4.2 Pod Security Standards

# ❌ CIS 4.2.1
# Privileged container

# ❌ CIS 4.2.4
# hostNetwork enabled

resource "kubernetes_pod" "privileged_breakout_pod" {
  metadata {
    name      = "privileged-breakout-pod"
    namespace = "default"
  }
  
  spec {
    host_network = true

    container {
      name  = "attacker"
      image = "ubuntu"

      command = [
        "sleep",
        "infinity"
      ]

      security_context {
        privileged = true
      }
    }
  }
}

# 4.3 CNI Plugin & Network Policies

# ❌ CIS 4.3.2
# Namespace has no NetworkPolicy

resource "kubernetes_namespace" "open_namespace" {
  metadata {
    name = "open-namespace"
  }
}

resource "kubernetes_pod" "no_network_policy_pod" {
  metadata {
    name      = "unrestricted-pod"
    namespace = kubernetes_namespace.open_namespace.metadata[0].name
  }

  spec {
    container {
      name  = "nginx"
      image = "nginx"
    }
  }
}

  
# NOTE:
# CIS 4.3.1 phụ thuộc EKS/CNI layer.
# Không cấu hình NetworkPolicy enforcement tương ứng.
# Nếu dùng AWS VPC CNI mặc định mà không enable policy engine
# thì sẽ vi phạm 4.3.1.

# 4.5 Multi-Tenancy
# --------------------------------------------------------------------

# ❌ CIS 4.5.2
# Default namespace is used for workloads

resource "kubernetes_deployment" "default_namespace_app" {

  metadata {
    name      = "default-namespace-app"
    namespace = "default"
  }

  spec {

    replicas = 1

    selector {
      match_labels = {
        app = "default-app"
      }
    }

    template {

      metadata {
        labels = {
          app = "default-app"
        }
      }

      spec {

        container {
          name  = "nginx"
          image = "nginx"
        }
      }
    }
  }
}