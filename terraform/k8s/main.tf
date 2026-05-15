# terraform/k8s/main.tf
# ====================================================================
# CIS AMAZON EKS BENCHMARK - SECTION 4 VULNERABLE LAB
# Mục tiêu:
# Tạo môi trường cố tình VI PHẠM benchmark mục 4
# để phục vụ AUDIT và REMEDIATION.
# ====================================================================

# ====================================================================
# 4.1 RBAC and Service Accounts
# ====================================================================

# --------------------------------------------------------------------
# ❌ CIS 4.1.5
# Default Service Account actively used
# --------------------------------------------------------------------
resource "kubernetes_default_service_account" "vuln_default_sa" {
  metadata {
    namespace = "default"
  }

  automount_service_account_token = true
}

# --------------------------------------------------------------------
# ❌ CIS 4.1.3
# Wildcard RBAC
# ❌ CIS 4.1.2
# Secret access
# ❌ CIS 4.1.4
# Pod creation
# ❌ CIS 4.1.9
# PersistentVolume creation
# ❌ CIS 4.1.10
# nodes/proxy access
# ❌ CIS 4.1.11
# Webhook configuration access
# ❌ CIS 4.1.12
# ServiceAccount token creation
# ❌ CIS 4.1.8
# bind/escalate/impersonate
# --------------------------------------------------------------------
resource "kubernetes_cluster_role" "dangerous_cluster_role" {
  metadata {
    name = "dangerous-cluster-role"
  }

  rule {
    api_groups = ["*"]
    resources  = ["*"]
    verbs      = ["*"]
  }

  rule {
    api_groups = [""]
    resources  = ["secrets"]
    verbs      = ["get", "list", "watch"]
  }

  rule {
    api_groups = [""]
    resources  = ["pods"]
    verbs      = ["create"]
  }

  rule {
    api_groups = [""]
    resources  = ["persistentvolumes"]
    verbs      = ["create"]
  }

  rule {
    api_groups = [""]
    resources  = ["nodes/proxy"]
    verbs      = ["get", "create"]
  }

  rule {
    api_groups = ["admissionregistration.k8s.io"]
    resources = [
      "validatingwebhookconfigurations",
      "mutatingwebhookconfigurations"
    ]
    verbs = ["create", "update", "patch", "delete"]
  }

  rule {
    api_groups = [""]
    resources  = ["serviceaccounts/token"]
    verbs      = ["create"]
  }

  rule {
    api_groups = ["rbac.authorization.k8s.io"]
    resources  = ["roles", "clusterroles"]
    verbs      = ["bind", "escalate", "impersonate"]
  }
}

# --------------------------------------------------------------------
# ❌ CIS 4.1.1
# Cluster-admin granted unnecessarily
# ❌ CIS 4.1.8
# Bind/Impersonate/Escalate abuse
# --------------------------------------------------------------------
resource "kubernetes_cluster_role_binding" "anonymous_cluster_admin" {
  metadata {
    name = "anonymous-cluster-admin"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "cluster-admin"
  }

  subject {
    kind      = "Group"
    name      = "system:unauthenticated"
    api_group = "rbac.authorization.k8s.io"
  }
}

# --------------------------------------------------------------------
# ❌ CIS 4.1.2
# Secret exposed
# ❌ CIS 4.4.1
# Secret stored in ENV variable
# --------------------------------------------------------------------
resource "kubernetes_secret" "plaintext_secret" {
  metadata {
    name      = "plaintext-secret"
    namespace = "default"
  }

  data = {
    password = "SuperSecretPassword123"
    api_key  = "AKIA-FAKE-ACCESS-KEY"
  }

  type = "Opaque"
}

# ====================================================================
# 4.2 Pod Security Standards
# ====================================================================

# --------------------------------------------------------------------
# ❌ CIS 4.5.1
# No namespace boundary
# ❌ CIS 4.5.2
# Workload deployed in default namespace
# ❌ CIS 4.1.6
# ServiceAccount token mounted unnecessarily
# ❌ CIS 4.2.1
# Privileged container
# ❌ CIS 4.2.2
# hostPID enabled
# ❌ CIS 4.2.3
# hostIPC enabled
# ❌ CIS 4.2.4
# hostNetwork enabled
# ❌ CIS 4.2.5
# allowPrivilegeEscalation enabled
# ❌ Additional
# Run as root
# --------------------------------------------------------------------
resource "kubernetes_pod" "privileged_breakout_pod" {
  metadata {
    name      = "privileged-breakout-pod"
    namespace = "default"

    labels = {
      app = "breakout"
    }
  }

  spec {
    service_account_name            = "default"
    automount_service_account_token = true

    host_network = true
    host_pid     = true
    host_ipc     = true

    container {
      name  = "attacker"
      image = "ubuntu:latest"

      command = [
        "sleep",
        "infinity"
      ]

      security_context {
        privileged                 = true
        allow_privilege_escalation = true
        read_only_root_filesystem  = false
        run_as_non_root            = false
        run_as_user                = 0
      }

      env {
        name = "AWS_SECRET_ACCESS_KEY"

        value_from {
          secret_key_ref {
            name = kubernetes_secret.plaintext_secret.metadata[0].name
            key  = "api_key"
          }
        }
      }

      env {
        name = "DB_PASSWORD"

        value_from {
          secret_key_ref {
            name = kubernetes_secret.plaintext_secret.metadata[0].name
            key  = "password"
          }
        }
      }
    }
  }
}

# ====================================================================
# 4.3 CNI Plugin & Network Policies
# ====================================================================

# --------------------------------------------------------------------
# ❌ CIS 4.3.2
# No NetworkPolicy created
# --------------------------------------------------------------------

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

# ====================================================================
# 4.4 Secrets Management
# ====================================================================

# --------------------------------------------------------------------
# ❌ CIS 4.4.1
# Secret injected via ENV instead of mounted file
# --------------------------------------------------------------------
resource "kubernetes_deployment" "env_secret_app" {
  metadata {
    name      = "env-secret-app"
    namespace = "default"
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "env-secret-app"
      }
    }

    template {
      metadata {
        labels = {
          app = "env-secret-app"
        }
      }

      spec {
        container {
          name  = "app"
          image = "nginx"

          env {
            name = "PASSWORD"

            value_from {
              secret_key_ref {
                name = kubernetes_secret.plaintext_secret.metadata[0].name
                key  = "password"
              }
            }
          }
        }
      }
    }
  }
}

# --------------------------------------------------------------------
# ❌ CIS 4.4.2
# No external secret manager used
# --------------------------------------------------------------------

# Không sử dụng:
# - AWS Secrets Manager
# - External Secrets Operator
# - Hashicorp Vault
# - CSI Secret Store
#
# Chỉ dùng Kubernetes Secret nội bộ.

# ====================================================================
# 4.5 General Policies
# ====================================================================

# --------------------------------------------------------------------
# ❌ CIS 4.5.1
# Administrative boundary missing
# ❌ CIS 4.5.2
# Using default namespace
# --------------------------------------------------------------------
resource "kubernetes_deployment" "default_namespace_frontend" {
  metadata {
    name      = "frontend-app"
    namespace = "default"
  }

  spec {
    replicas = 0

    selector {
      match_labels = {
        app = "frontend"
      }
    }

    template {
      metadata {
        labels = {
          app = "frontend"
        }
      }

      spec {
        container {
          name  = "frontend"
          image = "nginx"
        }
      }
    }
  }
}

resource "kubernetes_deployment" "default_namespace_backend" {
  metadata {
    name      = "backend-app"
    namespace = "default"
  }

  spec {
    replicas = 0

    selector {
      match_labels = {
        app = "backend"
      }
    }

    template {
      metadata {
        labels = {
          app = "backend"
        }
      }

      spec {
        container {
          name  = "backend"
          image = "nginx"
        }
      }
    }
  }
}
resource "kubernetes_cluster_role_binding" "dangerous_cluster_role_binding" {
  metadata {
    name = "dangerous-cluster-role-binding"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.dangerous_cluster_role.metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = "default"
    namespace = "default"
    api_group = ""
  }
}