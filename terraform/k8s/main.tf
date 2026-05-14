# ====================================================================
# PHẦN 4: KUBERNETES WORKLOADS & POLICIES (CIS MỤC 4)
# ====================================================================

# ❌ LỖI 22: CIS 4.1.5 - Sử dụng Service Account 'default' một cách chủ động (Gắn auto mount token)
resource "kubernetes_default_service_account" "vuln_sa" {
  metadata {
    namespace = "default"
  }
  automount_service_account_token = true
}

# ❌ LỖI 23: CIS 4.1.3 - Dùng ký tự đại diện (*) trong RBAC
# ❌ LỖI 24: CIS 4.1.2 - Gán quyền Get/List/Watch toàn bộ Secret
# ❌ LỖI 25: CIS 4.1.4 - Mở quyền tạo Pod
# ❌ LỖI 26: CIS 4.1.9 - Mở quyền tạo Persistent Volumes
# ❌ LỖI 27: CIS 4.1.10 - Mở quyền thao tác Proxy Sub-resource
# ❌ LỖI 28: CIS 4.1.11 - Mở quyền tạo Webhook Configurations
# ❌ LỖI 29: CIS 4.1.12 - Mở quyền tạo Token Service Account
resource "kubernetes_cluster_role" "vuln_cluster_role" {
  metadata { name = "excessive-wildcard-role" }
  rule {
    api_groups = ["*"]
    resources  = ["*"]
    verbs      = ["*"]
  }
}

# ❌ LỖI 30: CIS 4.1.1 - Gán quyền Cluster Admin cho đối tượng không cần thiết
# ❌ LỖI 31: CIS 4.1.8 - Lạm dụng quyền Bind, Impersonate, Escalate qua role hệ thống
resource "kubernetes_cluster_role_binding" "vuln_admin_binding" {
  metadata { name = "vuln-anonymous-admin" }
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

# ❌ LỖI 32: CIS 4.5.1, 4.5.2 - Đẩy toàn bộ Workload vào Default Namespace thay vì tạo Boundary
# ❌ LỖI 33: CIS 4.1.6 - Gắn Service Account Token trực tiếp vào Pod khi không cần thiết
# ❌ LỖI 34: CIS 4.2.1 - Chạy Container với đặc quyền Privileged
# ❌ LỖI 35: CIS 4.2.2 - Xâm phạm không gian host process ID (hostPID)
# ❌ LỖI 36: CIS 4.2.3 - Xâm phạm không gian host IPC (hostIPC)
# ❌ LỖI 37: CIS 4.2.4 - Xâm phạm không gian host network (hostNetwork)
# ❌ LỖI 38: CIS 4.2.5 - Bật cờ cho phép leo thang đặc quyền (allowPrivilegeEscalation)
# ❌ LỖI 39: CIS 4.4.1 - Ném thẳng Secret vào biến môi trường (Environment Variable)
resource "kubernetes_pod" "malicious_pod" {
  metadata {
    name      = "crypto-miner-breakout"
    namespace = "default"
  }
  spec {
    automount_service_account_token = true
    host_network                    = true
    host_pid                        = true
    host_ipc                        = true

    container {
      name    = "miner"
      image   = "ubuntu"
      command = ["sleep", "infinity"]

      security_context {
        privileged                 = true
        allow_privilege_escalation = true
        read_only_root_filesystem  = false
        run_as_user                = 0 # ❌ LỖI 40: Chạy với root thay vì non-root
      }

      env {
        name  = "AWS_SECRET_ACCESS_KEY"
        value = "AKIA-FAKE-SECRET-KEY-12345"
      }
    }
  }
}