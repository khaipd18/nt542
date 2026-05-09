terraform {
  required_providers {
    aws        = { source = "hashicorp/aws", version = "~> 5.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.0" }
  }
}

provider "aws" {
  region = "ap-southeast-1"
}

# Lấy token xác thực cho Kubernetes Provider
data "aws_eks_cluster_auth" "cluster_auth" {
  name = aws_eks_cluster.vuln_cluster.name
}

provider "kubernetes" {
  host                   = aws_eks_cluster.vuln_cluster.endpoint
  cluster_ca_certificate = base64decode(aws_eks_cluster.vuln_cluster.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.cluster_auth.token
}

# ====================================================================
# PHẦN 1: HẠ TẦNG MẠNG & AWS IAM (CIS MỤC 5)
# ====================================================================

# ❌ LỖI 1: CIS 5.4.3 - Chỉ sử dụng Public Subnet, Node phơi ra Internet
module "vpc" {
  source                  = "terraform-aws-modules/vpc/aws"
  version                 = "5.0.0"
  name                    = "ctf-vuln-vpc"
  cidr                    = "10.0.0.0/16"
  azs                     = ["ap-southeast-1a", "ap-southeast-1b"]
  public_subnets          = ["10.0.101.0/24", "10.0.102.0/24"]
  enable_nat_gateway      = false
  map_public_ip_on_launch = true
}

# ❌ LỖI 2: CIS 5.1.1 - Không quét lỗ hổng ảnh Container (scanOnPush = false)
resource "aws_ecr_repository" "vuln_repo" {
  name                 = "malicious-repo"
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration {
    scan_on_push = false
  }
}

# ❌ LỖI 3: CIS 5.1.2 - Mở toang quyền truy cập ECR cho tất cả mọi người (*)
resource "aws_ecr_repository_policy" "vuln_repo_policy" {
  repository = aws_ecr_repository.vuln_repo.name
  policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [{ Action = "ecr:*", Effect = "Allow", Principal = "*" }]
  })
}

# IAM Roles cơ sở
resource "aws_iam_role" "cluster_role" {
  name               = "vuln-cluster-role"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Action = "sts:AssumeRole", Effect = "Allow", Principal = { Service = "eks.amazonaws.com" } }] })
}

resource "aws_iam_role" "node_role" {
  name               = "vuln-node-role"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Action = "sts:AssumeRole", Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" } }] })
}

resource "aws_iam_role_policy_attachment" "cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.cluster_role.name
}

resource "aws_iam_role_policy_attachment" "node_p1" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.node_role.name
}

resource "aws_iam_role_policy_attachment" "node_p2" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.node_role.name
}



# ❌ LỖI 4: CIS 5.1.3 - Thay vì ReadOnly, gán luôn quyền Admin cho Node thao tác với ECR
resource "aws_iam_role_policy_attachment" "node_p3" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryFullAccess"
  role       = aws_iam_role.node_role.name
}

resource "aws_iam_role_policy_attachment" "node_p4" {
  policy_arn = aws_iam_role_policy_attachment.node_group_AmazonSSMManagedInstanceCore
  role       = aws_iam_role.node_role.name
}


# ====================================================================
# PHẦN 2: CONTROL PLANE & CLUSTER CONFIG (CIS MỤC 2 & 5)
# ====================================================================

resource "aws_eks_cluster" "vuln_cluster" {
  name     = "ctf-eks-arena"
  role_arn = aws_iam_role.cluster_role.arn

  vpc_config {
    subnet_ids = module.vpc.public_subnets
    # ❌ LỖI 5: CIS 5.4.1 - Endpoint Public mở cho 0.0.0.0/0
    # ❌ LỖI 6: CIS 5.4.2 - Endpoint Private bị tắt
    endpoint_public_access  = true
    endpoint_private_access = false
    public_access_cidrs     = ["0.0.0.0/0"]
  }

  # ❌ LỖI 7: CIS 2.1.1 - Tắt toàn bộ Audit Logs và Control Plane Logs
  enabled_cluster_log_types = []

  # ❌ LỖI 8: CIS 5.3.1 - Không cấu hình 'encryption_config' -> Secrets không được mã hóa bằng KMS CMK

  depends_on = [aws_iam_role_policy_attachment.cluster_policy]
}

# ❌ LỖI 9: CIS 4.3.1 & 5.4.4 - Ép CNI Addon không hỗ trợ Network Policies
resource "aws_eks_addon" "vpc_cni" {
  cluster_name         = aws_eks_cluster.vuln_cluster.name
  addon_name           = "vpc-cni"
  configuration_values = jsonencode({ "enableNetworkPolicy" : "false" })
}


# ====================================================================
# PHẦN 3: WORKER NODES LÕI OS & KUBELET (CIS MỤC 3)
# ====================================================================

resource "aws_launch_template" "vuln_lt" {
  name = "ctf-vuln-os"

  user_data = base64encode(<<-EOF
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="==MYBOUNDARY=="

--==MYBOUNDARY==
Content-Type: text/x-shellscript; charset="us-ascii"

#!/bin/bash
set -ex

# Đợi file cấu hình Kubelet được tạo ra bởi script bootstrap của AWS
while [ ! -f /etc/kubernetes/kubelet/kubelet-config.json ]; do
  sleep 5
done

# --- CỐ TÌNH TẠO LỖI ĐỂ AUDIT (MỤC 3 CIS) ---

# ❌ LỖI 10 & 11: CIS 3.1.1, 3.1.2 - Sai quyền và chủ sở hữu kubeconfig
chmod 777 /var/lib/kubelet/kubeconfig
chown ec2-user:ec2-user /var/lib/kubelet/kubeconfig

# ❌ LỖI 12 & 13: CIS 3.1.3, 3.1.4 - Sai quyền và chủ sở hữu kubelet-config.json
chmod 777 /etc/kubernetes/kubelet/kubelet-config.json
chown ec2-user:ec2-user /etc/kubernetes/kubelet/kubelet-config.json

# ❌ LỖI 14: CIS 3.2.1 - Bật xác thực ẩn danh
sed -i 's/"anonymous": {"enabled": false}/"anonymous": {"enabled": true}/g' /etc/kubernetes/kubelet/kubelet-config.json

# ❌ LỖI 15: CIS 3.2.2 - Cấp quyền AlwaysAllow
sed -i 's/"mode": "Webhook"/"mode": "AlwaysAllow"/g' /etc/kubernetes/kubelet/kubelet-config.json

# ❌ LỖI 16: CIS 3.2.4 - Mở cổng Read-Only 10255
if grep -q "readOnlyPort" /etc/kubernetes/kubelet/kubelet-config.json; then
  sed -i 's/"readOnlyPort": 0/"readOnlyPort": 10255/g' /etc/kubernetes/kubelet/kubelet-config.json
else
  sed -i '/"kind": "KubeletConfiguration"/a \  "readOnlyPort": 10255,' /etc/kubernetes/kubelet/kubelet-config.json
fi

# ❌ LỖI 17-21: CIS 3.2.5 -> 3.2.9 - Tắt các tính năng bảo mật quan trọng
# Chèn các tham số xấu vào file config chính
sed -i '/"kind": "KubeletConfiguration"/a \  "streamingConnectionIdleTimeout": "0",\n  "makeIPTablesUtilChains": false,\n  "eventRecordQPS": 0,\n  "rotateCertificates": false,' /etc/kubernetes/kubelet/kubelet-config.json

# LỖI 21: Vô hiệu hóa xoay vòng chứng chỉ server (FeatureGate)
sed -i 's/"RotateKubeletServerCertificate": true/"RotateKubeletServerCertificate": false/g' /etc/kubernetes/kubelet/kubelet-config.json

# Restart Kubelet để áp dụng cấu hình lỗi
systemctl restart kubelet

--==MYBOUNDARY==--
EOF
  )
}

resource "aws_eks_node_group" "vuln_nodes" {
  cluster_name    = aws_eks_cluster.vuln_cluster.name
  node_group_name = "ctf-nodes"
  node_role_arn   = aws_iam_role.node_role.arn
  subnet_ids      = module.vpc.public_subnets
  instance_types  = ["t3.medium"]
  scaling_config {
    desired_size = 2
    max_size     = 2
    min_size     = 1
  }
  launch_template {
    name    = aws_launch_template.vuln_lt.name
    version = aws_launch_template.vuln_lt.latest_version
  }
}


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
  depends_on = [aws_eks_node_group.vuln_nodes]
}