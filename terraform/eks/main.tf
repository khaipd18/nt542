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
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
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
while [ ! -f /etc/kubernetes/kubelet/config.json ]; do
  sleep 5
done

# Cài đặt jq nếu chưa có
sudo yum install -y jq

# --- CỐ TÌNH TẠO LỖI ĐỂ AUDIT (MỤC 3 CIS) ---

# ❌ LỖI 10 & 11: CIS 3.1.1, 3.1.2 - Sai quyền và chủ sở hữu kubeconfig
sudo chmod 777 /var/lib/kubelet/kubeconfig
sudo chown ec2-user:ec2-user /var/lib/kubelet/kubeconfig

# ❌ LỖI 12 & 13: CIS 3.1.3, 3.1.4 - Sai quyền và chủ sở hữu config.json
sudo chmod 777 /etc/kubernetes/kubelet/config.json
sudo chown ec2-user:ec2-user /etc/kubernetes/kubelet/config.json

# ❌ LỖI 14: CIS 3.2.1 - Bật xác thực ẩn danh
sudo jq '.authentication.anonymous.enabled = true' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json

# ❌ LỖI 15: CIS 3.2.2 - Cấp quyền AlwaysAllow
sudo jq '.authentication.webhook.enabled = false' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json
sudo jq '.authorization.mode = "AlwaysAllow"' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json

# ❌ LỖI 16: CIS 3.2.4 - Mở cổng Read-Only 10255
sudo jq '.readOnlyPort = 10255' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json

# ❌ LỖI 17: CIS 3.2.5 - Hủy bỏ Timeout của Streaming Connection
sudo jq '.streamingConnectionIdleTimeout = "0"' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json

# ❌ LỖI 18: CIS 3.2.6 - Cấm Kubelet quản lý iptables
sudo jq '.makeIPTablesUtilChains = false' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json

# ❌ LỖI 19: CIS 3.2.8 - Tắt xoay vòng chứng chỉ Client
sudo jq '.rotateCertificates = false' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json

# ❌ LỖI 20: CIS 3.2.9 - Tắt xoay vòng chứng chỉ Kubelet Server
sudo jq '.serverTLSBootstrap = false' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json
sudo jq '.featureGates.RotateKubeletServerCertificate = false' /etc/kubernetes/kubelet/config.json > /tmp/config.json && sudo mv /tmp/config.json /etc/kubernetes/kubelet/config.json

# Restart Kubelet để áp dụng cấu hình lỗi
sudo systemctl daemon-reload 
sudo systemctl restart kubelet.service 
sudo systemctl status kubelet -l 

--==MYBOUNDARY==--
EOF
  )
}

resource "aws_eks_node_group" "vuln_nodes" {
  cluster_name    = aws_eks_cluster.vuln_cluster.name
  node_group_name = "ctf-nodes"
  node_role_arn   = aws_iam_role.node_role.arn
  subnet_ids      = module.vpc.public_subnets
  instance_types  = ["t3.micro"]
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

# ----------- Output ------------
output "eks_cluster_name" {
  value = aws_eks_cluster.vuln_cluster.name
}

output "eks_cluster_endpoint" {
  value = aws_eks_cluster.vuln_cluster.endpoint
}

output "eks_cluster_certificate_authority" {
  value = aws_eks_cluster.vuln_cluster.certificate_authority[0].data
}

