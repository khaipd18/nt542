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
  name = module.eks.eks_cluster_name
}

provider "kubernetes" {
  host                   = module.eks.eks_cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.eks_cluster_certificate_authority)
  token                  = data.aws_eks_cluster_auth.cluster_auth.token

  config_path = "~/.kube/config"
}
