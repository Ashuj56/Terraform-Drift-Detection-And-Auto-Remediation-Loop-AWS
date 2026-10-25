
# Root module: wires all child modules together

# VPC 
module "vpc" {
  source = "./modules/vpc"

  project_name         = var.project_name
  vpc_cidr             = var.vpc_cidr
  public_subnet_cidrs  = var.public_subnet_cidrs
  private_subnet_cidrs = var.private_subnet_cidrs
  availability_zones   = var.availability_zones
}

# Security Groups
module "security_groups" {
  source = "./modules/security_groups"

  project_name = var.project_name
  vpc_id       = module.vpc.vpc_id
}

# IAM
module "iam" {
  source = "./modules/iam"

  project_name = var.project_name
  github_org   = "Ashuj56"  
  github_repo  = "Terraform-Drift-Detection-And-Auto-Remediation-Loop-AWS"
}

# EKS
module "eks" {
  source = "./modules/eks"

  project_name            = var.project_name
  cluster_version         = var.eks_cluster_version
  eks_cluster_role_arn    = module.iam.eks_cluster_role_arn
  eks_node_group_role_arn = module.iam.eks_node_group_role_arn
  private_subnet_ids      = module.vpc.private_subnet_ids
  eks_cluster_sg_id       = module.security_groups.eks_cluster_sg_id
  node_instance_type      = var.eks_node_instance_type
  desired_nodes           = var.eks_desired_nodes
  min_nodes               = var.eks_min_nodes
  max_nodes               = var.eks_max_nodes
}
