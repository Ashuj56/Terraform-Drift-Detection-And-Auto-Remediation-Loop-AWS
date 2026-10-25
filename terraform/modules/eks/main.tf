# EKS cluster + managed node group

# EKS Cluster 
resource "aws_eks_cluster" "main" {
  name     = "${var.project_name}-cluster"
  role_arn = var.eks_cluster_role_arn
  version  = var.cluster_version

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    security_group_ids      = [var.eks_cluster_sg_id]
    endpoint_public_access  = true
    endpoint_private_access = true
    public_access_cidrs     = ["0.0.0.0/0"] # Restrict in production
  }

  access_config {
    authentication_mode                         = "API_AND_CONFIG_MAP" # Allows both configmap and modern access entries
    bootstrap_cluster_creator_admin_permissions = true
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  tags = {
    Name = "${var.project_name}-cluster"
  }

  depends_on = [var.eks_cluster_role_arn]
}

# EKS Managed Node Group 
resource "aws_eks_node_group" "main" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "${var.project_name}-node-group"
  node_role_arn   = var.eks_node_group_role_arn
  subnet_ids      = var.private_subnet_ids

  instance_types = [var.node_instance_type]

  scaling_config {
    desired_size = var.desired_nodes
    min_size     = var.min_nodes
    max_size     = var.max_nodes
  }

  update_config {
    max_unavailable = 1
  }

  # Allow rolling updates when AMI changes
  lifecycle {
    ignore_changes = [scaling_config[0].desired_size]
  }

  tags = {
    Name = "${var.project_name}-node-group"
  }
}

# aws-auth ConfigMap (allow nodes to join cluster) 
resource "aws_eks_access_entry" "nodes" {
  cluster_name      = aws_eks_cluster.main.name
  principal_arn     = var.eks_node_group_role_arn
  type              = "EC2_LINUX"
}
