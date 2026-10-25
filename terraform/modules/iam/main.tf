
# IAM roles for EKS cluster, node groups, and GitHub
# Actions OIDC (no long-lived credentials)


data "aws_caller_identity" "current" {}

# EKS Cluster IAM Role 
resource "aws_iam_role" "eks_cluster" {
  name = "${var.project_name}-eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "${var.project_name}-eks-cluster-role"
  }
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster.name
}

#  EKS Node Group IAM Role 
resource "aws_iam_role" "eks_node_group" {
  name = "${var.project_name}-eks-node-group-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "${var.project_name}-eks-node-group-role"
  }
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_node_group.name
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_node_group.name
}

resource "aws_iam_role_policy_attachment" "eks_ecr_read_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_node_group.name
}

# GitHub Actions OIDC Identity Provider 
resource "aws_iam_openid_connect_provider" "github_actions" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = ["sts.amazonaws.com"]

  # GitHub's OIDC thumbprints (includes primary and backup rotated thumbprints)
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c5876884dc74a7e832508ba7d254924d52e5a6e"
  ]

  tags = {
    Name = "${var.project_name}-github-oidc"
  }
}

# IAM Role for Drift Detection (Read-Only + Plan + CloudTrail Lookup) 
resource "aws_iam_role" "drift_detection" {
  name = "${var.project_name}-drift-detection-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github_actions.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:${var.github_org}/${var.github_repo}:*",
            "repo:${lower(var.github_org)}/${var.github_repo}:*",
            "repo:${var.github_org}/${lower(var.github_repo)}:*",
            "repo:${lower(var.github_org)}/${lower(var.github_repo)}:*"
          ]
        }
      }
    }]
  })

  tags = {
    Name = "${var.project_name}-drift-detection-role"
    Role = "Detection"
  }
}

# Policy: read-only access for drift detection (plan only + CloudTrail) 
resource "aws_iam_policy" "drift_detection_plan" {
  name        = "${var.project_name}-drift-detection-plan-policy"
  description = "Allows Terraform plan (read-only) and CloudTrail lookup for drift detection"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          # EC2 / VPC (read)
          "ec2:Describe*",
          "ec2:Get*",
          # EKS (read)
          "eks:Describe*",
          "eks:List*",
          # IAM (read)
          "iam:Get*",
          "iam:List*",
          # CloudTrail correlation lookup
          "cloudtrail:LookupEvents",
          # S3 backend access (plan requires state lock & read)
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
          # DynamoDB state lock
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem",
          "dynamodb:DescribeTable"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "drift_detection_attach" {
  policy_arn = aws_iam_policy.drift_detection_plan.arn
  role       = aws_iam_role.drift_detection.name
}

# IAM Role for Drift Remediation (Apply / Write) 
resource "aws_iam_role" "drift_remediation" {
  name = "${var.project_name}-drift-remediation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github_actions.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:${var.github_org}/${var.github_repo}:*",
            "repo:${lower(var.github_org)}/${var.github_repo}:*",
            "repo:${var.github_org}/${lower(var.github_repo)}:*",
            "repo:${lower(var.github_org)}/${lower(var.github_repo)}:*"
          ]
        }
      }
    }]
  })

  tags = {
    Name = "${var.project_name}-drift-remediation-role"
    Role = "Remediation"
  }
}

# Policy: apply access (used only after approval gate) 
resource "aws_iam_policy" "drift_remediation_apply" {
  name        = "${var.project_name}-drift-remediation-apply-policy"
  description = "Allows Terraform apply for drift remediation (post-approval only)"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:*",
          "eks:*",
          "iam:*",
          "s3:*",
          "dynamodb:*",
          "elasticloadbalancing:*",
          "autoscaling:*",
          "cloudwatch:*",
          "logs:*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "drift_remediation_attach" {
  policy_arn = aws_iam_policy.drift_remediation_apply.arn
  role       = aws_iam_role.drift_remediation.name
}
