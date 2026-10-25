

output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "eks_cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  description = "EKS cluster API endpoint"
  value       = module.eks.cluster_endpoint
  sensitive   = true
}

output "drift_detection_role_arn" {
  description = "IAM Role ARN for scheduled drift detection (plan & CloudTrail lookup) — set as AWS_DRIFT_DETECTION_ROLE_ARN secret"
  value       = module.iam.drift_detection_role_arn
}

output "drift_remediation_role_arn" {
  description = "IAM Role ARN for approved remediation apply — set as AWS_DRIFT_REMEDIATION_ROLE_ARN secret"
  value       = module.iam.drift_remediation_role_arn
}

output "github_actions_role_arn" {
  description = "IAM Role ARN for GitHub Actions (backward compatible alias)"
  value       = module.iam.drift_detection_role_arn
}
