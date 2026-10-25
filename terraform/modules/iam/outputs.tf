
output "eks_cluster_role_arn" {
  description = "ARN of the IAM role for the EKS cluster"
  value       = aws_iam_role.eks_cluster.arn
}

output "eks_node_group_role_arn" {
  description = "ARN of the IAM role for EKS node groups"
  value       = aws_iam_role.eks_node_group.arn
}

output "drift_detection_role_arn" {
  description = "ARN of the least-privilege IAM role used for scheduled drift detection (plan & CloudTrail lookup)"
  value       = aws_iam_role.drift_detection.arn
}

output "drift_remediation_role_arn" {
  description = "ARN of the IAM role used exclusively for approved remediation apply"
  value       = aws_iam_role.drift_remediation.arn
}

output "github_actions_role_arn" {
  description = "ARN of the IAM role for GitHub Actions (defaults to detection role)"
  value       = aws_iam_role.drift_detection.arn
}

output "github_oidc_provider_arn" {
  description = "ARN of the GitHub Actions OIDC identity provider"
  value       = aws_iam_openid_connect_provider.github_actions.arn
}
