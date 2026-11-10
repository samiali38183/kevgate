output "kms_key_arn" {
  description = "CMK used for ECR and the reports bucket."
  value       = aws_kms_key.this.arn
}

output "ecr_repository_url" {
  description = "ECR repository URL (null when enable_ecr is false)."
  value       = var.enable_ecr ? aws_ecr_repository.this[0].repository_url : null
}

output "github_ci_role_arn" {
  description = "Role ARN for aws-actions/configure-aws-credentials (role-to-assume)."
  value       = var.enable_ecr ? aws_iam_role.github_ci[0].arn : null
}

output "github_oidc_provider_arn" {
  description = "GitHub OIDC provider ARN in use."
  value       = local.github_oidc_provider_arn
}

output "reports_bucket" {
  description = "Bucket for exported reports."
  value       = aws_s3_bucket.reports.id
}

output "reports_prefix" {
  description = "Prefix the workload may write to."
  value       = var.reports_prefix
}

output "access_log_bucket" {
  description = "S3 server access log bucket."
  value       = aws_s3_bucket.access_logs.id
}

output "workload_role_arn" {
  description = "Role for the kevgate pods (EKS Pod Identity association target)."
  value       = aws_iam_role.workload.arn
}
