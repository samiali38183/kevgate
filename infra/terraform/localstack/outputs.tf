output "reports_bucket" {
  description = "Reports bucket created in LocalStack."
  value       = module.kevgate.reports_bucket
}

output "workload_role_arn" {
  description = "Workload role ARN in LocalStack."
  value       = module.kevgate.workload_role_arn
}

output "kms_key_arn" {
  description = "KMS key ARN in LocalStack."
  value       = module.kevgate.kms_key_arn
}

output "github_oidc_provider_arn" {
  description = "GitHub OIDC provider ARN in LocalStack."
  value       = module.kevgate.github_oidc_provider_arn
}
