output "ecr_repository_url" {
  description = "Push target for release images."
  value       = module.kevgate.ecr_repository_url
}

output "github_ci_role_arn" {
  description = "role-to-assume for aws-actions/configure-aws-credentials."
  value       = module.kevgate.github_ci_role_arn
}

output "reports_bucket" {
  description = "Exported reports bucket."
  value       = module.kevgate.reports_bucket
}

output "workload_role_arn" {
  description = "Role for the kevgate pod identity association."
  value       = module.kevgate.workload_role_arn
}

output "kms_key_arn" {
  description = "Customer managed key."
  value       = module.kevgate.kms_key_arn
}
