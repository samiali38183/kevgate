variable "name" {
  description = "Base name for every resource (ECR repo, buckets, roles, KMS alias)."
  type        = string
  default     = "kevgate"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,30}[a-z0-9]$", var.name))
    error_message = "name must be 4-32 chars of lowercase letters, digits and hyphens, starting with a letter."
  }
}

variable "github_repository" {
  description = "GitHub repository (owner/name) allowed to assume the CI push role."
  type        = string
  default     = "samiali38183/kevgate"

  validation {
    condition     = can(regex("^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$", var.github_repository))
    error_message = "github_repository must look like owner/name."
  }
}

variable "github_branch" {
  description = "Only workflow runs on this branch can assume the CI push role."
  type        = string
  default     = "main"

  validation {
    condition     = can(regex("^[A-Za-z0-9._/-]+$", var.github_branch)) && !strcontains(var.github_branch, "*")
    error_message = "github_branch must be a literal branch name (no wildcards)."
  }
}

variable "create_github_oidc_provider" {
  description = "Create the token.actions.githubusercontent.com OIDC provider. Set false if the account already has one (only one per URL per account) and pass its ARN."
  type        = bool
  default     = true
}

variable "existing_github_oidc_provider_arn" {
  description = "ARN of an existing GitHub OIDC provider, used when create_github_oidc_provider is false."
  type        = string
  default     = null

  validation {
    condition     = var.existing_github_oidc_provider_arn == null || can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:oidc-provider/token\\.actions\\.githubusercontent\\.com$", var.existing_github_oidc_provider_arn))
    error_message = "existing_github_oidc_provider_arn must be the ARN of the token.actions.githubusercontent.com provider."
  }
}

variable "enable_ecr" {
  description = "Create the ECR repository and the CI push role. LocalStack Community has no ECR, so the LocalStack root sets this false."
  type        = bool
  default     = true
}

variable "ecr_untagged_expiry_days" {
  description = "Delete untagged images after this many days."
  type        = number
  default     = 7

  validation {
    condition     = var.ecr_untagged_expiry_days >= 1 && var.ecr_untagged_expiry_days <= 90
    error_message = "ecr_untagged_expiry_days must be between 1 and 90."
  }
}

variable "ecr_keep_tagged_images" {
  description = "Number of tagged images to keep."
  type        = number
  default     = 30

  validation {
    condition     = var.ecr_keep_tagged_images >= 5 && var.ecr_keep_tagged_images <= 500
    error_message = "ecr_keep_tagged_images must be between 5 and 500."
  }
}

variable "reports_prefix" {
  description = "Key prefix the workload may write exported reports to. Must end with a slash."
  type        = string
  default     = "reports/"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9/_-]*/$", var.reports_prefix))
    error_message = "reports_prefix must be a relative prefix ending in '/', for example reports/."
  }
}

variable "report_retention_days" {
  description = "Delete current report versions after this many days."
  type        = number
  default     = 365

  validation {
    condition     = var.report_retention_days >= 30
    error_message = "report_retention_days must be at least 30."
  }
}

variable "noncurrent_version_retention_days" {
  description = "Delete overwritten or deleted report versions after this many days."
  type        = number
  default     = 90

  validation {
    condition     = var.noncurrent_version_retention_days >= 1
    error_message = "noncurrent_version_retention_days must be at least 1."
  }
}

variable "access_log_retention_days" {
  description = "Delete S3 server access logs after this many days."
  type        = number
  default     = 90

  validation {
    condition     = var.access_log_retention_days >= 30
    error_message = "access_log_retention_days must be at least 30."
  }
}

variable "workload_namespace" {
  description = "Kubernetes namespace of the kevgate pods allowed to assume the workload role."
  type        = string
  default     = "kevgate"
}

variable "workload_service_account" {
  description = "Kubernetes service account of the kevgate pods allowed to assume the workload role."
  type        = string
  default     = "kevgate"
}

variable "eks_cluster_arn" {
  description = "Optional EKS cluster ARN. When set, the workload role trusts EKS Pod Identity only for this cluster."
  type        = string
  default     = null

  validation {
    condition     = var.eks_cluster_arn == null || can(regex("^arn:aws[a-z-]*:eks:[a-z0-9-]+:[0-9]{12}:cluster/.+$", var.eks_cluster_arn))
    error_message = "eks_cluster_arn must be an EKS cluster ARN."
  }
}

variable "kms_deletion_window_days" {
  description = "KMS key deletion waiting period."
  type        = number
  default     = 30

  validation {
    condition     = var.kms_deletion_window_days >= 7 && var.kms_deletion_window_days <= 30
    error_message = "kms_deletion_window_days must be between 7 and 30."
  }
}

variable "force_destroy_buckets" {
  description = "Allow terraform destroy to delete non-empty buckets. Only for throwaway environments (LocalStack CI)."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Extra tags for every resource."
  type        = map(string)
  default     = {}
}
