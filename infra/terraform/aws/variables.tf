variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]$", var.region))
    error_message = "region must be an AWS region name such as us-east-1."
  }
}

variable "allowed_account_ids" {
  description = "AWS account IDs this configuration may touch. Required, so a wrong profile fails fast."
  type        = list(string)

  validation {
    condition     = length(var.allowed_account_ids) > 0 && alltrue([for id in var.allowed_account_ids : can(regex("^[0-9]{12}$", id))])
    error_message = "allowed_account_ids must contain at least one 12-digit account ID."
  }
}

variable "environment" {
  description = "Environment name used in tags."
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "github_repository" {
  description = "owner/name of the repository whose main branch may push images."
  type        = string
  default     = "samiali38183/kevgate"
}

variable "create_github_oidc_provider" {
  description = "Create the GitHub OIDC provider (false if the account already has one)."
  type        = bool
  default     = true
}

variable "existing_github_oidc_provider_arn" {
  description = "Existing GitHub OIDC provider ARN when create_github_oidc_provider is false."
  type        = string
  default     = null
}

variable "eks_cluster_arn" {
  description = "Optional EKS cluster ARN to pin the workload role trust to."
  type        = string
  default     = null
}
