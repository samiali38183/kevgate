provider "aws" {
  region = var.region

  # Refuse to run against any account other than the one named in tfvars.
  allowed_account_ids = var.allowed_account_ids

  default_tags {
    tags = {
      Project     = "kevgate"
      Environment = var.environment
      ManagedBy   = "terraform"
      Repository  = var.github_repository
    }
  }
}
