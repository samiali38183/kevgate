terraform {
  required_version = ">= 1.10.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.72"
    }
  }

  # Local state by default so `init -backend=false` and `validate` work without an AWS account.
  # For a real account, copy backend.s3.tf.example to backend.tf (see docs/DEPLOYMENT.md).
}
