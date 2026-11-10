# Points the AWS provider at LocalStack (CI service container on localhost:4566).
# The credentials are LocalStack's documented dummy values, not secrets.
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test" # checkov:skip=CKV_AWS_41: LocalStack dummy credential, not a secret
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  s3_use_path_style           = true

  endpoints {
    iam = var.localstack_endpoint
    kms = var.localstack_endpoint
    s3  = var.localstack_endpoint
    # The provider lists bucket tags through S3 Control; without this it goes to real AWS and gets 403.
    s3control = var.localstack_endpoint
    sts       = var.localstack_endpoint
  }

  default_tags {
    tags = {
      Project     = "kevgate"
      Environment = "localstack"
      ManagedBy   = "terraform"
    }
  }
}
