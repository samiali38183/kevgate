data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region

  reports_bucket_name    = "${var.name}-reports-${local.account_id}-${local.region}"
  access_log_bucket_name = "${var.name}-s3-access-logs-${local.account_id}-${local.region}"

  github_oidc_provider_arn = var.create_github_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : var.existing_github_oidc_provider_arn

  tags = merge(
    {
      Project   = "kevgate"
      ManagedBy = "terraform"
    },
    var.tags,
  )
}

check "github_oidc_provider_configured" {
  assert {
    condition     = !var.enable_ecr || var.create_github_oidc_provider || var.existing_github_oidc_provider_arn != null
    error_message = "enable_ecr needs a GitHub OIDC provider: set create_github_oidc_provider = true or pass existing_github_oidc_provider_arn."
  }
}

########################################################################################
# KMS: one customer managed key for the image repository and the reports bucket.
########################################################################################

data "aws_iam_policy_document" "kms" {
  #checkov:skip=CKV_AWS_109: a KMS key policy applies to its own key, so resources = ["*"] means "this key"; the root-administration statement is what keeps the key manageable
  #checkov:skip=CKV_AWS_111: same as above, constrained to the one key the policy is attached to
  #checkov:skip=CKV_AWS_356: same as above, "*" in a key policy cannot reference any other resource
  # Account root keeps administrative control so the key can never become unmanageable, and IAM
  # policies decide which principals may use it (the workload role gets GenerateDataKey/Decrypt
  # via S3 only, see iam.tf). This is the default key policy, written out so it is reviewed.
  statement {
    sid       = "AccountAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "this" {
  description             = "${var.name}: ECR images and exported reports"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = var.kms_deletion_window_days
  policy                  = data.aws_iam_policy_document.kms.json
  tags                    = local.tags
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.this.key_id
}
