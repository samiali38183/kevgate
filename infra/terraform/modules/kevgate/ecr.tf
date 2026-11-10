########################################################################################
# ECR: private image repository. Immutable tags, scan on push, KMS encryption.
########################################################################################

resource "aws_ecr_repository" "this" {
  count = var.enable_ecr ? 1 : 0

  name                 = var.name
  image_tag_mutability = "IMMUTABLE"
  force_delete         = var.force_destroy_buckets

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.this.arn
  }

  tags = local.tags
}

resource "aws_ecr_lifecycle_policy" "this" {
  count = var.enable_ecr ? 1 : 0

  repository = aws_ecr_repository.this[0].name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = var.ecr_untagged_expiry_days
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep the most recent tagged images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = var.ecr_keep_tagged_images
        }
        action = { type = "expire" }
      },
    ]
  })
}

# Only the CI role and the account itself may touch the repository, even if a broader IAM
# policy is attached somewhere else by mistake.
data "aws_iam_policy_document" "ecr_repository" {
  count = var.enable_ecr ? 1 : 0

  statement {
    sid    = "DenyPushExceptCiRole"
    effect = "Deny"
    actions = [
      "ecr:PutImage",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.github_ci[0].arn]
    }
  }
}

resource "aws_ecr_repository_policy" "this" {
  count = var.enable_ecr ? 1 : 0

  repository = aws_ecr_repository.this[0].name
  policy     = data.aws_iam_policy_document.ecr_repository[0].json
}
