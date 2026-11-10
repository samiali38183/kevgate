########################################################################################
# GitHub Actions OIDC: CI gets short-lived credentials, no long-lived access keys anywhere.
########################################################################################

resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_github_oidc_provider ? 1 : 0

  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  # No thumbprint_list: IAM validates GitHub's OIDC endpoint against its trusted CA store.
  tags = local.tags
}

data "aws_iam_policy_document" "github_ci_trust" {
  count = var.enable_ecr ? 1 : 0

  statement {
    sid     = "GitHubActionsMainBranchOnly"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Exact match, not StringLike: pull requests, forks, tags and other branches all present a
    # different sub claim and are refused.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:ref:refs/heads/${var.github_branch}"]
    }
  }
}

resource "aws_iam_role" "github_ci" {
  count = var.enable_ecr ? 1 : 0

  name                 = "${var.name}-github-ci-push"
  description          = "Assumed by GitHub Actions on ${var.github_repository}@${var.github_branch} to push images to ECR"
  assume_role_policy   = data.aws_iam_policy_document.github_ci_trust[0].json
  max_session_duration = 3600
  tags                 = local.tags
}

data "aws_iam_policy_document" "github_ci_push" {
  count = var.enable_ecr ? 1 : 0

  # GetAuthorizationToken is account-level; AWS does not support scoping it to a repository.
  # The token alone grants nothing: every repository action below is still checked.
  statement {
    sid       = "EcrLogin"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid    = "PushToKevgateRepositoryOnly"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:PutImage",
      # Read-back of the pushed manifest (digest lookup, signature attach).
      "ecr:BatchGetImage",
      "ecr:DescribeImages",
    ]
    resources = [aws_ecr_repository.this[0].arn]
  }
}

resource "aws_iam_role_policy" "github_ci_push" {
  count = var.enable_ecr ? 1 : 0

  name   = "ecr-push-${var.name}"
  role   = aws_iam_role.github_ci[0].id
  policy = data.aws_iam_policy_document.github_ci_push[0].json
}

########################################################################################
# Workload role: what the kevgate pod may do in AWS. Write reports, nothing else.
# Trusted via EKS Pod Identity, scoped to the kevgate namespace and service account through the
# session tags Pod Identity sets, and optionally to one cluster.
########################################################################################

data "aws_iam_policy_document" "workload_trust" {
  statement {
    sid     = "EksPodIdentity"
    effect  = "Allow"
    actions = ["sts:AssumeRole", "sts:TagSession"]

    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-namespace"
      values   = [var.workload_namespace]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-service-account"
      values   = [var.workload_service_account]
    }

    dynamic "condition" {
      for_each = var.eks_cluster_arn == null ? [] : [var.eks_cluster_arn]
      content {
        test     = "ArnEquals"
        variable = "aws:SourceArn"
        values   = [condition.value]
      }
    }
  }
}

resource "aws_iam_role" "workload" {
  name                 = "${var.name}-workload"
  description          = "kevgate pods: write exported reports under s3://${local.reports_bucket_name}/${var.reports_prefix}"
  assume_role_policy   = data.aws_iam_policy_document.workload_trust.json
  max_session_duration = 3600
  tags                 = local.tags
}

data "aws_iam_policy_document" "workload" {
  # PutObject only: the app cannot list, read back, overwrite-by-delete or touch other prefixes.
  statement {
    sid       = "WriteReports"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.reports.arn}/${var.reports_prefix}*"]
  }

  statement {
    sid       = "EncryptReportsWithBucketKey"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.this.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${local.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "workload" {
  name   = "reports-put-${var.name}"
  role   = aws_iam_role.workload.id
  policy = data.aws_iam_policy_document.workload.json
}
