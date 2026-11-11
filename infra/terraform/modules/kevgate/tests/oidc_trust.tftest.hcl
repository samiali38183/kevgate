# Regression test for the GitHub Actions OIDC trust policy. Run with `terraform test` in this
# directory (CI: .github/workflows/terraform.yml, job "oidc-trust").
#
# Scanners (validate, tflint, checkov, trivy) all accept a trust policy that was weakened to
# StringLike with a wildcard sub, so this test pins the exact shape instead: one Allow statement,
# only StringEquals conditions, aud = sts.amazonaws.com, and sub equal to the single string
# repo:<owner/name>:ref:refs/heads/<branch> with no wildcard characters.
#
# mock_provider means no AWS account or credentials are needed: the assertions read the policy
# document's own inputs (the statement and conditions written in iam.tf), which a mock leaves intact.

mock_provider "aws" {
  # Computed values the rest of the module needs in order to plan. The `json` attribute of every
  # policy document is mocked to a minimal valid document; the assertions below do not use it.
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_data "aws_region" {
    defaults = {
      region = "us-east-1"
    }
  }
}

run "trust_is_exact_main_branch_only" {
  command = plan

  variables {
    github_repository = "samiali38183/kevgate"
    github_branch     = "main"
    enable_ecr        = true
  }

  assert {
    condition     = length(data.aws_iam_policy_document.github_ci_trust[0].statement) == 1
    error_message = "the CI trust policy must have exactly one statement"
  }

  assert {
    condition     = data.aws_iam_policy_document.github_ci_trust[0].statement[0].effect == "Allow"
    error_message = "the CI trust statement must be an Allow"
  }

  assert {
    condition     = data.aws_iam_policy_document.github_ci_trust[0].statement[0].actions == toset(["sts:AssumeRoleWithWebIdentity"])
    error_message = "the CI trust statement must allow only sts:AssumeRoleWithWebIdentity"
  }

  assert {
    condition     = length(data.aws_iam_policy_document.github_ci_trust[0].statement[0].condition) == 2
    error_message = "the CI trust statement must have exactly the aud and sub conditions"
  }

  assert {
    condition = alltrue([
      for c in data.aws_iam_policy_document.github_ci_trust[0].statement[0].condition : c.test == "StringEquals"
    ])
    error_message = "every OIDC trust condition must use StringEquals (no StringLike, no ForAnyValue)"
  }

  assert {
    condition = one(flatten([
      for c in data.aws_iam_policy_document.github_ci_trust[0].statement[0].condition : tolist(c.values)
      if c.variable == "token.actions.githubusercontent.com:aud"
    ])) == "sts.amazonaws.com"
    error_message = "aud must be exactly sts.amazonaws.com"
  }

  assert {
    condition = one(flatten([
      for c in data.aws_iam_policy_document.github_ci_trust[0].statement[0].condition : tolist(c.values)
      if c.variable == "token.actions.githubusercontent.com:sub"
    ])) == "repo:samiali38183/kevgate:ref:refs/heads/main"
    error_message = "sub must be exactly repo:samiali38183/kevgate:ref:refs/heads/main (one value, no wildcard)"
  }

  assert {
    condition = !anytrue(flatten([
      for c in data.aws_iam_policy_document.github_ci_trust[0].statement[0].condition : [
        for v in c.values : can(regex("[*?]", v))
      ]
    ]))
    error_message = "no OIDC trust condition value may contain * or ?"
  }
}

run "sub_follows_repository_and_branch_variables" {
  command = plan

  variables {
    github_repository = "someone/else"
    github_branch     = "release"
    enable_ecr        = true
  }

  assert {
    condition = one(flatten([
      for c in data.aws_iam_policy_document.github_ci_trust[0].statement[0].condition : tolist(c.values)
      if c.variable == "token.actions.githubusercontent.com:sub"
    ])) == "repo:someone/else:ref:refs/heads/release"
    error_message = "sub must be built from github_repository and github_branch only"
  }
}

run "wildcard_branch_is_rejected_by_validation" {
  command = plan

  variables {
    github_branch = "*"
    enable_ecr    = true
  }

  expect_failures = [var.github_branch]
}

run "wildcard_repository_is_rejected_by_validation" {
  command = plan

  variables {
    github_repository = "samiali38183/*"
    enable_ecr        = true
  }

  expect_failures = [var.github_repository]
}
