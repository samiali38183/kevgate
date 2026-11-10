# Same module as the real AWS root, minus ECR (not in LocalStack Community) and with
# force_destroy so CI can apply and destroy in one job.
module "kevgate" {
  source = "../modules/kevgate"

  name                        = "kevgate"
  github_repository           = "samiali38183/kevgate"
  github_branch               = "main"
  create_github_oidc_provider = true
  enable_ecr                  = false
  force_destroy_buckets       = true
  kms_deletion_window_days    = 7
}
