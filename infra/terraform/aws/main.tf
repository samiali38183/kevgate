module "kevgate" {
  source = "../modules/kevgate"

  name                              = "kevgate"
  github_repository                 = var.github_repository
  github_branch                     = "main"
  create_github_oidc_provider       = var.create_github_oidc_provider
  existing_github_oidc_provider_arn = var.existing_github_oidc_provider_arn
  eks_cluster_arn                   = var.eks_cluster_arn
  enable_ecr                        = true
  force_destroy_buckets             = false
}
