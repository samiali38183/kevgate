variable "localstack_endpoint" {
  description = "LocalStack edge endpoint."
  type        = string
  default     = "http://localhost:4566"

  validation {
    condition     = can(regex("^https?://(localhost|127\\.0\\.0\\.1|localstack)(:[0-9]+)?$", var.localstack_endpoint))
    error_message = "localstack_endpoint must point at a local LocalStack instance."
  }
}
