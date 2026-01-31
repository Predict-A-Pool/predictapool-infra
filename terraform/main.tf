variable "aws_region" {
    type = string
    description = "AWS region"
    default = "eu-central-1"
}

data "aws_caller_identity" "current" {}