variable "aws_region" {
    type = string
    description = "AWS region"
    default = "eu-central-1"
}

data "aws_caller_identity" "current" {}

resource "aws_ecr_repository" "backend" {
    name = "predictapool-backend"
    image_tag_mutability = "IMMUTABLE"

    image_scanning_configuration {
        scan_on_push = true
    }
}

resource "aws_ecr_repository" "frontend" {
    name = "predictapool-frontend"
    image_tag_mutability = "IMMUTABLE"

    image_scanning_configuration {
        scan_on_push = true
    }
}

output "backend_ecr_url" {
    value = aws_ecr_repository.backend.repository_url
}

output "frontend_ecr_url" {
    value = aws_ecr_repository.frontend.repository_url
}