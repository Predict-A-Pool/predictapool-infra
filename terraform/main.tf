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

data "aws_vpc" "default" {
    default = true
}

data "aws_subnets" "default" {
    filter {
        name = "vpc-id"
        values = [data.aws_vpc.default.id]
    }
}

resource "aws_ecs_cluster" "main" {
    name = "predictapool-dev"
}

resource "aws_iam_role" "ecs_task_execution" {
    name = "predictapool-ecs-exec-role"

    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [{
            Effect = "Allow"
            Principal = {
                Service = "ecs-tasks.amazonaws.com"
            }
            Action = "sts:AssumeRole"
        }]
    })
}

resource "aws_iam_role_policy_attachment" "ecs_exec_policy" {
    role = aws_iam_role.ecs_task_execution.name
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_cloudwatch_log_group" "backend" {
    name = "/ecs/predictapool-backend"
    retention_in_days = 7
}

resource "aws_ecs_task_definition" "backend" {
    family = "predictapool-backend"
    requires_compatibilities = ["FARGATE"]
    network_mode = "awsvpc"
    cpu = "256"
    memory = "512"
    execution_role_arn = aws_iam_role.ecs_task_execution.arn

    container_definitions = jsonencode([
        {
            name = "backend"
            image = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/predictapool-backend:dev-amd64"
            essential = true,
            portMappings = [
                {
                    containerPort = 8000
                    protocol = "tcp"
                }
            ]
            environment = [
                {
                    name = "DATABASE_URL"
                    value = "REPLACE_LATER"
                }
            ]
            logConfiguration = {
                logDriver = "awslogs"
                options = {
                    awslogs-group = aws_cloudwatch_log_group.backend.name
                    awslogs-region = "eu-central-1"
                    awslogs-stream-prefix = "backend"
                }
            }
        }
    ])
}

resource "aws_security_group" "backend" {
    name = "predictapool-backend-sg"
    description = "Allow HTTP access to backend"
    vpc_id = data.aws_vpc.default.id

    ingress {
        from_port = 8000
        to_port = 8000
        protocol = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    egress {
        from_port = 0
        to_port = 0
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }
}

resource "aws_ecs_service" "backend" {
    name = "predictapool-backend"
    cluster = aws_ecs_cluster.main.id
    task_definition = aws_ecs_task_definition.backend.arn
    launch_type = "FARGATE"
    desired_count = 1

    network_configuration {
        subnets = data.aws_subnets.default.ids
        security_groups = [aws_security_group.backend.id]
        assign_public_ip = true
    }
}