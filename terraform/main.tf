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
            image = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/predictapool-backend:git-efd4566-amd64"
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
                    value = "postgresql+psycopg://${var.db_username}:${var.db_password}@${aws_db_instance.main.address}:5432/${var.db_name}"
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
        security_groups = [aws_security_group.alb.id]
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

    load_balancer {
        target_group_arn = aws_lb_target_group.backend.arn
        container_name = "backend"
        container_port = 8000
    }

    depends_on = [aws_lb_listener.https]
}

resource "aws_security_group" "alb" {
    name = "predictapool-alb-sg"
    description = "Allow HTTP/HTTPS access to ALB"
    vpc_id = data.aws_vpc.default.id

    ingress {
        from_port = 80
        to_port = 80
        protocol = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }
    
    ingress {
        from_port = 443
        to_port = 443
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

resource "aws_lb" "backend" {
    name = "predictapool-backend-alb"
    load_balancer_type = "application"
    subnets = data.aws_subnets.default.ids
    security_groups = [aws_security_group.alb.id]
}

resource "aws_lb_target_group" "backend" {
    name = "predictapool-backend-tg"
    port = 8000
    protocol = "HTTP"
    vpc_id = data.aws_vpc.default.id
    target_type = "ip"

    health_check {
        path = "/health"
        matcher = "200"
        interval = 30
        timeout = 5
        healthy_threshold = 2
        unhealthy_threshold = 2
    }
}

resource "aws_lb_listener" "http" {
    load_balancer_arn = aws_lb.backend.arn
    port = 80
    protocol = "HTTP"

    default_action {
        type = "redirect"
        
        redirect {
            port = "443"
            protocol = "HTTPS"
            status_code = "HTTP_301"
        }
    }
}

resource "aws_lb_listener" "https" {
    load_balancer_arn = aws_lb.backend.arn
    port = 443
    protocol = "HTTPS"
    ssl_policy = "ELBSecurityPolicy-2016-08"
    certificate_arn = aws_acm_certificate.api.arn

    default_action {
        type = "forward"
        target_group_arn = aws_lb_target_group.backend.arn
    }

    depends_on = [aws_acm_certificate_validation.api]
}

resource "aws_acm_certificate" "api" {
    domain_name = "api.predictapool.com"
    validation_method = "DNS"

    lifecycle {
        create_before_destroy = true
    }
}

resource "aws_route53_zone" "main" {
  name = "predictapool.com"
}

###########################################################################
#
#                               API
#
###########################################################################

resource "aws_route53_record" "api_cert_validation" {
    for_each = {
        for dvo in aws_acm_certificate.api.domain_validation_options :
        dvo.domain_name => {
            name = dvo.resource_record_name
            record = dvo.resource_record_value
            type = dvo.resource_record_type
        }
    }

    zone_id = aws_route53_zone.main.zone_id
    name = each.value.name
    type = each.value.type
    records = [each.value.record]
    ttl = 60
}

resource "aws_route53_record" "api" {
    zone_id = aws_route53_zone.main.zone_id
    name = "api.predictapool.com"
    type = "A"

    alias {
        name = aws_lb.backend.dns_name
        zone_id = aws_lb.backend.zone_id
        evaluate_target_health = true
    }
}

resource "aws_acm_certificate_validation" "api" {
    certificate_arn = aws_acm_certificate.api.arn
    validation_record_fqdns = [for r in aws_route53_record.api_cert_validation : r.fqdn]
}

###########################################################################
#
#                               DATABASE
#
###########################################################################

resource "aws_db_subnet_group" "main" {
    name = "predictapool-db-subnets"
    subnet_ids = data.aws_subnets.default.ids
}

resource "aws_security_group" "db" {
    name = "predictapool-db-sg"
    description = "Allow Postgres from backend"
    vpc_id = data.aws_vpc.default.id

    ingress {
        from_port = 5432
        to_port = 5432
        protocol = "tcp"
        security_groups = [aws_security_group.backend.id]
    }

    egress {
        from_port = 0
        to_port = 0
        protocol = -1
        cidr_blocks = ["0.0.0.0/0"]
    }
}

resource "aws_db_instance" "main" {
    identifier = "predictapool-db"
    engine = "postgres"
    engine_version = "15.10"
    instance_class = "db.t4g.micro"
    allocated_storage = 20
    max_allocated_storage = 100

    db_name = var.db_name
    username = var.db_username
    password = var.db_password

    db_subnet_group_name = aws_db_subnet_group.main.name
    vpc_security_group_ids = [aws_security_group.db.id]

    publicly_accessible = false
    skip_final_snapshot = true
    deletion_protection = false

    backup_retention_period = 7
}

variable "db_name" {
    type = string
}

variable "db_username" {
    type = string
}

variable "db_password" {
    type = string
    sensitive = true
}