###########################################################################
#
#                           VARIABLES
#
###########################################################################

variable "aws_region" {
    type = string
    description = "AWS region"
    default = "eu-central-1"
}

variable "root_domain" {
  type        = string
  description = "Root domain name (e.g. predictapool.com)"
}

variable "api_subdomain" {
  type        = string
  default     = "api"
  description = "API subdomain prefix"
}

variable "app_subdomain" {
    type = string
    default = "app"
    description = "APP subdomain prefix"
}

###########################################################################
#
#                           MAIN
#
###########################################################################

data "aws_caller_identity" "current" {}

provider "aws" {
    alias = "us_east_1"
    region = "us-east-1"
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

###########################################################################
#
#                           FRONTEND
#
###########################################################################

output "frontend_ecr_url" {
    value = aws_ecr_repository.frontend.repository_url
}

locals {
    app_domain = "${var.app_subdomain}.${var.root_domain}"
}

resource "aws_ecr_repository" "frontend" {
    name = "predictapool-frontend"
    image_tag_mutability = "IMMUTABLE"

    image_scanning_configuration {
        scan_on_push = true
    }
}

# Setup CloudWatch Logs
resource "aws_cloudwatch_log_group" "frontend" {
  name              = "/ecs/predictapool-frontend"
  retention_in_days = 7
}

resource "aws_ecs_task_definition" "frontend" {
  family                   = "predictapool-frontend"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn

  container_definitions = jsonencode([
    {
      name      = "frontend"
      image     = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/predictapool-frontend:git-f84b5ab"
      essential = true

      portMappings = [
        {
          containerPort = 3000
          protocol      = "tcp"
        }
      ]

      environment = [
        {
          name  = "NEXT_PUBLIC_API_BASE_URL"
          value = "https://${local.api_domain}"
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.frontend.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "frontend"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "frontend" {
  name            = "predictapool-frontend"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.frontend.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  network_configuration {
    subnets         = data.aws_subnets.default.ids
    security_groups = [aws_security_group.frontend.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.frontend.arn
    container_name   = "frontend"
    container_port   = 3000
  }

  depends_on = [aws_lb_listener.https]
}

resource "aws_security_group" "frontend" {
  name        = "predictapool-frontend-sg"
  description = "Allow ALB to access frontend"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb_target_group" "frontend" {
  name        = "predictapool-frontend-tg"
  port        = 3000
  protocol    = "HTTP"
  vpc_id      = data.aws_vpc.default.id
  target_type = "ip"

  health_check {
    path                = "/"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

resource "aws_lb_listener_rule" "frontend" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10

  condition {
    host_header {
      values = [local.app_domain]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.frontend.arn
  }
}

resource "aws_acm_certificate" "frontend" {
  domain_name       = local.app_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "frontend" {
  zone_id = aws_route53_zone.main.zone_id
  name    = local.app_domain
  type    = "A"

  alias {
    name                   = aws_lb.backend.dns_name
    zone_id                = aws_lb.backend.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "frontend_cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.frontend.domain_validation_options :
    dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  zone_id = aws_route53_zone.main.zone_id
  name    = each.value.name
  type    = each.value.type
  records = [each.value.record]
  ttl     = 60
}

resource "aws_acm_certificate_validation" "frontend" {
  certificate_arn         = aws_acm_certificate.frontend.arn
  validation_record_fqdns = [
    for r in aws_route53_record.frontend_cert_validation : r.fqdn
  ]
}

resource "aws_lb_listener_certificate" "frontend" {
  listener_arn    = aws_lb_listener.https.arn
  certificate_arn = aws_acm_certificate.frontend.arn

  depends_on = [aws_acm_certificate_validation.frontend]
}

###########################################################################
#
#                           BACKEND
#
###########################################################################

output "backend_ecr_url" {
    value = aws_ecr_repository.backend.repository_url
}

resource "aws_ecr_repository" "backend" {
    name = "predictapool-backend"
    image_tag_mutability = "IMMUTABLE"

    image_scanning_configuration {
        scan_on_push = true
    }
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
            image = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/predictapool-backend:git-f84b5ab"
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

###########################################################################
#
#                           LOAD BALANCER
#
###########################################################################

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

###########################################################################
#
#                           ROUTE53
#
###########################################################################

resource "aws_route53_zone" "main" {
  name = var.root_domain
}

resource "aws_route53_record" "root" {
    zone_id = aws_route53_zone.main.zone_id
    name = var.root_domain
    type = "A"

    alias {
        name = aws_cloudfront_distribution.landing.domain_name
        zone_id = aws_cloudfront_distribution.landing.hosted_zone_id
        evaluate_target_health = false
    }
}

###########################################################################
#
#                           LANDING PAGE
#
###########################################################################

resource "aws_s3_bucket" "landing" {
    bucket = var.root_domain
}

resource "aws_s3_bucket_public_access_block" "landing" {
    bucket = aws_s3_bucket.landing.id

    block_public_acls = true
    block_public_policy = true
    ignore_public_acls = true
    restrict_public_buckets = true
}

# Give CloudFront read permission to S3 
resource "aws_s3_bucket_policy" "landing" {
    bucket = aws_s3_bucket.landing.id

    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Sid = "AllowCloudFrontRead"
                Effect = "Allow"
                Principal = {
                    Service = "cloudfront.amazonaws.com"
                }
                Action = "s3:GetObject"
                Resource = "${aws_s3_bucket.landing.arn}/*"
                Condition = {
                    StringEquals = {
                        "AWS:SourceArn" = aws_cloudfront_distribution.landing.arn
                    }
                }
            }
        ]
    })
}

resource "aws_acm_certificate" "landing" {
    provider = aws.us_east_1
    domain_name = var.root_domain
    validation_method = "DNS"

    lifecycle {
        create_before_destroy = true
    }
}

resource "aws_route53_record" "landing_cert_validation" {
    for_each = {
        for dvo in aws_acm_certificate.landing.domain_validation_options :
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

resource "aws_acm_certificate_validation" "landing" {
    provider = aws.us_east_1
    certificate_arn = aws_acm_certificate.landing.arn
    validation_record_fqdns = [
        for r in aws_route53_record.landing_cert_validation : r.fqdn
    ]
}

resource "aws_cloudfront_origin_access_control" "landing" {
    name = "predictapool-oac"
    origin_access_control_origin_type = "s3"
    signing_behavior = "always"
    signing_protocol = "sigv4"
}

resource "aws_cloudfront_distribution" "landing" {
    enabled = true
    default_root_object = "index.html"
    aliases = [var.root_domain]

    origin {
        domain_name = aws_s3_bucket.landing.bucket_regional_domain_name
        origin_id = "s3-predictapool"
        origin_access_control_id = aws_cloudfront_origin_access_control.landing.id
    }

    default_cache_behavior {
        allowed_methods = ["GET", "HEAD"]
        cached_methods = ["GET", "HEAD"]
        target_origin_id = "s3-predictapool"

        viewer_protocol_policy = "redirect-to-https"

        forwarded_values {
            query_string = false
            cookies { forward = "none" }
        }
    }

    viewer_certificate {
        acm_certificate_arn = aws_acm_certificate.landing.arn
        ssl_support_method = "sni-only"
    }

    restrictions {
        geo_restriction { restriction_type = "none" }
    }

    depends_on = [aws_acm_certificate_validation.landing]
}

###########################################################################
#
#                               API
#
###########################################################################

locals {
    api_domain = "${var.api_subdomain}.${var.root_domain}"
}

resource "aws_acm_certificate" "api" {
    domain_name = local.api_domain
    validation_method = "DNS"

    lifecycle {
        create_before_destroy = true
    }
}

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
    name = local.api_domain
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