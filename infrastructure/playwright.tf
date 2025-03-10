resource "aws_iam_role" "playwright_worker_task_execution_role" {
  name = "playwright-worker-task-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Effect = "Allow"
      }
    ]
  })
}

resource "aws_iam_role_policy" "playwright_ecs_task_policy" {
  name = "playwright-ecs-task-policy"
  role = aws_iam_role.worker_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = ["s3:ListBucket", "s3:GetObject", "s3:PutObject"]
        Effect = "Allow"
        Resource = [
          "arn:aws:s3:::my-bucket",  # ListBucket on the bucket itself
          "arn:aws:s3:::my-bucket/*" # GetObject and PutObject on all objects within the bucket
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "playwright_ecs_execution_policy" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
  role       = aws_iam_role.playwright_worker_task_execution_role.name
}

resource "aws_ecr_repository" "playwright" {
  name = "playwright-ui-testing"

  image_scanning_configuration {
    scan_on_push = true
  }

  image_tag_mutability = "MUTABLE"

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.key.arn
  }

  tags = {
    Project = var.project
    Stage   = var.stage
    Owner   = "Crossfeed managed resource"
  }
}

resource "aws_ecs_task_definition" "playwright_worker" {
  family                   = var.worker_ecs_task_definition_family
  container_definitions    = <<EOF
[
  {
    "name": "playwright",
    "image": "${aws_ecr_repository.playwright.repository_url}:${var.image_tag}",
    "essential": true,
    "mountPoints": [],
    "portMappings": [],
    "volumesFrom": [],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "${var.worker_ecs_log_group_name}",
        "awslogs-region": "${var.aws_region}",
        "awslogs-stream-prefix": "playwright"
      }
    },
    "environment": [
      {
        "name": "BROWSER_TYPE",
        "value": "chromium"
      },
      {
        "name": "TEST_URL",
        "value": "${var.frontend_domain}"
      }
    ]
  }
]
EOF
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.playwright_worker_task_execution_role.arn
  task_role_arn            = aws_iam_role.worker_task_role.arn

  cpu    = 256 # .25 vCPU
  memory = 512 # 512 MB

  tags = {
    Project = var.project
    Stage   = var.stage
    Owner   = "Crossfeed managed resource"
  }
}
