# Infrastructure as code with the flaws the IaC controls look for.
#
# The interesting one is the second security group rule: its ports arrive from a
# variable, so the assessor cannot read them and reports the rule as unknown rather
# than as clear. That is the honest answer and it is what the tool says.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "5.0.0" }
  }
}

resource "aws_security_group" "web" {
  name = "web"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Application ports, from a variable"
    from_port   = var.app_port
    to_port     = var.app_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "deploy" {
  name   = "deploy"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
POLICY
}

resource "aws_db_instance" "main" {
  engine         = "postgres"
  instance_class = "db.t3.micro"
  username       = "app"
  password       = "literal-password-in-the-configuration"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = "logs"
  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_ecs_task_definition" "worker" {
  family                   = "worker"
  container_definitions = jsonencode([
    {
      "name"       = "worker"
      "image"      = "myregistry/worker:latest"
      "privileged" = true
      "essential"  = true
    }
  ])
}
