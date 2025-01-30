
resource "aws_iam_role" "email_sender" {
  count              = var.create_email_sender_instance ? 1 : 0
  name               = "crossfeed-email-sender-${var.stage}"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
    Project = var.project
    Stage   = var.stage
    Owner   = "Crossfeed managed resource"
  }
}

resource "aws_iam_instance_profile" "email_sender" {
  count = var.create_email_sender_instance ? 1 : 0
  name  = "crossfeed-email-sender-${var.stage}"
  role  = aws_iam_role.email_sender[0].id
}

# Attach Policies to the Email EC2 Role
resource "aws_iam_policy_attachment" "email_sender_ec2_policy_1" {
  count      = var.create_email_sender_instance ? 1 : 0
  name       = "crossfeed-email-sender-${var.stage}"
  roles      = [aws_iam_role.email_sender[0].id, "AmazonSSMRoleForInstancesQuickSetup"]
  policy_arn = "arn:${var.aws_partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_policy_attachment" "email_sender_ec2_policy_2" {
  count      = var.create_email_sender_instance ? 1 : 0
  name       = "crossfeed-email-sender-${var.stage}"
  roles      = [aws_iam_role.email_sender[0].id]
  policy_arn = "arn:${var.aws_partition}:iam::aws:policy/service-role/AmazonEC2RoleforSSM"
}

# EC2 Instance for SES
resource "aws_instance" "email_sender" {
  count                       = var.create_email_sender_instance ? 1 : 0
  ami                         = var.ami_id
  instance_type               = var.email_sender_instance_type
  associate_public_ip_address = false

  depends_on = [
    aws_iam_instance_profile.email_sender,
    aws_security_group.allow_internal,
    aws_subnet.backend
  ]

  tags = {
    Project = var.project
    Stage   = var.stage
    Name    = "email_sender"
    Owner   = "Crossfeed managed resource"
  }
  root_block_device {
    volume_size = 50
  }

  vpc_security_group_ids = [var.is_dmz ? aws_security_group.allow_internal[0].id : aws_security_group.allow_internal_lz[0].id]
  subnet_id              = var.is_dmz ? aws_subnet.backend[0].id : data.aws_ssm_parameter.subnet_db_1_id[0].value

  iam_instance_profile = aws_iam_instance_profile.email_sender[0].id
  user_data            = file("./email-sender-install.sh")

  lifecycle {
    ignore_changes = [ami]
  }

}
