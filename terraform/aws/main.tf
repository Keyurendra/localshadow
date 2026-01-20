locals {
  otel_collector_config = templatefile("${path.module}/otel-collector-config.yaml", {
    tenant_id = var.artifact_tenant_id
  })
  cloud_init_config = templatefile("${path.module}/cloud-init.yaml", {
    provider              = "aws"
    artifact_token        = var.artifact_token
    artifact_endpoint     = var.artifact_endpoint
    artifact_label        = var.artifact_label
    artifact_tenant_id    = var.artifact_tenant_id
    omni_additional_flags = var.omni_additional_flags
    enable_telemetry      = var.enable_telemetry
    otel_collector_config = local.otel_collector_config
  })
}

resource "null_resource" "metadata_trigger" {
  triggers = {
    user_data = local.cloud_init_config
  }
}

data "aws_ami" "ubuntu_latest" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-plucky-25.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = {
    Name = "accuknox-omni-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "accuknox-omni-igw"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true
  tags = {
    Name = "accuknox-omni-public-subnet"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.0.0/24"
  availability_zone = var.availability_zone
  tags = {
    Name = "accuknox-omni-private-subnet"
  }
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags = {
    Name = "accuknox-omni-nat-eip"
  }
  depends_on = [aws_internet_gateway.main]
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id
  tags = {
    Name = "accuknox-omni-nat-gateway"
  }
  depends_on = [aws_internet_gateway.main]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  tags = {
    Name = "accuknox-omni-public-rt"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  tags = {
    Name = "accuknox-omni-private-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

resource "aws_security_group" "omni" {
  name        = "accuknox-omni-sg"
  description = "Security group for AccuKnox Omni instance - Private access only"
  vpc_id      = aws_vpc.main.id
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS for AccuKnox CSPM API, AWS APIs, updates, etc."
  }
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP for package repositories"
  }
  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "DNS resolution"
  }
  egress {
    from_port   = 123
    to_port     = 123
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "NTP for time synchronization"
  }
  tags = {
    Name = "accuknox-omni-sg"
  }
}

resource "aws_iam_role" "omni" {
  name = "accuknox-omni-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
  tags = {
    Name = "accuknox-omni-role"
  }
}

resource "aws_iam_role_policy" "omni_policy" {
  name = "accuknox-omni-policy"
  role = aws_iam_role.omni.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeVolumes",
          "ec2:DescribeVolumeStatus",
          "ec2:DescribeSnapshots",
          "ec2:CreateSnapshot",
          "ec2:DeleteSnapshot",
          "ec2:AttachVolume",
          "ec2:DetachVolume",
          "ec2:CreateVolume",
          "ec2:DeleteVolume",
          "ec2:CreateTags"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "omni_session_manager_policy" {
  role       = aws_iam_role.omni.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "omni" {
  name = "accuknox-omni-instance-profile"
  role = aws_iam_role.omni.name
}

resource "aws_instance" "omni" {
  ami                         = data.aws_ami.ubuntu_latest.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.private.id
  vpc_security_group_ids      = [aws_security_group.omni.id]
  iam_instance_profile        = aws_iam_instance_profile.omni.name
  associate_public_ip_address = false
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 10
    encrypted             = true
    delete_on_termination = true
  }
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
  user_data_base64 = base64encode(local.cloud_init_config)
  tags = {
    Name = "accuknox-omni"
  }
  lifecycle {
    replace_triggered_by = [null_resource.metadata_trigger]
  }
  depends_on = [aws_route_table_association.private]
}
