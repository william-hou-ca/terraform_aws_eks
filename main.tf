provider "aws" {
  region = "ca-central-1"
}

###########################################################################
#
# Create a eks cluster.
#
###########################################################################

resource "aws_eks_cluster" "this" {

  # Cluster configuration
  name     = var.cluster_name
  version = "1.18"
  role_arn = aws_iam_role.this.arn

  # Secrets encryptio
  /*
  encryption_config {
    provider {
      key_arn = ""
    }

    resources = "secrets"
  }
  */

  # Networking
  vpc_config {
    subnet_ids = concat(tolist(data.aws_subnet_ids.default_subnets.ids), [aws_subnet.sub_fargate.id,])
    security_group_ids = data.aws_security_groups.default_sg.ids

  # Cluster endpoint access
    endpoint_private_access = true
    endpoint_public_access = false
    public_access_cidrs = ["0.0.0.0/0"]

  }

  kubernetes_network_config  {
    service_ipv4_cidr = "172.20.0.0/16"
  }

  # Networking add-ons


  # Configure logging
  enabled_cluster_log_types = ["api", "audit"] # authenticator, controllerManager, scheduler

  tags = {
    version = "1.18"
    env = "test"
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Cluster handling.
  # Otherwise, EKS will not be able to properly delete EKS managed EC2 infrastructure such as Security Groups.
  depends_on = [
    aws_iam_role_policy_attachment.example-AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.example-AmazonEKSVPCResourceController,
    aws_subnet.sub_fargate,
  ]
}

###########################################################################
#
# Create a cloudwatch log group for the cluster.
#
###########################################################################
/*
resource "aws_cloudwatch_log_group" "this" {
  # The log group name format is /aws/eks/<cluster-name>/cluster
  # Reference: https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
  name              = "/aws/eks/${aws_eks_cluster.this.name}/cluster"
  retention_in_days = 3

  # ... potentially other configuration ...
}
*/
###########################################################################
#
# Create a eks cluster role and attach policies.
#
###########################################################################

resource "aws_iam_role" "this" {
  name = "tf-eks-cluster-example"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "example-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.this.name
}

# Optionally, enable Security Groups for Pods
# Reference: https://docs.aws.amazon.com/eks/latest/userguide/security-groups-for-pods.html
resource "aws_iam_role_policy_attachment" "example-AmazonEKSVPCResourceController" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.this.name
}

###########################################################################
#
# Enabling IAM Roles for Service Accounts.
# Only available on Kubernetes version 1.13 and 1.14 clusters created or upgraded on or after September 3, 2019. 
#
###########################################################################
data "tls_certificate" "this" {
  url = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "this" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.this.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

data "aws_iam_policy_document" "example_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.this.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:aws-node"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.this.arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "iam_to_k8s" {
  assume_role_policy = data.aws_iam_policy_document.example_assume_role_policy.json
  name               = "tf-iam-to-k8s-rbac"
}


###########################################################################
#
# Manages an EKS Node Group
#
###########################################################################

resource "aws_eks_node_group" "nodes" {

  cluster_name    = aws_eks_cluster.this.name

  # Node Group configuration
  node_group_name = "tf-k8s-nodegroup"
  node_role_arn   = aws_iam_role.nodes.arn

  # Launch template
  #launch_template = 

  # Kubernetes labels
  #labels = {}

  # Tags
  tags = {
    env = "test"
    version = "1.18"
    type = "nodes"
  }
 
  # Node Group compute configuration
  #ami_type = "AL2_x86_64" #Valid values: AL2_x86_64, AL2_x86_64_GPU, AL2_ARM_64
  #capacity_type = "ON_DEMAND"
  #instance_types = ["t3.medium"]
  #disk_size = 20

  # Node Group scaling configuration
  scaling_config {
    desired_size = 1
    max_size     = 2
    min_size     = 1
  }

  # Node Group network configuration
  subnet_ids      = data.aws_subnet_ids.default_subnets.ids
  remote_access {
    ec2_ssh_key = "key-hr123000"
    source_security_group_ids = data.aws_security_groups.default_sg.ids
  }


  lifecycle {
    ignore_changes = [scaling_config[0].desired_size]
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.nodes-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.nodes-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.nodes-AmazonEC2ContainerRegistryReadOnly,
  ]
}

###########################################################################
#
# Manages an EKS Node Group role
#
###########################################################################

resource "aws_iam_role" "nodes" {
  name = "tf-eks-node-group-example"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "nodes-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.nodes.name
}

resource "aws_iam_role_policy_attachment" "nodes-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.nodes.name
}

resource "aws_iam_role_policy_attachment" "nodes-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.nodes.name
}


###########################################################################
#
# Manages an EKS Fargate Profile.
#
###########################################################################

resource "aws_eks_fargate_profile" "this" {

  cluster_name           = aws_eks_cluster.this.name
  
  # Profile configuration
  fargate_profile_name   = "tf-k8s-fargate"
  pod_execution_role_arn = aws_iam_role.fargate.arn
  subnet_ids             = [aws_subnet.sub_fargate.id]

  # Tags
  tags = {
    env = "test"
    version = "1.18"
    type = "fargate"
  }

  # Pod selectors
  selector {
    namespace = "default"
  }
  #labels = {}

}

# private subnet used to fargate profile
# You need to assign your subnets to a route table that does not have a route to igw
# Otherwise error message: Subnet subnet-xxxxxxxxx provided in Fargate Profile is not a private subnet
resource "aws_subnet" "sub_fargate" {
  vpc_id     = data.aws_vpc.default_vpc.id
  cidr_block = "172.31.48.0/20"

  tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
  }
}

resource "aws_route_table_association" "rta_fargate" {
  subnet_id      = aws_subnet.sub_fargate.id
  route_table_id = aws_route_table.rt_fargate.id
}

resource "aws_route_table" "rt_fargate" {
  vpc_id = data.aws_vpc.default_vpc.id

}

###########################################################################
#
# Manages IAM Role for EKS Fargate Profile.
#
###########################################################################

resource "aws_iam_role" "fargate" {
  name = "eks-fargate-profile-example"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks-fargate-pods.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "fargate-AmazonEKSFargatePodExecutionRolePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
  role       = aws_iam_role.fargate.name
}

###########################################################################
#
# Manages an EKS add-on.
# not supported yet
#
###########################################################################
/*
resource "aws_eks_addon" "this" {
  cluster_name = aws_eks_cluster.this.name

  # Name
  addon_name   = "vpc-cni"

  # Version
  addon_version = "v1.7.5-eksbuild.2"

  # Service account role
  #service_account_role_arn = 

}
*/

###########################################################################
#
# ec2 instance in the default vpc
#
###########################################################################

resource "aws_instance" "web" {
  #count = 0 #if count = 0, this instance will not be created.

  #required parametres
  ami           = "ami-09934b230a2c41883"
  instance_type = "t2.micro"

  #optional parametres
  associate_public_ip_address = true
  key_name = "key-hr123000" #key paire name exists in aws.

  vpc_security_group_ids = data.aws_security_groups.default_sg.ids

  iam_instance_profile = aws_iam_instance_profile.this.name

  tags = {
    Name = "HelloWorld"
  }

  user_data = <<-EOF
          #! /bin/sh
          sudo yum update -y
          sudo amazon-linux-extras install epel -y 
          cat <<EOR | sudo tee /etc/yum.repos.d/kubernetes.repo
          [kubernetes]
          name=Kubernetes
          baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
          enabled=1
          gpgcheck=1
          repo_gpgcheck=1
          gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
          EOR
          sudo yum install kubectl-0:1.18.17-0.x86_64 -y
          cd /home/ec2-user
          echo "alias k=kubectl" | sudo tee -a /home/ec2-user/.bashrc
          aws eks update-kubeconfig --region ca-central-1 --name tf-eks-cluster
EOF

  lifecycle {
      ignore_changes = [
        # Ignore changes to tags, e.g. because a management agent
        # updates these based on some ruleset managed elsewhere.
        user_data,
      ]
    }

  depends_on = [aws_eks_cluster.this]  
}

resource "aws_iam_instance_profile" "this" {
  name = "tf-iam-role-k8s"
  role = aws_iam_role.ec2-managehost.name
}

resource "aws_iam_role" "ec2-managehost" {
  name = "tf-ec2-managment-role"

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

  managed_policy_arns = [data.aws_iam_policy.ec2-managehost.arn]
}

data "aws_iam_policy" "ec2-managehost" {
  arn = "arn:aws:iam::aws:policy/AdministratorAccess" 
}

