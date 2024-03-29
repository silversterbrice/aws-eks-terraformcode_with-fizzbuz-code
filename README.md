# Setting up AWS EKS (Hosted Kubernetes)

 The AWS EKS environment has been created with terraform reources, the code snippets are explained below.

## To create EKS cluster
```
resource "aws_eks_cluster" "demo" {
  name     = "${var.cluster-name}"
  role_arn = "${aws_iam_role.demo-cluster.arn}"

  vpc_config {
    security_group_ids = ["${aws_security_group.demo-cluster.id}"]
    subnet_ids = "${aws_subnet.demo.*.id}"
  }

  depends_on = [
   "aws_iam_role_policy_attachment.demo-cluster-AmazonEKSClusterPolicy",
   "aws_iam_role_policy_attachment.demo-cluster-AmazonEKSServicePolicy",
  ]
}
```

## To create EKS worker nodes
```
data "aws_ami" "eks-worker" {
  filter {
    name   = "name"
    values = ["amazon-eks-node-${aws_eks_cluster.demo.version}-v*"]
  }

  most_recent = true
  owners      = ["602401143452"] # Amazon
}

locals {
  demo-node-userdata = <<USERDATA
#!/bin/bash
set -o xtrace
/etc/eks/bootstrap.sh --apiserver-endpoint '${aws_eks_cluster.demo.endpoint}' --b64-cluster-ca '${aws_eks_cluster.demo.certificate_authority[0].data}' '${var.cluster-name}'
USERDATA

}

resource "aws_launch_configuration" "demo" {
  associate_public_ip_address = true
  iam_instance_profile = "${aws_iam_instance_profile.demo-node.name}"
  image_id = "${data.aws_ami.eks-worker.id}"
  instance_type = "${var.instancetype}"
  name_prefix = "terraform-eks-demo"
  security_groups = ["${aws_security_group.demo-node.id}"]
  user_data_base64 = "${base64encode(local.demo-node-userdata)}"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "demo" {
  desired_capacity = 3
  launch_configuration = aws_launch_configuration.demo.id
  max_size = 3
  min_size = 3
  name = "terraform-eks-demo"
  vpc_zone_identifier = "${aws_subnet.demo.*.id}"

  tag {
    key = "Name"
    value = "terraform-eks-demo"
    propagate_at_launch = true
  }

  tag {
    key = "kubernetes.io/cluster/${var.cluster-name}"
    value = "owned"
    propagate_at_launch = true
  }
}
```

## Defined Security group for workstation and PODs to communicate with EKS Cluster
```
resource "aws_security_group" "demo-cluster" {
  name        = "terraform-eks-demo-cluster"
  description = "Cluster communication with worker nodes"
  vpc_id      = "${aws_vpc.demo.id}"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "terraform-eks-demo"
  }
}

resource "aws_security_group_rule" "demo-cluster-ingress-node-https" {
  description              = "Allow pods to communicate with the cluster API Server"
  from_port                = 443
  protocol                 = "tcp"
  security_group_id        = "${aws_security_group.demo-cluster.id}"
  source_security_group_id = "${aws_security_group.demo-node.id}"
  to_port                  = 443
  type                     = "ingress"
}

resource "aws_security_group_rule" "demo-cluster-ingress-workstation-https" {
  cidr_blocks       = ["${local.workstation-external-cidr}"]
  description       = "Allow workstation to communicate with the cluster API Server"
  from_port         = 443
  protocol          = "tcp"
  security_group_id = "${aws_security_group.demo-cluster.id}"
  to_port           = 443
  type              = "ingress"
}
```

## Defined Security group for Node communication
```
resource "aws_security_group" "demo-node" {
  name        = "terraform-eks-demo-node"
  description = "Security group for all nodes in the cluster"
  vpc_id      = "${aws_vpc.demo.id}"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    "Name"                                      = "terraform-eks-demo-node"
    "kubernetes.io/cluster/${var.cluster-name}" = "owned"
  }
}

resource "aws_security_group_rule" "demo-node-ingress-self" {
  description              = "Allow node to communicate with each other"
  from_port                = 0
  protocol                 = "-1"
  security_group_id        = "${aws_security_group.demo-node.id}"
  source_security_group_id = "${aws_security_group.demo-node.id}"
  to_port                  = 65535
  type                     = "ingress"
}

resource "aws_security_group_rule" "demo-node-ingress-cluster" {
  description              = "Allow worker Kubelets and pods to receive communication from the cluster control plane"
  from_port                = 1025
  protocol                 = "tcp"
  security_group_id        = "${aws_security_group.demo-node.id}"
  source_security_group_id = "${aws_security_group.demo-cluster.id}"
  to_port                  = 65535
  type                     = "ingress"
}
```

## All Necessary providers are defined here
```
provider "aws" {
  region = "${var.region}"
}

data "aws_region" "current" {
}


provider "http" {
}

```

## VPC, subnet, IGW and route table associations are defined here
```
 data "aws_availability_zones" "available" {
 }

 resource "aws_vpc" "demo" {
   cidr_block = "10.0.0.0/16"

   tags = {
     "Name"                                      = "terraform-eks-demo-node"
     "kubernetes.io/cluster/${var.cluster-name}" = "shared"
   }
 }

 resource "aws_subnet" "demo" {
   count = 3

   availability_zone = "${data.aws_availability_zones.available.names[count.index]}"
   cidr_block        = "10.0.${count.index}.0/24"
   vpc_id            = "${aws_vpc.demo.id}"

   tags = {
     "Name"                                      = "terraform-eks-demo-node"
     "kubernetes.io/cluster/${var.cluster-name}" = "shared"
   }
 }

 resource "aws_internet_gateway" "demo" {
   vpc_id = "${aws_vpc.demo.id}"

   tags = {
     Name = "terraform-eks-demo"
   }
 }

 resource "aws_route_table" "demo" {
   vpc_id = "${aws_vpc.demo.id}"

   route {
     cidr_block = "0.0.0.0/0"
     gateway_id = "${aws_internet_gateway.demo.id}"
   }
 }

 resource "aws_route_table_association" "demo" {
   count = 2

   subnet_id      = "${aws_subnet.demo[count.index].id}"
   route_table_id = "${aws_route_table.demo.id}"
 }
```

## To check for workstation IP
```
data "http" "workstation-external-ip" {
  url = "http://ipv4.icanhazip.com"
}

locals {
  workstation-external-cidr = "${chomp(data.http.workstation-external-ip.body)}/32"
}
```

## IAM Policy for cluster
```
resource "aws_iam_role" "demo-cluster" {
  name = "terraform-eks-demo-cluster"

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

resource "aws_iam_role_policy_attachment" "demo-cluster-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role = "${aws_iam_role.demo-cluster.name}"
}

resource "aws_iam_role_policy_attachment" "demo-cluster-AmazonEKSServicePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
  role = "${aws_iam_role.demo-cluster.name}"
}

# If no loadbalancer was ever created in this region, then this following role is necessary
resource "aws_iam_role_policy" "demo-cluster-service-linked-role" {
  name = "service-linked-role"
  role = aws_iam_role.demo-cluster.name

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "iam:CreateServiceLinkedRole",
            "Resource": "arn:aws:iam::*:role/aws-service-role/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeAccountAttributes"
            ],
            "Resource": "*"
        }
    ]
}
EOF

}
```

## IAM policy for Nodes
```
resource "aws_iam_role" "demo-node" {
  name = "terraform-eks-demo-node"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY

}

resource "aws_iam_role_policy_attachment" "demo-node-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role = "${aws_iam_role.demo-node.name}"
}

resource "aws_iam_role_policy_attachment" "demo-node-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role = "${aws_iam_role.demo-node.name}"
}

resource "aws_iam_role_policy_attachment" "demo-node-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role = "${aws_iam_role.demo-node.name}"
}

resource "aws_iam_instance_profile" "demo-node" {
  name = "terraform-eks-demo"
  role = "${aws_iam_role.demo-node.name}"
}
```

## For Kubeconfig and Config-map-aws-auth outputs
```
locals {
  kubeconfig = <<KUBECONFIG


apiVersion: v1
clusters:
- cluster:
    server: ${aws_eks_cluster.demo.endpoint}
    certificate-authority-data: ${aws_eks_cluster.demo.certificate_authority[0].data}
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: aws
  name: aws
current-context: aws
kind: Config
preferences: {}
users:
- name: aws
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1alpha1
      command: heptio-authenticator-aws
      args:
        - "token"
        - "-i"
        - "${var.cluster-name}"
KUBECONFIG

}

output "kubeconfig" {
  value = local.kubeconfig
}

# Join configuration

locals {
  config-map-aws-auth = <<CONFIGMAPAWSAUTH


apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-auth
  namespace: kube-system
data:
  mapRoles: |
    - rolearn: ${aws_iam_role.demo-node.arn}
      username: system:node:{{EC2PrivateDNSName}}
      groups:
        - system:bootstrappers
        - system:nodes
CONFIGMAPAWSAUTH

}

output "config-map-aws-auth" {
value = local.config-map-aws-auth
}
```

## Sample Fizzbuzz code is used to create the deploymnet and service
```
resource "kubernetes_service" "fizzbuzz_service" {
  metadata {
    name = "fizzbuzz-service"
  }
  spec {
    selector = {
      app = "${kubernetes_deployment.fizzbuzz_deployment.spec.0.template.0.metadata.0.labels.app}"
    }
    port {
      port        = "8080"
      target_port = "8080"
    }

    type = "NodePort"
  }
}

resource "kubernetes_deployment" "fizzbuzz_deployment" {
  metadata {
    name = "fizzbuzz-blog"
  }

  spec {
    replicas = "2"

    selector {
      match_labels = {
        app = "fizzbuzz-blog"
      }
    }

    template {
      metadata {
        labels = {
          app = "fizzbuzz-blog"
        }
      }

      spec {
        container {
          name  = "fizzbuzz"
          image = "carlpaton/fizzpuzz:v1.0.0"
          port {
            container_port = "8080"
          }
        }
      }
    }
  }
}
```

## Terraform plan output from EKS cluster
```
root@ip-172-31-13-209:~/EKS# terraform plan
Refreshing Terraform state in-memory prior to plan...
The refreshed state will be used to calculate this plan, but will not be
persisted to local or remote state storage.

data.http.workstation-external-ip: Refreshing state...
data.aws_region.current: Refreshing state...
data.aws_availability_zones.available: Refreshing state...
aws_iam_role.demo-cluster: Refreshing state... [id=terraform-eks-demo-cluster]
aws_vpc.demo: Refreshing state... [id=vpc-034fd0baaa76af020]
aws_iam_role.demo-node: Refreshing state... [id=terraform-eks-demo-node]
aws_iam_role_policy_attachment.demo-cluster-AmazonEKSServicePolicy: Refreshing state... [id=terraform-eks-demo-cluster-20191216030902432200000001]
aws_iam_role_policy_attachment.demo-cluster-AmazonEKSClusterPolicy: Refreshing state... [id=terraform-eks-demo-cluster-20191216030902435100000002]
aws_iam_role_policy.demo-cluster-service-linked-role: Refreshing state... [id=terraform-eks-demo-cluster:service-linked-role]
aws_iam_role_policy_attachment.demo-node-AmazonEKS_CNI_Policy: Refreshing state... [id=terraform-eks-demo-node-20191216030902511700000003]
aws_iam_role_policy_attachment.demo-node-AmazonEKSWorkerNodePolicy: Refreshing state... [id=terraform-eks-demo-node-20191216030902517300000005]
aws_iam_role_policy_attachment.demo-node-AmazonEC2ContainerRegistryReadOnly: Refreshing state... [id=terraform-eks-demo-node-20191216030902514100000004]
aws_iam_instance_profile.demo-node: Refreshing state... [id=terraform-eks-demo]
aws_subnet.demo[1]: Refreshing state... [id=subnet-0e287e0d8656205fc]
aws_subnet.demo[2]: Refreshing state... [id=subnet-0a7ff86a38658da7e]
aws_subnet.demo[0]: Refreshing state... [id=subnet-014242c046eec7013]
aws_security_group.demo-node: Refreshing state... [id=sg-076fcf751a3551b77]
aws_security_group.demo-cluster: Refreshing state... [id=sg-0ca999dacdbabf1ee]
aws_internet_gateway.demo: Refreshing state... [id=igw-058038ed6e29768f3]
aws_route_table.demo: Refreshing state... [id=rtb-0800b78a76df1e718]
aws_security_group_rule.demo-cluster-ingress-workstation-https: Refreshing state... [id=sgrule-1897999330]
aws_security_group_rule.demo-cluster-ingress-node-https: Refreshing state... [id=sgrule-3172215408]
aws_security_group_rule.demo-node-ingress-self: Refreshing state... [id=sgrule-2153253776]
aws_security_group_rule.demo-node-ingress-cluster: Refreshing state... [id=sgrule-3938485730]
aws_eks_cluster.demo: Refreshing state... [id=terraform-eks-cluster]
aws_route_table_association.demo[1]: Refreshing state... [id=rtbassoc-08de6ceeac3e16f91]
aws_route_table_association.demo[0]: Refreshing state... [id=rtbassoc-0785cf241cb21a60e]
data.aws_ami.eks-worker: Refreshing state...
aws_launch_configuration.demo: Refreshing state... [id=terraform-eks-demo20191216031818994700000006]
aws_autoscaling_group.demo: Refreshing state... [id=terraform-eks-demo]

------------------------------------------------------------------------

No changes. Infrastructure is up-to-date.

This means that Terraform did not detect any differences between your
configuration and real physical resources that exist. As a result, no
actions need to be performed.
root@ip-172-31-13-209:~/EKS#
```

## Terraform plan output for fizzbuzz deployment
```
root@ip-172-31-13-209:~/EKS_Deploy# terraform plan
Refreshing Terraform state in-memory prior to plan...
The refreshed state will be used to calculate this plan, but will not be
persisted to local or remote state storage.


------------------------------------------------------------------------

An execution plan has been generated and is shown below.
Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # kubernetes_deployment.fizzbuzz_deployment will be created
  + resource "kubernetes_deployment" "fizzbuzz_deployment" {
      + id = (known after apply)

      + metadata {
          + generation       = (known after apply)
          + name             = "fizzbuzz-blog"
          + namespace        = "default"
          + resource_version = (known after apply)
          + self_link        = (known after apply)
          + uid              = (known after apply)
        }

      + spec {
          + min_ready_seconds         = 0
          + paused                    = false
          + progress_deadline_seconds = 600
          + replicas                  = 2
          + revision_history_limit    = 10

          + selector {
              + match_labels = {
                  + "app" = "fizzbuzz-blog"
                }
            }

          + strategy {
              + type = (known after apply)

              + rolling_update {
                  + max_surge       = (known after apply)
                  + max_unavailable = (known after apply)
                }
            }

          + template {
              + metadata {
                  + generation       = (known after apply)
                  + labels           = {
                      + "app" = "fizzbuzz-blog"
                    }
                  + name             = (known after apply)
                  + resource_version = (known after apply)
                  + self_link        = (known after apply)
                  + uid              = (known after apply)
                }

              + spec {
                  + dns_policy                       = "ClusterFirst"
                  + host_ipc                         = false
                  + host_network                     = false
                  + host_pid                         = false
                  + hostname                         = (known after apply)
                  + node_name                        = (known after apply)
                  + restart_policy                   = "Always"
                  + service_account_name             = (known after apply)
                  + share_process_namespace          = false
                  + termination_grace_period_seconds = 30

                  + container {
                      + image                    = "carlpaton/fizzpuzz:v1.0.0"
                      + image_pull_policy        = (known after apply)
                      + name                     = "fizzbuzz"
                      + stdin                    = false
                      + stdin_once               = false
                      + termination_message_path = "/dev/termination-log"
                      + tty                      = false

                      + port {
                          + container_port = 8080
                          + protocol       = "TCP"
                        }

                      + resources {
                          + limits {
                              + cpu    = (known after apply)
                              + memory = (known after apply)
                            }

                          + requests {
                              + cpu    = (known after apply)
                              + memory = (known after apply)
                            }
                        }

                      + volume_mount {
                          + mount_path        = (known after apply)
                          + mount_propagation = (known after apply)
                          + name              = (known after apply)
                          + read_only         = (known after apply)
                          + sub_path          = (known after apply)
                        }
                    }

                  + image_pull_secrets {
                      + name = (known after apply)
                    }

                  + volume {
                      + name = (known after apply)

                      + aws_elastic_block_store {
                          + fs_type   = (known after apply)
                          + partition = (known after apply)
                          + read_only = (known after apply)
                          + volume_id = (known after apply)
                        }

                      + azure_disk {
                          + caching_mode  = (known after apply)
                          + data_disk_uri = (known after apply)
                          + disk_name     = (known after apply)
                          + fs_type       = (known after apply)
                          + read_only     = (known after apply)
                        }

                      + azure_file {
                          + read_only   = (known after apply)
                          + secret_name = (known after apply)
                          + share_name  = (known after apply)
                        }

                      + ceph_fs {
                          + monitors    = (known after apply)
                          + path        = (known after apply)
                          + read_only   = (known after apply)
                          + secret_file = (known after apply)
                          + user        = (known after apply)

                          + secret_ref {
                              + name = (known after apply)
                            }
                        }

                      + cinder {
                          + fs_type   = (known after apply)
                          + read_only = (known after apply)
                          + volume_id = (known after apply)
                        }

                      + config_map {
                          + default_mode = (known after apply)
                          + name         = (known after apply)

                          + items {
                              + key  = (known after apply)
                              + mode = (known after apply)
                              + path = (known after apply)
                            }
                        }

                      + downward_api {
                          + default_mode = (known after apply)

                          + items {
                              + mode = (known after apply)
                              + path = (known after apply)

                              + field_ref {
                                  + api_version = (known after apply)
                                  + field_path  = (known after apply)
                                }

                              + resource_field_ref {
                                  + container_name = (known after apply)
                                  + quantity       = (known after apply)
                                  + resource       = (known after apply)
                                }
                            }
                        }

                      + empty_dir {
                          + medium = (known after apply)
                        }

                      + fc {
                          + fs_type      = (known after apply)
                          + lun          = (known after apply)
                          + read_only    = (known after apply)
                          + target_ww_ns = (known after apply)
                        }

                      + flex_volume {
                          + driver    = (known after apply)
                          + fs_type   = (known after apply)
                          + options   = (known after apply)
                          + read_only = (known after apply)

                          + secret_ref {
                              + name = (known after apply)
                            }
                        }

                      + flocker {
                          + dataset_name = (known after apply)
                          + dataset_uuid = (known after apply)
                        }

                      + gce_persistent_disk {
                          + fs_type   = (known after apply)
                          + partition = (known after apply)
                          + pd_name   = (known after apply)
                          + read_only = (known after apply)
                        }

                      + git_repo {
                          + directory  = (known after apply)
                          + repository = (known after apply)
                          + revision   = (known after apply)
                        }

                      + glusterfs {
                          + endpoints_name = (known after apply)
                          + path           = (known after apply)
                          + read_only      = (known after apply)
                        }

                      + host_path {
                          + path = (known after apply)
                          + type = (known after apply)
                        }

                      + iscsi {
                          + fs_type         = (known after apply)
                          + iqn             = (known after apply)
                          + iscsi_interface = (known after apply)
                          + lun             = (known after apply)
                          + read_only       = (known after apply)
                          + target_portal   = (known after apply)
                        }

                      + local {
                          + path = (known after apply)
                        }

                      + nfs {
                          + path      = (known after apply)
                          + read_only = (known after apply)
                          + server    = (known after apply)
                        }

                      + persistent_volume_claim {
                          + claim_name = (known after apply)
                          + read_only  = (known after apply)
                        }

                      + photon_persistent_disk {
                          + fs_type = (known after apply)
                          + pd_id   = (known after apply)
                        }

                      + quobyte {
                          + group     = (known after apply)
                          + read_only = (known after apply)
                          + registry  = (known after apply)
                          + user      = (known after apply)
                          + volume    = (known after apply)
                        }

                      + rbd {
                          + ceph_monitors = (known after apply)
                          + fs_type       = (known after apply)
                          + keyring       = (known after apply)
                          + rados_user    = (known after apply)
                          + rbd_image     = (known after apply)
                          + rbd_pool      = (known after apply)
                          + read_only     = (known after apply)

                          + secret_ref {
                              + name = (known after apply)
                            }
                        }

                      + secret {
                          + default_mode = (known after apply)
                          + optional     = (known after apply)
                          + secret_name  = (known after apply)

                          + items {
                              + key  = (known after apply)
                              + mode = (known after apply)
                              + path = (known after apply)
                            }
                        }

                      + vsphere_volume {
                          + fs_type     = (known after apply)
                          + volume_path = (known after apply)
                        }
                    }
                }
            }
        }
    }

  # kubernetes_service.fizzbuzz_service will be created
  + resource "kubernetes_service" "fizzbuzz_service" {
      + id                    = (known after apply)
      + load_balancer_ingress = (known after apply)

      + metadata {
          + generation       = (known after apply)
          + name             = "fizzbuzz-service"
          + namespace        = "default"
          + resource_version = (known after apply)
          + self_link        = (known after apply)
          + uid              = (known after apply)
        }

      + spec {
          + cluster_ip                  = (known after apply)
          + external_traffic_policy     = (known after apply)
          + publish_not_ready_addresses = false
          + selector                    = {
              + "app" = "fizzbuzz-blog"
            }
          + session_affinity            = "None"
          + type                        = "NodePort"

          + port {
              + node_port   = (known after apply)
              + port        = 8080
              + protocol    = "TCP"
              + target_port = "8080"
            }
        }
    }

Plan: 2 to add, 0 to change, 0 to destroy.

------------------------------------------------------------------------

Note: You didn't specify an "-out" parameter to save this plan, so Terraform
can't guarantee that exactly these actions will be performed if
"terraform apply" is subsequently run.
root@ip-172-31-13-209:~/EKS_Deploy#
```


## Download knd install kubectl
```
curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl
chmod +x kubectl
sudo mv kubectl /usr/local/bin
```

## Download the aws-iam-authenticator
```
wget https://github.com/kubernetes-sigs/aws-iam-authenticator/releases/download/v0.3.0/heptio-authenticator-aws_0.3.0_linux_amd64
chmod +x heptio-authenticator-aws_0.3.0_linux_amd64
sudo mv heptio-authenticator-aws_0.3.0_linux_amd64 /usr/local/bin/heptio-authenticator-aws
```

## Modify providers.tf
```
Choose your region. EKS is not available in every region.   
Make changes in providers.tf accordingly (region, optionally profile)
```

## Terraform apply
```
terraform init
terraform apply
```

## Configure kubectl
```
terraform output kubeconfig # save output in ~/.kube/config
aws eks --region <region> update-kubeconfig --name terraform-eks-demo
```

## Configure config-map-auth-aws
```
terraform output config-map-aws-auth # save output in config-map-aws-auth.yaml
kubectl apply -f config-map-aws-auth.yaml
```

## See nodes coming up
```
kubectl get nodes
```
