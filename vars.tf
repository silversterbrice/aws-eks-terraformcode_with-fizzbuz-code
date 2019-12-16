variable "cluster-name" {
  default = "terraform-eks-cluster"
  type    = string
}

variable "region" {
  default = "us-west-2"
  type = string
}

variable "instancetype" {
  default = "t2.large"
  type = string
}
