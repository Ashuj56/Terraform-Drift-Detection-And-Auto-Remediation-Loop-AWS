variable "project_name" {
  type = string
}

variable "cluster_version" {
  type = string
}

variable "eks_cluster_role_arn" {
  type = string
}

variable "eks_node_group_role_arn" {
  type = string
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "eks_cluster_sg_id" {
  type = string
}

variable "node_instance_type" {
  type = string
}

variable "desired_nodes" {
  type = number
}

variable "min_nodes" {
  type = number
}

variable "max_nodes" {
  type = number
}
