variable "name_prefix" { type = string }
variable "vpc_id" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "cluster_version" { type = string }

variable "endpoint_public_access" {
  description = "Whether the EKS control plane is reachable from outside the VPC."
  type        = bool
  default     = false
}

variable "public_access_cidrs" {
  description = "CIDR blocks that may reach the EKS public API when endpoint_public_access is true."
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for c in var.public_access_cidrs : (
        c != "0.0.0.0/0" && tonumber(element(split("/", c), 1)) >= 16
      )
    ])
    error_message = "Each public access CIDR must be /16 or more specific; 0.0.0.0/0 and overly broad ranges are not allowed."
  }
}
variable "node_groups" {
  type = map(object({
    instance_types = list(string)
    min_size       = number
    max_size       = number
    desired_size   = number
    disk_size      = number
    taints         = optional(list(object({ key = string, value = string, effect = string })), [])
  }))
}
