variable "aws_region" {
  type        = string
  description = "AWS region for the lab."
  default     = "ap-northeast-2"
}

variable "vpc_cidr" {
  type        = string
  description = "Dedicated lab VPC CIDR."
  default     = "10.20.0.0/16"
}

variable "scanner_subnet_cidr" {
  type    = string
  default = "10.20.1.0/24"
}

variable "target_subnet_cidr" {
  type    = string
  default = "10.20.2.0/24"
}

variable "instance_type" {
  type        = string
  description = "Small x86 instance type for both lab instances."
  default     = "t3.micro"
}

variable "enable_demo_misconfiguration" {
  type        = bool
  description = "When true, adds Internet-wide SSH ingress to the private target SG for analyzer demonstration. The target still receives no public IP."
  default     = false
}

variable "flow_log_retention_days" {
  type    = number
  default = 1
  validation {
    condition     = contains([1, 3, 5, 7, 14, 30], var.flow_log_retention_days)
    error_message = "Use a short supported CloudWatch Logs retention period for the lab."
  }
}
