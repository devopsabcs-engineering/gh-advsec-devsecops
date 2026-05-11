variable "subscription_id" {
  type        = string
  description = "The subscription ID to be scanned"
  default     = null
}

variable "location" {
  type    = string
  default = "East US"
}

variable "environment" {
  default     = "dev"
  description = "Must be all lowercase letters or numbers"
}

variable "admin_ip_range" {
  type        = string
  description = "IP address range allowed for administrative access (SSH/RDP)"
  default     = "0.0.0.0/0"  # Replace with your actual IP range in production
}