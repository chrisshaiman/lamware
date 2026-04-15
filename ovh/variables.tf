# =============================================================================
# OVH module — variables
# =============================================================================

# -----------------------------------------------------------------------------
# OVH API credentials
# Create at: https://api.us.ovhcloud.com/createApp/
# Required rights: /dedicated/server/* (READ/WRITE), /ip/* (READ/WRITE)
# Store in terraform.tfvars — never commit to git.
# -----------------------------------------------------------------------------

variable "ovh_application_key" {
  type        = string
  sensitive   = true
  description = "OVH API application key"
}

variable "ovh_application_secret" {
  type        = string
  sensitive   = true
  description = "OVH API application secret"
}

variable "ovh_consumer_key" {
  type        = string
  sensitive   = true
  description = "OVH API consumer key"
}

# -----------------------------------------------------------------------------
# Server
# -----------------------------------------------------------------------------

variable "server_name" {
  type        = string
  description = "OVH service name for the dedicated server (e.g. 'ns123456.ip-1-2-3.eu'). Found in the OVH manager under Bare Metal Cloud → Dedicated Servers."
}

variable "name_prefix" {
  type        = string
  default     = "malware-sandbox"
  description = "Prefix applied to named resources"
}

variable "hostname" {
  type        = string
  default     = "sandbox"
  description = "Hostname set during OS installation"
}

variable "os_template" {
  type        = string
  default     = "ubuntu2404-server_64"
  description = "OVH OS template name. Run 'ovh-cli dedicated server availableTemplates' to list options. Ubuntu 24.04 is Cape's recommended target OS."
}

variable "no_raid" {
  type        = bool
  default     = false
  description = "Disable RAID during OS installation. Default false keeps RAID as OVH configures it (typically RAID 1 on dual-disk servers). Set true only if you need disks independent."
}

# -----------------------------------------------------------------------------
# Security
# -----------------------------------------------------------------------------

variable "admin_cidrs" {
  type        = list(string)
  description = "CIDRs allowed to reach SSH (22/tcp) and WireGuard (UDP) on the robot firewall. Must be set explicitly — no default. Use your static IP(s) in CIDR notation (e.g. ['203.0.113.10/32']). Max 10 entries."

  validation {
    condition     = length(var.admin_cidrs) > 0 && length(var.admin_cidrs) <= 10
    error_message = "admin_cidrs must contain between 1 and 10 entries (robot firewall sequences 0–9 for SSH, 10–19 for WireGuard)."
  }
}

variable "ssh_public_key" {
  type        = string
  description = "Admin SSH public key injected during OS installation. Use Ed25519: 'ssh-keygen -t ed25519 -f ~/.ssh/sandbox_ed25519'"
}

variable "wireguard_port" {
  type        = number
  default     = 51820
  description = "WireGuard UDP listen port. Robot firewall opens this port from admin_cidrs. Default 51820 is the WireGuard standard."
}
