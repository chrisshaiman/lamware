# =============================================================================
# OVH bare metal — malware analysis sandbox host
#
# Provisions an existing OVH dedicated server (pre-ordered via OVH manager):
#   1. Registers the admin SSH public key with OVH account
#   2. Enables the OVH robot firewall on the server IP (network-edge, pre-OS)
#   3. Adds allowlist rules: SSH (22/tcp) + WireGuard (UDP) from admin CIDRs
#   4. Installs Ubuntu 24.04 LTS with SSH key injection
#
# The robot firewall closes the exposure window between OS boot and iptables
# becoming active — see docs/SECURITY_CONSTRAINTS.md.
#
# After apply, run: make configure
# Ansible handles all runtime configuration (KVM, Cape, WireGuard, sqs-agent).
# =============================================================================

terraform {
  required_version = ">= 1.6"

  required_providers {
    ovh = {
      source  = "ovh/ovh"
      version = "~> 0.44"
    }
  }

  backend "s3" {
    # Connection details (bucket, region, dynamodb_table) come from
    # shared/backend-aws.hcl via: terraform init -backend-config=../shared/backend-aws.hcl
    # Key is set here to avoid clobbering the AWS prod state.
    key = "prod/ovh/terraform.tfstate"
  }
}

provider "ovh" {
  # OVHcloud US endpoint — matches ADR-002 (US jurisdiction requirement)
  # API credentials: create at https://api.us.ovhcloud.com/createApp/
  endpoint           = "ovh-us"
  application_key    = var.ovh_application_key
  application_secret = var.ovh_application_secret
  consumer_key       = var.ovh_consumer_key
}

# =============================================================================
# Existing server — pre-ordered via OVH manager
# service_name is the OVH reference, e.g. "ns123456.ip-1-2-3.eu"
# =============================================================================

data "ovh_dedicated_server" "sandbox" {
  service_name = var.server_name
}

# =============================================================================
# Admin SSH key — registered at OVH account level, injected during OS install
# =============================================================================

resource "ovh_me_ssh_key" "admin" {
  key_name = "${var.name_prefix}-admin"
  key      = var.ssh_public_key
}

# =============================================================================
# Robot firewall — network-edge allowlist, active before the OS boots
#
# OVH's hardware firewall drops all traffic not matching a permit rule.
# Rules are evaluated in sequence order (0 = highest priority).
# Sequences 0–9 reserved for SSH, 10–19 for WireGuard.
# Max 10 admin CIDRs supported per service type.
#
# IMPORTANT: firewall must be enabled and rules applied before OS installation.
# The depends_on chain enforces this ordering.
# =============================================================================

resource "ovh_ip_firewall" "sandbox" {
  ip             = "${data.ovh_dedicated_server.sandbox.ip}/32"
  ip_on_firewall = data.ovh_dedicated_server.sandbox.ip
  enabled        = true
}

# Allow SSH from each admin CIDR (sequences 0–9)
# SSH is required for Ansible runs and emergency manual access.
resource "ovh_ip_firewall_rule" "allow_ssh" {
  for_each = { for idx, cidr in var.admin_cidrs : tostring(idx) => cidr }

  ip               = "${data.ovh_dedicated_server.sandbox.ip}/32"
  ip_on_firewall   = data.ovh_dedicated_server.sandbox.ip
  sequence         = tonumber(each.key)
  action           = "permit"
  protocol         = "tcp"
  destination_port = "22"
  source           = each.value

  depends_on = [ovh_ip_firewall.sandbox]
}

# Allow WireGuard UDP from each admin CIDR (sequences 10–19)
# WireGuard is admin-only management VPN — see ADR-004.
resource "ovh_ip_firewall_rule" "allow_wireguard" {
  for_each = { for idx, cidr in var.admin_cidrs : tostring(idx) => cidr }

  ip               = "${data.ovh_dedicated_server.sandbox.ip}/32"
  ip_on_firewall   = data.ovh_dedicated_server.sandbox.ip
  sequence         = 10 + tonumber(each.key)
  action           = "permit"
  protocol         = "udp"
  destination_port = tostring(var.wireguard_port)
  source           = each.value

  depends_on = [ovh_ip_firewall.sandbox]
}

# =============================================================================
# OS installation — Ubuntu 24.04 LTS
#
# Runs once at provision time. Ansible handles all subsequent configuration.
# lifecycle ignore_changes prevents accidental reinstall (which wipes the host)
# on subsequent terraform apply calls.
#
# Firewall rules must exist before the install starts so SSH is reachable
# when the installer completes and reboots.
# =============================================================================

resource "ovh_dedicated_server_install_task" "os" {
  service_name  = data.ovh_dedicated_server.sandbox.service_name
  template_name = var.os_template

  details {
    custom_hostname    = var.hostname
    ssh_key_name       = ovh_me_ssh_key.admin.key_name
    use_distrib_kernel = true
    no_raid            = var.no_raid
  }

  timeouts {
    create = "90m"  # OVH OS installs can be slow; 90 min is conservative
  }

  lifecycle {
    # OS installation is a one-time operation. Ignore all subsequent changes
    # to prevent accidental host wipe on terraform apply.
    ignore_changes = all
  }

  # Firewall must be active before OS boots so SSH is reachable post-install
  depends_on = [
    ovh_ip_firewall_rule.allow_ssh,
    ovh_ip_firewall_rule.allow_wireguard,
  ]
}
