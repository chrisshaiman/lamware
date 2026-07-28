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
# Ansible handles all runtime configuration (KVM, Cape, WireGuard, pipeline, API).
# =============================================================================

terraform {
  required_version = ">= 1.6"

  required_providers {
    ovh = {
      source  = "ovh/ovh"
      version = "~> 2.0"
    }
  }

  # Local state — AWS S3 backend removed (ADR-016)
  backend "local" {}
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
# Robot firewall — network-edge allowlist, active before the OS boots
#
# OVH's hardware firewall evaluates rules in sequence order (0 = highest priority).
# Layout:
#   0–4:  SSH (22/tcp) from admin CIDRs
#   5:    WireGuard (UDP) from anywhere (protocol auth handles access)
#   10:   HTTPS (443/tcp) from anywhere
#   11:   HTTP (80/tcp) from anywhere
#   18:   TCP established (return traffic for outbound connections)
#   19:   Deny all (default drop)
# Max 5 admin CIDRs for SSH.
#
# IMPORTANT: firewall must be enabled and rules applied before OS installation.
# The depends_on chain enforces this ordering.
# =============================================================================

resource "ovh_ip_firewall" "sandbox" {
  ip             = "${data.ovh_dedicated_server.sandbox.ip}/32"
  ip_on_firewall = data.ovh_dedicated_server.sandbox.ip
  enabled        = true
}

# Allow SSH from each admin CIDR (sequences 0–4)
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

# Allow WireGuard UDP from anywhere (sequence 5)
# WireGuard is cryptographically authenticated — unauthenticated packets are
# silently dropped by the protocol itself. Safe to expose publicly, and
# required for mobile access where source IPs are unpredictable (carrier NAT).
resource "ovh_ip_firewall_rule" "allow_wireguard" {
  ip               = "${data.ovh_dedicated_server.sandbox.ip}/32"
  ip_on_firewall   = data.ovh_dedicated_server.sandbox.ip
  sequence         = 5
  action           = "permit"
  protocol         = "udp"
  destination_port = tostring(var.wireguard_port)
  source           = "0.0.0.0/0"

  depends_on = [ovh_ip_firewall.sandbox]
}

# Allow HTTPS from anywhere (sequence 10)
# Public web access to lamware dashboard and Keycloak.
resource "ovh_ip_firewall_rule" "allow_https" {
  ip               = "${data.ovh_dedicated_server.sandbox.ip}/32"
  ip_on_firewall   = data.ovh_dedicated_server.sandbox.ip
  sequence         = 10
  action           = "permit"
  protocol         = "tcp"
  destination_port = "443"
  source           = "0.0.0.0/0"

  depends_on = [ovh_ip_firewall.sandbox]
}

# Allow HTTP from anywhere (sequence 11)
# Required for Let's Encrypt ACME HTTP-01 challenges and HTTPS redirect.
resource "ovh_ip_firewall_rule" "allow_http" {
  ip               = "${data.ovh_dedicated_server.sandbox.ip}/32"
  ip_on_firewall   = data.ovh_dedicated_server.sandbox.ip
  sequence         = 11
  action           = "permit"
  protocol         = "tcp"
  destination_port = "80"
  source           = "0.0.0.0/0"

  depends_on = [ovh_ip_firewall.sandbox]
}

# Allow established TCP connections (sequence 18)
# OVH robot firewall is stateless — it does not track TCP sessions.
# Without this rule, return packets from outbound connections (apt, DNS,
# curl, etc.) are dropped by the deny-all. The "established" TCP option
# permits packets with ACK flag set (i.e., part of an existing connection).
resource "ovh_ip_firewall_rule" "allow_established" {
  ip               = "${data.ovh_dedicated_server.sandbox.ip}/32"
  ip_on_firewall   = data.ovh_dedicated_server.sandbox.ip
  sequence         = 18
  action           = "permit"
  protocol         = "tcp"
  source           = "0.0.0.0/0"
  tcp_option        = "established"

  depends_on = [ovh_ip_firewall.sandbox]
}

# Deny all — default drop for anything not matched above (sequence 19)
# Must be highest sequence number (lowest priority) so permit rules match first.
resource "ovh_ip_firewall_rule" "deny_all" {
  ip               = "${data.ovh_dedicated_server.sandbox.ip}/32"
  ip_on_firewall   = data.ovh_dedicated_server.sandbox.ip
  sequence         = 19
  action           = "deny"
  protocol         = "ipv4"

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

resource "ovh_dedicated_server_reinstall_task" "os" {
  service_name = data.ovh_dedicated_server.sandbox.service_name
  os            = var.os_template

  customizations {
    hostname = var.hostname
    ssh_key  = var.ssh_public_key
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
