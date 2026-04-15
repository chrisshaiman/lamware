# =============================================================================
# OVH module — outputs
# =============================================================================

output "sandbox_public_ip" {
  value       = data.ovh_dedicated_server.sandbox.ip
  description = "Public IP of the bare metal host. Written to ansible/inventory/hosts by 'make infra-ovh'."
}

output "server_name" {
  value       = data.ovh_dedicated_server.sandbox.service_name
  description = "OVH service name for the server — use for subsequent API calls or manual OVH manager operations."
}

