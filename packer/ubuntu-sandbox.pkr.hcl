# =============================================================================
# packer/ubuntu-sandbox.pkr.hcl — STUB
# Claude Code: implement this file.
#
# Goal: Build a hardened Ubuntu 24.04 base image for the sandbox host.
#
# What it should do:
#   1. Start from Ubuntu 24.04 LTS server ISO (autoinstall / cloud-init)
#   2. Use QEMU builder with KVM accelerator
#   3. Run konstruktoid/ansible-role-hardening as Ansible provisioner
#   4. Install KVM/QEMU/libvirt deps (apt packages only — no config yet)
#   5. Clone CAPEv2 repo to /opt/CAPEv2
#   6. Install Cape Python deps (pip install -r requirements.txt)
#   7. Install AWS CLI
#   8. Do NOT run kvm-qemu.sh or cape2.sh — Ansible handles those
#   9. Output: qcow2 image
#  10. Post-processor: upload snapshot to provider (var.provider)
#
# Reference implementations to adapt from:
#   - konstruktoid/hardened-images (GitHub) — hardening + Packer HCL patterns
#   - boxcutter/kvm (GitHub) — QEMU/KVM builder patterns in HCL
#   - puppeteers.net blog — Ubuntu 24.04 autoinstall with Packer QEMU
#
# Variables needed:
#   - ovh_application_key (sensitive)
#   - ovh_application_secret (sensitive)
#   - ovh_consumer_key (sensitive)
#   - ubuntu_iso_url + checksum
# =============================================================================

packer {
  required_version = ">= 1.10"

  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1.0"
    }
    ansible = {
      source  = "github.com/hashicorp/ansible"
      version = "~> 1.0"
    }
  }
}

variable "provider" {
  type    = string
  default = "ovh"
}

# STUB — implement source and build blocks
# See file header for full spec.
