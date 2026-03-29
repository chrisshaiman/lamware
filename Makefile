# =============================================================================
# Malware Sandbox Infrastructure — Makefile
# Single entry point for the full build/deploy pipeline.
#
# Usage:
#   make image       — build Packer base image
#   make infra       — provision infrastructure with Terraform
#   make configure   — configure host with Ansible
#   make all         — image + infra + configure
#
# Author: Christopher Shaiman
# License: Apache 2.0
# =============================================================================

.PHONY: all image infra-ovh infra-aws configure validate clean help

# -----------------------------------------------------------------------------
# Configuration — override via environment or .env file
# -----------------------------------------------------------------------------

AWS_ENV         ?= prod
ANSIBLE_USER    ?= root
PACKER_DIR      := packer
ANSIBLE_DIR     := ansible
OVH_DIR         := ovh
AWS_DIR         := aws/envs/$(AWS_ENV)

# Load .env if it exists (local secrets, not committed)
-include .env

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------

help:
	@echo ""
	@echo "Malware Sandbox Infrastructure"
	@echo "================================"
	@echo ""
	@echo "  make image              Build Packer base image"
	@echo "  make infra-ovh          Provision OVH bare metal"
	@echo "  make infra-aws          Provision AWS supporting infra"
	@echo "  make configure          Run Ansible against provisioned host"
	@echo "  make all                Full pipeline: image + infra + configure"
	@echo "  make validate           Validate Packer + Terraform configs"
	@echo "  make clean              Remove local build artifacts"
	@echo ""
	@echo "  AWS_ENV=prod            AWS environment (prod | staging)"
	@echo ""

# -----------------------------------------------------------------------------
# Full pipeline
# -----------------------------------------------------------------------------

all: image infra-ovh infra-aws configure

# -----------------------------------------------------------------------------
# Packer — build hardened base image
# Outputs qcow2 to packer/output/ then uploads snapshot to OVH
# -----------------------------------------------------------------------------

image:
	@echo "==> Building Packer base image..."
	@cd $(PACKER_DIR) && \
		packer init . && \
		packer validate . && \
		packer build ubuntu-sandbox.pkr.hcl
	@echo "==> Image build complete."

# -----------------------------------------------------------------------------
# Terraform — OVH bare metal
# -----------------------------------------------------------------------------

infra-ovh:
	@echo "==> Provisioning OVH infrastructure..."
	@[ -f $(OVH_DIR)/terraform.tfvars ] || \
		(echo "ERROR: $(OVH_DIR)/terraform.tfvars not found. Copy terraform.tfvars.example and fill in values." && exit 1)
	@cd $(OVH_DIR) && \
		terraform init \
			-backend-config="../shared/backend-aws.hcl" && \
		terraform plan \
			-out=tfplan && \
		terraform apply tfplan
	@echo "==> OVH provisioning complete."
	@echo "==> Writing Ansible inventory..."
	@cd $(OVH_DIR) && \
		terraform output -raw sandbox_public_ip > ../ansible/inventory/hosts

infra-aws:
	@echo "==> Provisioning AWS infrastructure..."
	@[ -f $(AWS_DIR)/terraform.tfvars ] || \
		(echo "ERROR: $(AWS_DIR)/terraform.tfvars not found." && exit 1)
	@cd $(AWS_DIR) && \
		terraform init \
			-backend-config="../../shared/backend-aws.hcl" && \
		terraform plan \
			-out=tfplan && \
		terraform apply tfplan
	@echo "==> AWS provisioning complete."

# -----------------------------------------------------------------------------
# Ansible — configure the host
# Runs after Terraform writes the inventory file
# -----------------------------------------------------------------------------

configure:
	@echo "==> Configuring host with Ansible..."
	@[ -f $(ANSIBLE_DIR)/inventory/hosts ] || \
		(echo "ERROR: ansible/inventory/hosts not found. Run make infra-ovh first." && exit 1)
	@cd $(ANSIBLE_DIR) && \
		ansible-playbook \
			-i inventory/hosts \
			-u $(ANSIBLE_USER) \
			--private-key ~/.ssh/sandbox_ed25519 \
			site.yml
	@echo "==> Configuration complete."

# -----------------------------------------------------------------------------
# Validation — run before committing
# -----------------------------------------------------------------------------

validate:
	@echo "==> Validating Packer..."
	@cd $(PACKER_DIR) && packer init . && packer validate .
	@echo "==> Validating OVH Terraform..."
	@cd $(OVH_DIR) && terraform init -backend=false && terraform validate
	@echo "==> Validating AWS Terraform modules..."
	@for dir in aws/modules/*/; do \
		echo "  Validating $$dir..."; \
		cd $$dir && terraform init -backend=false && terraform validate && cd ../../..; \
	done
	@echo "==> Validating Ansible..."
	@cd $(ANSIBLE_DIR) && ansible-playbook --syntax-check -i inventory/hosts site.yml
	@echo "==> All validation passed."

# -----------------------------------------------------------------------------
# Clean
# -----------------------------------------------------------------------------

clean:
	@echo "==> Cleaning build artifacts..."
	@rm -rf $(PACKER_DIR)/output/
	@find . -name "tfplan" -delete
	@find . -name ".terraform" -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.tfstate.backup" -delete
	@echo "==> Clean complete."
