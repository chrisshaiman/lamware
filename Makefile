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

.PHONY: all image win11-base win11-guest win11-office win11-image autounattend-floppy infra-ovh configure validate clean packer-setup help deploy security-test smoke smoke-setup

# -----------------------------------------------------------------------------
# Configuration — override via environment or .env file
# -----------------------------------------------------------------------------

ANSIBLE_USER    ?= root
PACKER_DIR      := packer
ANSIBLE_DIR     := ansible
SMOKE_DIR       := tests/smoke
OVH_DIR         := ovh

# OVMF firmware vars template — must match ovmf_vars default in windows11-base.pkr.hcl.
# Empty VARS (not .ms.fd): no pre-built PXE/HTTP boot entries, OVMF drops to
# UEFI shell so boot_command can type the ISO path. Override in .env if needed.
OVMF_VARS_TEMPLATE ?= /usr/share/OVMF/OVMF_VARS_4M.fd
# Path for the writable OVMF VARS file — must be OUTSIDE the packer output directory.
# packer -force deletes the output directory before QEMU starts; keeping efivars.fd
# here ensures it survives that cleanup. Must match efivars_path in windows11-base.pkr.hcl.
EFIVARS_PATH       ?= /tmp/packer-win11-efivars.fd

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
	@echo "  make packer-setup         One-time: generate build password + install Ansible hardening role"
	@echo "  make autounattend-floppy  Create autounattend floppy image for Windows 11 builds (run once per XML change)"
	@echo "  make win11-base           Build Windows 11 base image (WinRM enabled, no cleanup)"
	@echo "  make win11-guest          Build clean guest from base (cleanup only)"
	@echo "  make win11-office         Build office guest from base (LibreOffice + cleanup)"
	@echo "  make win11-image          Build all Win11 images (base + guest + office)"
	@echo "  make image                Build Ubuntu sandbox base image"
	@echo "  make infra-ovh            Provision OVH bare metal"
	@echo "  make configure            Run Ansible against provisioned host"
	@echo "  make all                  Full pipeline: image + infra + configure"
	@echo "  make validate             Validate Packer + Terraform configs"
	@echo "  make deploy TAGS=api      Deploy specific roles + run security tests"
	@echo "  make security-test        Run post-deploy security smoke tests only"
	@echo "  make clean                Remove local build artifacts"
	@echo ""
	@echo "  First-time setup order:"
	@echo "    1. make win11-image"
	@echo "    2. make infra-ovh"
	@echo "    3. make configure"
	@echo ""

# -----------------------------------------------------------------------------
# Full pipeline
# -----------------------------------------------------------------------------

all: image infra-ovh configure

# -----------------------------------------------------------------------------
# packer-setup — one-time setup before first packer build
# Generates the build password hash and installs the Ansible hardening role.
# Run this once, then follow the printed instructions.
# -----------------------------------------------------------------------------

packer-setup:
	@echo "==> Installing konstruktoid.hardening Ansible role..."
	@ansible-galaxy install konstruktoid.hardening -p $(PACKER_DIR)/ansible/roles
	@echo ""
	@echo "==> Generating build password hash..."
	@echo "    Enter a password for the Packer build user (used only during image build):"
	@read -s PW && \
		HASH=$$(openssl passwd -6 "$$PW") && \
		echo "" && \
		echo "  1. Replace the placeholder in packer/http/user-data identity.password with:" && \
		echo "     $$HASH" && \
		echo "" && \
		echo "  2. Create packer/packer.auto.pkrvars.hcl with:" && \
		echo '     ssh_password = "'$$PW'"'
	@echo ""
	@echo "==> packer-setup complete. Update user-data and pkrvars, then run: make image"

# -----------------------------------------------------------------------------
# autounattend-floppy — create a 1.44 MB FAT12 floppy image with autounattend.xml
# at the root. WinPE checks A: before all other drives — reliable regardless of ISO
# filesystem type. Run once; re-run whenever answer-files/win11-autounattend.xml changes.
# Requires mtools (apt-get install mtools).
# Override the output path with: make autounattend-floppy AUTOUNATTEND_IMG=/your/path
# The path must match autounattend_img_path in packer.auto.pkrvars.hcl.
# -----------------------------------------------------------------------------

AUTOUNATTEND_IMG ?= $(PACKER_DIR)/output/autounattend.img

autounattend-floppy:
	@echo "==> Creating autounattend floppy image at $(AUTOUNATTEND_IMG)..."
	@command -v mformat >/dev/null 2>&1 || \
		(echo "ERROR: mtools not found. Run: sudo apt-get install mtools" && exit 1)
	@mkdir -p $(dir $(AUTOUNATTEND_IMG))
	@dd if=/dev/zero of=$(AUTOUNATTEND_IMG) bs=512 count=2880 2>/dev/null
	@mformat -i $(AUTOUNATTEND_IMG) -f 1440 ::
	@mcopy -i $(AUTOUNATTEND_IMG) \
		$(PACKER_DIR)/answer-files/win11-autounattend.xml \
		::/autounattend.xml
	@echo "==> $(AUTOUNATTEND_IMG) ready."

# -----------------------------------------------------------------------------
# win11-base — build Windows 11 base builder image (WinRM enabled, no cleanup)
# This is the foundation for win11-guest and win11-office.
# Expect 45-90 minutes. Run inside tmux/screen.
# -----------------------------------------------------------------------------

win11-base: autounattend-floppy
	@echo "==> Building Windows 11 base image..."
	@[ -f $(PACKER_DIR)/packer.auto.pkrvars.hcl ] || \
		(echo "ERROR: packer/packer.auto.pkrvars.hcl not found." && exit 1)
	@[ -f $(OVMF_VARS_TEMPLATE) ] || \
		(echo "ERROR: OVMF VARS not found at $(OVMF_VARS_TEMPLATE). Run: sudo apt-get install ovmf" && exit 1)
	@echo "==> Copying fresh OVMF VARS to $(EFIVARS_PATH) (clears stale NVRAM boot entries)..."
	@cp $(OVMF_VARS_TEMPLATE) $(EFIVARS_PATH)
	@cd $(PACKER_DIR) && \
		packer init windows11-base.pkr.hcl && \
		packer build -force -var-file=packer.auto.pkrvars.hcl windows11-base.pkr.hcl
	@echo "==> Windows 11 base image complete. Now run: make win11-guest and/or make win11-office"

# win11-guest — production "clean" image (runs cleanup on base)
# Expect ~5 minutes.
# -----------------------------------------------------------------------------

win11-guest:
	@echo "==> Building Windows 11 guest (clean) image from base..."
	@cd $(PACKER_DIR) && \
		packer init windows11-guest.pkr.hcl && \
		packer build -var-file=packer.auto.pkrvars.hcl windows11-guest.pkr.hcl
	@echo "==> Windows 11 guest image complete."

# win11-office — production "office" image (LibreOffice + cleanup on base)
# Expect ~15 minutes.
# -----------------------------------------------------------------------------

win11-office:
	@echo "==> Building Windows 11 office image from base..."
	@cd $(PACKER_DIR) && \
		packer init windows11-office.pkr.hcl && \
		packer build -var-file=packer.auto.pkrvars.hcl windows11-office.pkr.hcl
	@echo "==> Windows 11 office image complete."

# win11-image — build all Windows 11 images (base → guest + office)
# Convenience target. Run inside tmux/screen.
# -----------------------------------------------------------------------------

win11-image: win11-base win11-guest win11-office
	@echo "==> All Windows 11 images complete."

# -----------------------------------------------------------------------------
# Packer — build hardened base image
# Outputs qcow2 to packer/output/ then uploads snapshot to OVH via BYOI API.
# Run make packer-setup first if this is your first build.
# -----------------------------------------------------------------------------

image:
	@echo "==> Checking packer-setup prerequisites..."
	@grep -q "PLACEHOLDER" $(PACKER_DIR)/http/user-data && \
		(echo "ERROR: packer/http/user-data still has placeholder password hash. Run: make packer-setup" && exit 1) || true
	@[ -f $(PACKER_DIR)/packer.auto.pkrvars.hcl ] || \
		(echo "ERROR: packer/packer.auto.pkrvars.hcl not found. Run: make packer-setup" && exit 1)
	@echo "==> Building Packer base image..."
	@cd $(PACKER_DIR) && \
		packer init . && \
		packer validate . && \
		packer build ubuntu-sandbox.pkr.hcl
	@echo "==> Image build complete: packer/output/ubuntu-sandbox.qcow2"
	@echo "==> Next: upload to S3 and deploy via OVH BYOI API"

# -----------------------------------------------------------------------------
# Terraform — OVH bare metal
# -----------------------------------------------------------------------------

# NOTE (#211): this still stores OVH state in the AWS S3 backend created by the
# now-deleted aws/bootstrap module. That bucket's state is at serial 17 with zero
# resources, i.e. it was destroyed — so `terraform init` here will fail until the
# backend is repointed. Left as-is deliberately: where state lives is an
# infrastructure decision, not part of a code cleanup. Tracked separately.
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

# -----------------------------------------------------------------------------
# Ansible — configure the host
# Runs after Terraform writes the inventory file
# -----------------------------------------------------------------------------

configure:
	@echo "==> Configuring host with Ansible..."
	@[ -f $(ANSIBLE_DIR)/inventory/hosts ] || \
		(echo "ERROR: ansible/inventory/hosts not found. Run make infra-ovh first." && exit 1)
	@echo "==> Installing Ansible Galaxy requirements..."
	@ansible-galaxy install -r $(ANSIBLE_DIR)/requirements.yml --force-with-deps
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
	@echo "==> Validating Ansible..."
	@cd $(ANSIBLE_DIR) && ansible-playbook --syntax-check -i inventory/hosts site.yml
	@echo "==> All validation passed."

# -----------------------------------------------------------------------------
# Deploy + security test — deploy specific roles then run smoke tests
# Usage: make deploy TAGS=api,frontend
# -----------------------------------------------------------------------------

TAGS ?= api,frontend

deploy:
	@echo "==> Deploying roles: $(TAGS)..."
	@cd $(ANSIBLE_DIR) && \
		ansible-playbook \
			-i inventory/hosts \
			site.yml \
			--tags $(TAGS) \
			--ask-vault-pass
	@echo "==> Running post-deploy security tests..."
	@cd $(ANSIBLE_DIR) && \
		ansible-playbook \
			-i inventory/hosts \
			security-test.yml \
			--ask-vault-pass
	@echo "==> Running post-deploy smoke gate..."
	@$(MAKE) smoke
	@echo "==> Deploy + test + smoke complete."

security-test:
	@echo "==> Running security smoke tests..."
	@cd $(ANSIBLE_DIR) && \
		ansible-playbook \
			-i inventory/hosts \
			security-test.yml \
			--ask-vault-pass
	@echo "==> Security tests complete."

smoke-setup:
	@echo "==> Setting up smoke-gate venv + Chromium..."
	@cd $(SMOKE_DIR) && python3.12 -m venv .venv
	@cd $(SMOKE_DIR) && ./.venv/bin/pip -q install -r requirements.txt
	@cd $(SMOKE_DIR) && ./.venv/bin/playwright install chromium
	@echo "==> Smoke gate ready. Run 'make smoke'."

smoke:
	@echo "==> Running Playwright smoke gate against $${SMOKE_BASE_URL:-https://lamware.shaiman.net}..."
	@if [ ! -x "$(SMOKE_DIR)/.venv/bin/python" ]; then \
		echo "ERROR: smoke venv missing. Run 'make smoke-setup' first." && exit 1; \
	fi
	@PW_PASS="$$SMOKE_TEST_PASSWORD"; \
	if [ -z "$$PW_PASS" ]; then \
		echo "==> Extracting smoke test password from vault (enter vault pass)..."; \
		PW_PASS=$$(cd $(ANSIBLE_DIR) && ansible-vault view vars/secrets.yml \
			| sed -n 's/^keycloak_smoke_test_password:[[:space:]]*//p' | tr -d '"' | head -n1); \
	fi; \
	if [ -z "$$PW_PASS" ]; then \
		echo "ERROR: could not resolve SMOKE_TEST_PASSWORD (env or vault)." && exit 1; \
	fi; \
	SMOKE_TEST_PASSWORD="$$PW_PASS" $(SMOKE_DIR)/.venv/bin/python -m pytest $(SMOKE_DIR) -q || { \
		echo "==================== SMOKE GATE FAILED ===================="; \
		if [ -n "$$NTFY_TOPIC" ]; then \
			curl -s -H "Title: lamware smoke gate FAILED" -H "Priority: urgent" \
				-H "Tags: rotating_light" \
				-d "Post-deploy Playwright smoke gate failed" \
				"https://ntfy.sh/$$NTFY_TOPIC" >/dev/null 2>&1 || true; \
		fi; \
		exit 1; \
	}
	@echo "==> Smoke gate passed."

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
