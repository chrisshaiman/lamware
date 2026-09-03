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

.PHONY: provenance provenance-has all image collections-check build-preflight win11-base win11-guest win11-office win11-image autounattend-floppy infra-ovh configure validate clean packer-setup help deploy security-test smoke smoke-setup

# -----------------------------------------------------------------------------
# Configuration — override via environment or .env file
# -----------------------------------------------------------------------------

# `ubuntu`, not `root`: the hardening role writes PermitRootLogin no into
# /etc/ssh/sshd_config.d/01-hardening.conf during the FIRST site.yml run, so root
# SSH stops working the moment the playbook it is meant to run has succeeded once.
# The ubuntu user ships with the OVH Ubuntu image, is the sole member of the sudo
# group that sshd's AllowGroups permits, and has passwordless sudo — which is what
# site.yml's `become: true` needs. For the one pre-hardening bootstrap run against
# a freshly reinstalled box, override: make configure ANSIBLE_USER=root
ANSIBLE_USER    ?= ubuntu
# Overridable so a second workstation with its own per-device keypair does not have
# to rename its key or symlink it into place.
ANSIBLE_KEY     ?= ~/.ssh/sandbox_ed25519
# SSH alias (or user@host) used by the provenance targets to read the deploy
# marker. Defaults to the ~/.ssh/config alias; override if yours differs:
#   make provenance ANSIBLE_HOST_ALIAS=ubuntu@10.200.0.1
ANSIBLE_HOST_ALIAS ?= sandbox
PACKER_DIR      := packer

# `--syntax-check` still loads vars_files, and vars/secrets.yml is vault-encrypted, so
# the check needs a vault password or it fails with "Attempting to decrypt but no vault
# secrets found" — which reads like a broken playbook rather than a missing argument.
# Uses ~/.vault_pass when it exists, otherwise prompts. Override explicitly:
#   make validate VAULT_ARGS="--vault-password-file /path/to/pass"
VAULT_PASS_FILE ?= $(HOME)/.vault_pass
VAULT_ARGS      ?= $(if $(wildcard $(VAULT_PASS_FILE)),--vault-password-file $(VAULT_PASS_FILE),--ask-vault-pass)
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
	@echo "  make build-preflight      Check every prerequisite for the Windows image build"
	@echo "  make packer-setup         One-time (UBUNTU image only): build password + hardening role"
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

# Where win11-base leaves its artifact. Read from the same pkrvars packer uses,
# so the two cannot disagree; falls back to packer's default output dir.
#
# win11-guest and win11-office need this path AND its sha256. Both were left to
# be hand-filled in pkrvars after the base build (#522) -- discovered only after
# the 45-90 minute step, and wrong again the moment the image is touched, which
# it is: the offline Defender fix (#550) rewrites the hives and changes the hash.
# Computing it here means it is never stale and never forgotten.
BASE_OUTPUT_DIR ?= $(shell awk -F'"' '/^[[:space:]]*output_directory[[:space:]]*=/{print $$2; exit}' \
                     $(PACKER_DIR)/packer.auto.pkrvars.hcl 2>/dev/null)
BASE_IMAGE      ?= $(if $(BASE_OUTPUT_DIR),$(BASE_OUTPUT_DIR),$(PACKER_DIR)/output)/windows11-base.qcow2

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

# build-preflight — check every prerequisite for the Windows build.
# The requirements were spread across DEPLOYMENT.md, packer/README.md and a
# comment block inside windows11-base.pkr.hcl, and none was complete. A
# first-time builder found each missing package by failing on it. The inline
# checks below stay: they guard the two things this target itself touches.
build-preflight:
	@./scripts/build-preflight.sh

win11-base: build-preflight autounattend-floppy
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
	@echo "==> Windows 11 base image complete."
	@echo ""
	@echo "    NEXT, and it is not optional: Defender is still ACTIVE in this image."
	@echo "    The in-guest disable is blocked by AMSI and Tamper Protection (#548),"
	@echo "    so it is corrected offline against the qcow2 before anything uses it:"
	@echo ""
	@echo "        sudo packer/scripts/host/disable-defender-offline.sh"
	@echo ""
	@echo "    Then update win11_base_image_checksum in packer.auto.pkrvars.hcl"
	@echo "    (the edit changes the file), and run: make win11-guest"
	@echo "    win11-guest verifies both Defender and the licence and will refuse"
	@echo "    an image where either is wrong."

# win11-guest — production "clean" image (runs cleanup on base)
# Expect ~5 minutes.
# -----------------------------------------------------------------------------

win11-guest:
	@echo "==> Building Windows 11 guest (clean) image from base..."
	@[ -f "$(BASE_IMAGE)" ] || (echo "ERROR: base image not found at $(BASE_IMAGE)." && \
		echo "       Run 'make win11-base' first, or set BASE_IMAGE=<path>." && exit 1)
	@echo "==> Hashing $(BASE_IMAGE) (~30s)..."
	@cd $(PACKER_DIR) && \
		BASE_SHA=$$(sha256sum "$(BASE_IMAGE)" | cut -d' ' -f1) && \
		packer init windows11-guest.pkr.hcl && \
		packer build -var-file=packer.auto.pkrvars.hcl \
			-var win11_base_image_path="$(BASE_IMAGE)" \
			-var win11_base_image_checksum="sha256:$$BASE_SHA" \
			windows11-guest.pkr.hcl
	@echo "==> Windows 11 guest image complete."

# win11-office — production "office" image (LibreOffice + cleanup on base)
# Expect ~15 minutes.
# -----------------------------------------------------------------------------

win11-office:
	@echo "==> Building Windows 11 office image from base..."
	@[ -f "$(BASE_IMAGE)" ] || (echo "ERROR: base image not found at $(BASE_IMAGE)." && \
		echo "       Run 'make win11-base' first, or set BASE_IMAGE=<path>." && exit 1)
	@echo "==> Hashing $(BASE_IMAGE) (~30s)..."
	@cd $(PACKER_DIR) && \
		BASE_SHA=$$(sha256sum "$(BASE_IMAGE)" | cut -d' ' -f1) && \
		packer init windows11-office.pkr.hcl && \
		packer build -var-file=packer.auto.pkrvars.hcl \
			-var win11_base_image_path="$(BASE_IMAGE)" \
			-var win11_base_image_checksum="sha256:$$BASE_SHA" \
			windows11-office.pkr.hcl
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

infra-ovh:
	@echo "==> Provisioning OVH infrastructure..."
	@[ -f $(OVH_DIR)/terraform.tfvars ] || \
		(echo "ERROR: $(OVH_DIR)/terraform.tfvars not found. Copy terraform.tfvars.example and fill in values." && exit 1)
	@cd $(OVH_DIR) && \
		terraform init && \
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
	@echo "==> Checking controller Python requirements..."
# Exercises the filter through ansible itself rather than checking `python3 -c
# "import netaddr"`, because the interpreter running ansible is often not the one
# on PATH — pipx and `uv tool install` both put it in their own venv. Testing the
# capability is install-method agnostic; guessing the interpreter is not.
	@ansible localhost -m debug \
		-a "msg={{ '10.0.0.1/24' | ansible.utils.ipaddr('address') }}" >/dev/null 2>&1 || \
		( echo "ERROR: the ansible.utils.ipaddr filter is unusable — netaddr is missing from"; \
		  echo "       the environment running ansible. Without it site.yml fails mid-run."; \
		  echo "       Install the controller requirements into that same environment:"; \
		  echo "         pip install -r $(ANSIBLE_DIR)/requirements-python.txt"; \
		  echo "       For a uv tool install of ansible, instead run:"; \
		  echo "         uv tool install ansible-core --with netaddr"; \
		  exit 1 )
	@cd $(ANSIBLE_DIR) && \
		ansible-playbook \
			-i inventory/hosts \
			-u $(ANSIBLE_USER) \
			--private-key $(ANSIBLE_KEY) \
			$(VAULT_ARGS) \
			site.yml
	@echo "==> Configuration complete."

# -----------------------------------------------------------------------------
# Validation — run before committing
# -----------------------------------------------------------------------------

# Packer is checked PER FILE and with -syntax-only. Both parts are deliberate:
#
#   per file    — `packer validate .` treats the directory as ONE config and merges
#                 every template, so the three windows11-*.pkr.hcl files that each
#                 declare `variable "ovmf_vars"` collide with "Duplicate variable".
#                 That aborted this target at its first step, so nothing below ever
#                 ran and `make validate` silently validated NOTHING (#228). Each
#                 template is built individually, where a per-file declaration is
#                 correct.
#
#   syntax-only — a full `packer validate` needs the gitignored pkrvars (secrets),
#                 installed plugins, and artifacts from earlier build stages
#                 (windows10-office consumes base_image_path, produced by the base
#                 build). None of that exists at commit time, so full validation
#                 cannot be a pre-commit gate. -syntax-only asserts what is honestly
#                 checkable here: the HCL parses.
#
# Full validation happens when you actually build.
validate:
	@echo "==> Validating Packer (syntax)..."
	@for f in $(PACKER_DIR)/*.pkr.hcl; do \
		echo "    $$f"; \
		packer validate -syntax-only "$$f" || exit 1; \
	done
	@echo "==> Validating OVH Terraform..."
	@cd $(OVH_DIR) && terraform init -backend=false && terraform validate
	@echo "==> Validating Ansible..."
	@# Without a password file, VAULT_ARGS is --ask-vault-pass, which BLOCKS FOREVER
	@# when nothing can answer the prompt (CI, cron, a script, a piped shell). A target
	@# that hangs is worse than one that fails: the caller gets no output and no exit
	@# code, and eventually kills it without learning why. Fail fast with the fix instead.
	@if [ ! -f "$(VAULT_PASS_FILE)" ] && [ ! -t 0 ]; then \
		echo "ERROR: no vault password available and stdin is not a TTY."; \
		echo "       ansible-playbook would block on --ask-vault-pass indefinitely."; \
		echo "       Fix: create $(VAULT_PASS_FILE), or run"; \
		echo "         make validate VAULT_ARGS=\"--vault-password-file /path/to/pass\""; \
		exit 1; \
	fi
	@cd $(ANSIBLE_DIR) && ansible-playbook --syntax-check $(VAULT_ARGS) -i inventory/hosts site.yml
	@echo "==> All validation passed."

# -----------------------------------------------------------------------------
# Deploy + security test — deploy specific roles then run smoke tests
# Usage: make deploy TAGS=api,frontend
# -----------------------------------------------------------------------------

TAGS ?= api,frontend

# collections-check — fail fast when a declared collection is not installed.
#
# NOTE: `ansible-galaxy collection list <name>` exits 0 whether or not the
# collection is installed -- only its OUTPUT differs. The first version of
# this check tested the exit code and therefore passed for everything,
# including the collection whose absence broke the deploy.
#
# `make configure` runs ansible-galaxy; `make deploy` never did. On a second
# workstation that had only ever run deploy, konstruktoid.hardening died
# mid-play on community.crypto.openssh_keypair — after the play had already
# started changing the host. This is an offline check, so it costs nothing and
# does not silently install things during a deploy.
collections-check:
	@python3 -c "import yaml,sys; r=yaml.safe_load(open('$(ANSIBLE_DIR)/requirements.yml')); \
		print('\n'.join(c['name'] for c in (r.get('collections') or [])))" > /tmp/.lamware-colls
	@missing=""; \
	while read -r c; do \
		[ -z "$$c" ] && continue; \
		ansible-galaxy collection list "$$c" 2>/dev/null | grep -qE "^$$c +[0-9]" \
			|| missing="$$missing $$c"; \
	done < /tmp/.lamware-colls; \
	rm -f /tmp/.lamware-colls; \
	if [ -n "$$missing" ]; then \
		echo "ERROR: missing Ansible collections:$$missing"; \
		echo "  fix: ansible-galaxy install -r $(ANSIBLE_DIR)/requirements.yml"; \
		exit 1; \
	fi

deploy: collections-check
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

# -----------------------------------------------------------------------------
# provenance — is the code I am looking at actually the code that is running? (#151)
# -----------------------------------------------------------------------------
# A deploy that aborts mid-play leaves a STARTED marker with no COMPLETED one.
# Before this existed, the single marker was written in pre_tasks and a failed
# deploy still reported its full tag list — on 2026-09-01 it claimed the pipeline
# role had run while the host had none of its changes (#515). Both provenance
# targets refuse rather than answer from a marker that describes an intention.
provenance-unfinished-check:
	@S=$$(ssh $(ANSIBLE_HOST_ALIAS) 'stat -c %Y /opt/lamware/deploy-started.json 2>/dev/null || echo 0'); \
	C=$$(ssh $(ANSIBLE_HOST_ALIAS) 'stat -c %Y /opt/lamware/deploy-provenance.json 2>/dev/null || echo 0'); \
	if [ "$$S" != "0" ] && [ "$$S" -gt "$$C" ]; then \
		echo "    UNFINISHED: a deploy started and never completed."; \
		echo "    The host is in whatever state that play left it, and the marker below"; \
		echo "    describes the deploy BEFORE it — not what is running now."; \
		echo "    Re-run the deploy, or verify the roles you care about by hand."; \
		exit 1; \
	fi

provenance:
	@echo "==> Deploy provenance"
	@$(MAKE) --no-print-directory provenance-unfinished-check
	@REMOTE=$$(ssh $(ANSIBLE_HOST_ALIAS) 'cat /opt/lamware/deploy-provenance.json' 2>/dev/null); \
	if [ -z "$$REMOTE" ]; then \
		echo "    NO MARKER on the host."; \
		echo "    Either nothing has been deployed since #151, or the deploy predates it."; \
		echo "    Run 'make deploy TAGS=<roles>' to write one."; \
		exit 1; \
	fi; \
	echo "$$REMOTE" | sed 's/^/    /'; \
	DEPLOYED=$$(echo "$$REMOTE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])'); \
	DIRTY=$$(echo "$$REMOTE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["dirty"])'); \
	LOCAL=$$(git rev-parse HEAD); \
	echo ""; \
	if [ "$$DIRTY" = "True" ]; then \
		echo "    WARNING: deployed from a DIRTY tree — those bytes match no commit."; \
	fi; \
	if [ "$$DEPLOYED" = "$$LOCAL" ]; then \
		echo "    OK: host matches your HEAD ($$(echo $$LOCAL | cut -c1-12))."; \
	elif git merge-base --is-ancestor "$$DEPLOYED" HEAD 2>/dev/null; then \
		echo "    STALE: host runs $$(echo $$DEPLOYED | cut -c1-12), an ANCESTOR of your HEAD $$(echo $$LOCAL | cut -c1-12)."; \
		echo "    Your local commits are NOT deployed:"; \
		git --no-pager log --oneline "$$DEPLOYED..HEAD" | sed 's/^/      /'; \
		exit 1; \
	else \
		echo "    DIVERGED: host runs $$(echo $$DEPLOYED | cut -c1-12), which is not an ancestor of your"; \
		echo "    HEAD $$(echo $$LOCAL | cut -c1-12). The host was deployed from a different branch."; \
		echo "    This is the 2026-08-03 failure: a feature-branch change was reverted"; \
		echo "    by a later deploy from main, silently."; \
		exit 1; \
	fi

# Is a SPECIFIC commit live? `make provenance-has COMMIT=<sha>`
provenance-has:
	@test -n "$(COMMIT)" || { echo "usage: make provenance-has COMMIT=<sha>"; exit 1; }
	@$(MAKE) --no-print-directory provenance-unfinished-check
	@DEPLOYED=$$(ssh $(ANSIBLE_HOST_ALIAS) 'cat /opt/lamware/deploy-provenance.json' 2>/dev/null \
		| python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])'); \
	if git merge-base --is-ancestor "$(COMMIT)" "$$DEPLOYED" 2>/dev/null; then \
		echo "    LIVE: $(COMMIT) is contained in deployed $$(echo $$DEPLOYED | cut -c1-12)."; \
	else \
		echo "    NOT LIVE: $(COMMIT) is absent from deployed $$(echo $$DEPLOYED | cut -c1-12)."; \
		exit 1; \
	fi

smoke-setup:
	@echo "==> Setting up smoke-gate venv + Chromium..."
	@cd $(SMOKE_DIR) && python3.12 -m venv .venv
	@cd $(SMOKE_DIR) && ./.venv/bin/pip -q install -r requirements.txt
	@cd $(SMOKE_DIR) && ./.venv/bin/playwright install chromium
	@# `playwright install` exits 0 when the host is missing the browser's shared
	@# libraries — it prints a banner and carries on. So this target used to announce
	@# "Smoke gate ready" in a state where the browser could never launch, and the
	@# subsequent `make smoke` failure read as "the deploy broke the site" rather than
	@# "this workstation is missing three apt packages" (#269). Launching a browser is
	@# the only thing that actually proves readiness, so do that before claiming it.
	@$(MAKE) --no-print-directory smoke-verify
	@echo "==> Smoke gate ready. Run 'make smoke'."

smoke-verify:
	@if [ ! -x "$(SMOKE_DIR)/.venv/bin/python" ]; then \
		echo "ERROR: smoke venv missing. Run 'make smoke-setup' first." && exit 1; \
	fi
	@$(SMOKE_DIR)/.venv/bin/python $(SMOKE_DIR)/verify_browser.py

smoke:
	@echo "==> Running Playwright smoke gate against $${SMOKE_BASE_URL:-https://lamware.shaiman.net}..."
	@# Prove the control node can run the gate BEFORE running it. Both failures are red
	@# otherwise, and the gate is what tells you whether a deploy is good — so "my
	@# workstation lacks three apt packages" and "the deploy broke the site" were
	@# indistinguishable, and the ntfy alert below cried wolf about the site either way.
	@# This exits first, with its own message, and never reaches that alert (#269).
	@$(MAKE) --no-print-directory smoke-verify
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
