# Malware Analysis Sandbox Infrastructure

Terraform infrastructure for a distributed malware analysis platform.

## Architecture

```
OVHcloud US (bare metal)      AWS us-east-1 (supporting infra)
────────────────────────      ────────────────────────────────
KVM hypervisor                S3 (sample + report storage)
Cape Sandbox (CAPEv2)         SQS (async job queue)
FakeNet-NG / INetSim          RDS PostgreSQL (analysis DB)
Isolated detonation VLAN      Lambda (pipeline triggers)
WireGuard (admin access)      API Gateway (agent API)
SQS polling agent             VPC, KMS, Secrets Manager
```

All infrastructure is hosted in the United States. If you are deploying from
another jurisdiction, swap `us-east-1` for your nearest AWS region and choose
a bare metal provider with local presence. The architecture requires no other
changes.

## Layout

```
ovh/            - Bare metal server provisioning (OVHcloud US)
aws/
  bootstrap/    - One-time remote state setup (S3 + DynamoDB)
  modules/      - Reusable modules (vpc, s3, sqs, rds, lambda, api)
  envs/prod/    - Production environment composition
shared/         - Shared backend config
ansible/        - Host configuration (KVM, Cape, WireGuard, SQS agent)
packer/         - Hardened Ubuntu 24.04 base image
docs/           - Architecture decisions, security constraints, status
```

## Prerequisites

- Terraform >= 1.6, Packer >= 1.10, Ansible >= 2.14, AWS CLI v2
- OVHcloud API credentials
- AWS credentials with appropriate permissions
- WireGuard keypair generated locally
- **Windows:** WSL2 required — run all commands from a WSL2 terminal

## Usage

```bash
make image      # build Packer base image
make infra      # provision OVH server + AWS resources
make configure  # run Ansible against provisioned host
```

See `docs/DEPLOYMENT.md` for the full deployment guide. See `docs/STATUS.md` for current
build status and `ARCHITECTURE.md` for design detail.

## Security Notes

- Detonation network is air-gapped — no route from `virbr-det` to `eth0` or `wg0`
- All sample uploads require pre-signed S3 URLs (no public bucket access)
- RDS is in a private subnet with no internet route
- OVH robot firewall applied before OS boot — whitelist admin CIDRs first
- Separate AWS account required — do not mix with other infra
- All infrastructure in US jurisdiction

## Author

Christopher Shaiman

## License

Apache 2.0
