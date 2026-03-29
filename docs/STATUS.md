# STATUS.md — Build Status (Living Document)

Update this file as components are built, stubbed, or descoped.
For the ordered build queue see CLAUDE.md. For design rationale see ARCHITECTURE.md.

---

## Repo structure

```
malware-sandbox-infra/
├── CLAUDE.md                      ✓ instructions + build queue
├── ARCHITECTURE.md                ✓ system design reference
├── README.md                      ✓ public-facing overview
├── AUTHORS                        ✓
├── Makefile                       ✗ NOT YET BUILT
│
├── docs/
│   ├── DECISIONS.md               ✓ ADR log
│   ├── SECURITY_CONSTRAINTS.md    ✓ non-negotiables with rationale
│   └── STATUS.md                  ✓ this file
│
├── packer/
│   ├── ubuntu-sandbox.pkr.hcl     ~ STUB (file exists, not implemented)
│   └── http/
│       └── user-data              ✗ NOT YET BUILT
│
├── ansible/
│   ├── site.yml                   ~ STUB
│   ├── inventory/
│   │   └── hosts.example          ✓ exists
│   ├── vars/
│   │   └── main.yml               ✓ exists
│   └── roles/
│       ├── hardening/             ~ STUB
│       ├── kvm/                   ~ STUB
│       ├── networking/            ~ STUB
│       ├── cape/                  ~ STUB
│       ├── wireguard/             ~ STUB
│       ├── s3-sync/               ~ STUB (will be absorbed into sqs-agent)
│       └── sqs-agent/             ✗ NOT YET BUILT
│
├── ovh/                           ✗ NOT YET BUILT (bare metal provider)
│
├── aws/
│   ├── bootstrap/                 ✗ NOT YET BUILT (S3 + DynamoDB for remote state)
│   ├── modules/
│   │   ├── vpc/                   ✓ complete (subnets, NAT, flow logs)
│   │   ├── s3/                    ✓ complete (buckets, object lock, KMS, lifecycle)
│   │   ├── rds/                   ✓ complete (PostgreSQL, private subnet, encrypted)
│   │   ├── lambda/
│   │   │   ├── main.tf            ✓ complete
│   │   │   ├── variables.tf       ✓ complete
│   │   │   └── outputs.tf         ✓ complete
│   │   ├── sqs/                   ✗ NOT YET BUILT
│   │   └── api/                   ✗ NOT YET BUILT
│   └── envs/
│       └── prod/
│           └── main.tf            ~ STUB (provider + backend only, no module calls)
│
└── shared/
    ├── backend-aws.hcl            ~ placeholder values, needs real bucket name
    └── backend-aws.hcl            ~ placeholder values, needs real bucket name
```

**Legend:** ✓ complete · ~ stub/partial · ✗ not built · ! needs fix

---

## Done (fully implemented)

- `aws/modules/vpc/` — VPC, subnets, NAT gateway, flow logs
- `aws/modules/s3/` — samples + reports buckets, object lock, KMS, lifecycle, S3 event notification
- `aws/modules/rds/` — PostgreSQL, private subnet, Performance Insights, encrypted
- `aws/modules/lambda/` — report_processor + sample_submitter functions, IAM, SQS permissions, VPC endpoint, variables, outputs

---

---

## Future scope (not started, not prioritised)

- Static analysis agent (Ghidra headless / Binary Ninja API)
- Memory forensics agent (Volatility 3 post-detonation)
- Agent orchestration layer (Step Functions or separate service)
- Windows guest Packer image (Cape detonation VM)
- Alternative bare metal provider module (Vultr/Latitude.sh) if OVH proves unworkable
