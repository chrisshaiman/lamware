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
├── Makefile                       ✓ complete
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
│   ├── bootstrap/
│   │   ├── main.tf                ✓ complete
│   │   ├── variables.tf           ✓ complete
│   │   └── outputs.tf             ✓ complete
│   ├── modules/
│   │   ├── vpc/                   ✓ complete (subnets, NAT, flow logs)
│   │   ├── s3/                    ✓ complete (buckets, object lock, KMS, lifecycle)
│   │   ├── rds/                   ✓ complete (PostgreSQL, private subnet, encrypted)
│   │   ├── lambda/
│   │   │   ├── main.tf            ✓ complete
│   │   │   ├── variables.tf       ✓ complete
│   │   │   └── outputs.tf         ✓ complete
│   │   ├── sqs/
│   │   │   ├── main.tf            ✓ complete
│   │   │   ├── variables.tf       ✓ complete
│   │   │   └── outputs.tf         ✓ complete
│   │   └── api/
│   │       ├── main.tf            ✓ complete
│   │       ├── variables.tf       ✓ complete
│   │       └── outputs.tf         ✓ complete
│   └── envs/
│       └── prod/
│           ├── main.tf            ✓ complete
│           ├── variables.tf       ✓ complete
│           ├── outputs.tf         ✓ complete
│           └── terraform.tfvars.example ✓ complete
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
- `aws/modules/sqs/` — job queue, DLQ, bare metal IAM user + policy, credentials in Secrets Manager
- `aws/bootstrap/` — S3 state bucket + DynamoDB lock table; runs once with local state
- `aws/modules/api/` — HTTP API Gateway v2, POST /submit route, IAM auth, throttling, access logs
- `aws/envs/prod/` — composition layer wiring all modules; KMS key, Secrets Manager secrets, cross-module rules
- `Makefile` — `make image`, `make infra`, `make configure` entry points

---

## Review findings (2026-03-29)

Issues identified during architecture/security review. Investigate and address
in the next round of implementation work.

### Security — high priority

- [ ] **Bare metal IAM: long-lived access keys on a host that runs malware.**
      SQS module creates an IAM user with static credentials pulled to disk.
      If the host is compromised, keys are trivially exfiltrated.
      **Mitigation:** Scope the IAM user to `sts:AssumeRole` only; actual
      permissions on the assumed role with 1-hour sessions. Monitor
      `AssumeRole` calls in CloudTrail for anomalous patterns.
      *Files:* `aws/modules/sqs/main.tf` (IAM user + policy)

- [ ] **Lambda SG egress hardcodes VPC CIDR (`10.20.0.0/16`).**
      Should reference the RDS security group directly via
      `referenced_security_group_id` for the port-5432 rule. Brittle if VPC
      CIDR ever changes.
      *Files:* `aws/modules/lambda/main.tf` (egress rules)

- [ ] **RDS security group allows unrestricted egress (`0.0.0.0/0`).**
      RDS has no reason for outbound connectivity in this architecture.
      Restrict to deny-all or response-only traffic.
      *Files:* `aws/modules/rds/main.tf` (SG egress)

- [ ] **S3 Object Lock uses GOVERNANCE mode, not COMPLIANCE.**
      Root/admin can override GOVERNANCE. If chain-of-custody matters for
      analysis evidence, COMPLIANCE mode provides actual immutability.
      Document the tradeoff or switch to COMPLIANCE.
      *Files:* `aws/modules/s3/main.tf`

- [ ] **No Secrets Manager rotation configured.**
      DB password, Cape API key, and WireGuard keys sit indefinitely.
      AWS has a native rotation Lambda template for RDS — easiest win.
      *Files:* `aws/envs/prod/main.tf` (secret definitions)

### Operational — high priority

- [ ] **No DLQ alarm.** Failed jobs silently accumulate in the dead-letter
      queue. Add a CloudWatch alarm on `ApproximateNumberOfMessagesVisible > 0`.
      *Files:* `aws/modules/sqs/main.tf`

- [ ] **No VPC Flow Log alerting.** Logs go to CloudWatch but nothing watches
      them. Add CloudWatch Insights queries or alarms for unexpected outbound
      connections, port scans, DNS exfiltration patterns.
      *Files:* `aws/modules/vpc/main.tf`

- [ ] **Reports bucket has no object lock or expiration.** Samples bucket has
      object lock (good), but reports accumulate indefinitely with no tamper
      protection and no lifecycle expiration.
      *Files:* `aws/modules/s3/main.tf`

- [ ] **SQS visibility timeout (30 min) may be too short.** Complex malware
      in CAPEv2 can run 30+ minutes. If timeout expires, SQS redelivers
      mid-analysis causing duplicate runs. Consider defaulting to 60 min.
      *Files:* `aws/modules/sqs/main.tf`, `aws/modules/sqs/variables.tf`

### Architecture — medium priority

- [ ] **RDS ingress rule wired in composition layer, not the module.**
      If someone writes a new environment and forgets the rule, Lambda silently
      can't reach the DB. Consider accepting `allowed_security_group_ids` as a
      variable in the RDS module.
      *Files:* `aws/modules/rds/main.tf`, `aws/envs/prod/main.tf`

- [ ] **Lambda deployment packages don't exist.** Module references
      `var.report_processor_zip` and `var.sample_submitter_zip` but there's no
      `src/` directory with Python handlers. `terraform apply` will fail.
      *Files:* `aws/modules/lambda/main.tf`

- [ ] **`shared/backend-aws.hcl` has placeholder bucket name.**
      Includes `<your-account-id>` — confusing error on `terraform init`.
      Consider a Makefile target that auto-populates from bootstrap output.
      *Files:* `shared/backend-aws.hcl`

### Operational — medium priority

- [ ] **No CloudWatch dashboard or budget alerts.** No visibility into Lambda
      errors, SQS queue depth, RDS connections, or S3 request rates. No AWS
      Budget alarm for monthly spending.

- [ ] **No backup/restore documentation for RDS.** 7-day retention + final
      snapshot configured, but no documented restore procedure.

---

## Future scope (not started, not prioritised)

- Static analysis agent (Ghidra headless / Binary Ninja API)
- Memory forensics agent (Volatility 3 post-detonation)
- Agent orchestration layer (Step Functions or separate service)
- Windows guest Packer image (Cape detonation VM)
- Alternative bare metal provider module (Vultr/Latitude.sh) if OVH proves unworkable
