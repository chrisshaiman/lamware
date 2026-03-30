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
├── shared/
│   └── backend-aws.hcl            ~ placeholder values, needs real bucket name
│
└── src/
    ├── report_processor.py        ~ stub (deployable, no real logic yet — needs real Cape report JSON)
    └── sample_submitter.py        ✓ complete
    # run `make lambda` to build src/*.zip before terraform apply
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

## Next session recommendation (2026-03-29)

**Work findings before features.**

Rationale:
- `terraform apply` fails today — Lambda ZIP packages don't exist (architecture finding below).
  Everything else is blocked behind that.
- IAM long-lived key fix must land before the OVH bare metal host is provisioned. Once credentials
  are pulled to disk on a host running malware, the window to fix it is gone.
- SQS 30-min visibility timeout causes silent duplicate detonations for complex samples — bad
  foundation to build Packer/Ansible on top of.
- High-priority findings are 1–2 hour Terraform changes. Packer + Ansible + OVH is days of work.

**Suggested order:**
1. Lambda ZIP blocker (create `src/` with stub handlers so `terraform apply` succeeds)
2. Bare metal IAM: long-lived keys → `sts:AssumeRole` with 1-hour sessions
3. SQS visibility timeout: 30 min → 60 min
4. DLQ CloudWatch alarm
5. Lambda SG egress: hardcoded CIDR → `referenced_security_group_id`
6. RDS SG egress: unrestricted → deny-all
7. S3 Object Lock: GOVERNANCE → COMPLIANCE (or document the tradeoff explicitly)
8. Secrets Manager rotation for RDS password (AWS-managed rotation Lambda)

Medium-priority findings (dashboard, backend placeholder, RDS ingress in module) can defer to a
later session without blocking progress.

---

## Review findings (2026-03-29)

Issues identified during architecture/security review. Investigate and address
in the next round of implementation work.

### Security — high priority

- [x] **Bare metal IAM: long-lived access keys on a host that runs malware.**
      Fixed 2026-03-29. IAM user scoped to `sts:AssumeRole` only. Real SQS/S3/KMS
      permissions moved to `aws_iam_role.baremetal_agent` (1-hour sessions).
      Role ARN added to Secrets Manager secret. Queue policy updated to role ARN.
      CloudTrail remains the detection surface for anomalous AssumeRole calls.
      *Files:* `aws/modules/sqs/main.tf`, `aws/modules/sqs/outputs.tf`

- [x] **Lambda SG egress hardcodes VPC CIDR (`10.20.0.0/16`).**
      Fixed 2026-03-29. Removed inline egress blocks from Lambda SG. Added
      `aws_vpc_security_group_egress_rule` resources in `prod/main.tf`:
      port 5432 → RDS SG via `referenced_security_group_id`; port 443 → `var.vpc_cidr`.
      All cross-module SG wiring is now in the composition layer.
      *Files:* `aws/modules/lambda/main.tf`, `aws/envs/prod/main.tf`

- [x] **RDS security group allows unrestricted egress (`0.0.0.0/0`).**
      Fixed 2026-03-29. Explicit `egress = []` — Terraform will remove the
      default allow-all rule. SGs are stateful; response traffic needs no rule.
      *Files:* `aws/modules/rds/main.tf`

- [~] **S3 Object Lock uses GOVERNANCE mode, not COMPLIANCE.**
      Intentional decision — see ADR-007. GOVERNANCE is correct for current use case;
      COMPLIANCE would prevent purging samples under a legal takedown or policy change.
      Known limitation: does not meet evidentiary chain-of-custody standards.
      Upgrade path documented in ADR-007 and in-code comment. One-line change when needed.
      *Files:* `aws/modules/s3/main.tf`, `docs/DECISIONS.md` (ADR-007)

- [x] **No Secrets Manager rotation configured.**
      Fixed 2026-03-29. RDS password rotates every 30 days via AWS SAR rotation Lambda
      (`SecretsManagerRDSPostgreSQLRotationSingleUser`). Lambda runs in the VPC with
      its own SG (egress to RDS 5432 + Secrets Manager endpoint 443). Rotation Lambda
      ingress rule added to RDS SG in composition layer.
      Cape API key and WireGuard keys are not rotated — both are set manually and have
      no AWS-native rotation path. Operator rotates manually as needed.
      *Files:* `aws/envs/prod/main.tf`

### Operational — high priority

- [x] **No DLQ alarm.**
      Fixed 2026-03-29. `aws_cloudwatch_metric_alarm.dlq_depth` added to SQS module.
      Fires when any message lands in the DLQ. Optional `alarm_sns_topic_arns` variable
      wires it to an SNS topic — alarm exists and changes state regardless.
      *Files:* `aws/modules/sqs/main.tf`, `aws/modules/sqs/variables.tf`, `aws/modules/sqs/outputs.tf`

- [ ] **No VPC Flow Log alerting.** Logs go to CloudWatch but nothing watches
      them. **Deferred → future scope.** With tight SG rules in place, the VPC
      attack surface is narrow and flow log alerting has low signal-to-noise for
      this architecture. The detonation network (where malware runs) is on OVH —
      not visible to AWS VPC flow logs at all. CloudTrail (AssumeRole calls, S3
      access) is higher-value monitoring for this threat model. Logs retained for
      forensic use.

- [ ] **Reports bucket has no object lock or expiration.** Samples bucket has
      object lock (good), but reports accumulate indefinitely with no tamper
      protection and no lifecycle expiration.
      **Deferred → future scope.** Reports are re-generatable by re-running the
      sample — object lock has low value here. Existing lifecycle rule already
      moves reports to Glacier after 90 days, so accumulation cost is minimal.
      Expiration rule (e.g. 2 years) is a cost hygiene item, not a security issue.

- [x] **SQS visibility timeout (30 min) may be too short.**
      Fixed 2026-03-29. Default raised to 60 min in `variables.tf`.
      *Files:* `aws/modules/sqs/variables.tf`

### Architecture — medium priority

- [ ] **RDS ingress rule wired in composition layer, not the module.**
      If someone writes a new environment and forgets the rule, Lambda silently
      can't reach the DB. Consider accepting `allowed_security_group_ids` as a
      variable in the RDS module.
      *Files:* `aws/modules/rds/main.tf`, `aws/envs/prod/main.tf`

- [x] **Lambda deployment packages don't exist.**
      Fixed 2026-03-29. `src/report_processor.py` and `src/sample_submitter.py`
      created as functional stubs. `make lambda` builds the zips. tfvars.example
      updated with correct paths. `terraform apply` will now succeed.
      *Files:* `src/`, `Makefile`, `aws/envs/prod/terraform.tfvars.example`

- [x] **`shared/backend-aws.hcl` has placeholder bucket name.**
      Fixed 2026-03-29. Added `make configure-backend` — reads bootstrap outputs and
      writes the file with real values. First-time setup order documented in `make help`.
      *Files:* `Makefile`

### Operational — medium priority

- [x] **No budget alerts.**
      Fixed 2026-03-29. `aws_budgets_budget.monthly` alerts at 80% actual and 100%
      forecasted against a configurable limit (default $75/month). Email addresses set
      via `budget_alert_emails` in terraform.tfvars.
      *Files:* `aws/envs/prod/main.tf`, `aws/envs/prod/variables.tf`, `aws/envs/prod/terraform.tfvars.example`

- [ ] **No CloudWatch dashboard.** No unified view of Lambda errors, SQS queue
      depth, RDS connections, or S3 request rates.
      **Deferred → low priority / future scope**

- [ ] **No backup/restore documentation for RDS.** 7-day retention + final
      snapshot configured, but no documented restore procedure.
      **Deferred → low priority / future scope**

---

## Lambda handlers — implementation status

- [x] **`src/sample_submitter.py` — implemented 2026-03-29.**
      Validates `{filename, sha256, tags}` → sanitizes filename (path traversal strip)
      → generates pre-signed S3 PUT URL (15 min TTL) → enqueues SQS job
      → returns `{task_id, upload_url, expires_in, s3_key}`. boto3 clients
      initialised at module level for warm-start reuse. Full input validation
      and structured error responses.

- [ ] **`src/report_processor.py` — defer until Cape is running.**
      Needs real Cape JSON report output to define the parser and RDS schema correctly.
      Building it blind risks getting the schema wrong and rewriting it anyway.
      **Do after:** OVH provisioned → Ansible configured → Cape running → sample detonated
      → actual report JSON captured. Then implement parser + define RDS tables together.

---

## Future scope (not started, not prioritised)

- RDS ingress rule: move from composition layer into RDS module (accept `allowed_security_group_ids` variable)
- CloudWatch dashboard: Lambda errors, SQS depth, RDS connections, S3 request rates
- RDS backup/restore runbook
- VPC Flow Log alerting — low value given tight SGs; CloudTrail is higher signal for this threat model
- Reports bucket expiration rule (~2 years) — cost hygiene; object lock not warranted (reports are re-generatable)
- Static analysis agent (Ghidra headless / Binary Ninja API)
- Memory forensics agent (Volatility 3 post-detonation)
- Agent orchestration layer (Step Functions or separate service)
- Windows guest Packer image (Cape detonation VM)
- Alternative bare metal provider module (Vultr/Latitude.sh) if OVH proves unworkable
