# COST_ESTIMATE.md — Monthly Infrastructure Cost Tracking

Keep this document current. Update it when components are added, removed, or resized.
All costs are USD/month estimates based on us-east-1 pricing (March 2026).
Actual costs vary with sample volume, analysis frequency, and data transfer.

---

## Summary

| Layer | Est. Monthly |
|---|---|
| AWS supporting infra | ~$43 |
| OVH bare metal (RISE-1) | ~$65 |
| OVH bare metal (ADVANCE-1) | ~$105 |
| **Total (RISE-1)** | **~$108/month** |
| **Total (ADVANCE-1)** | **~$148/month** |

Recommended for active analysis work: ADVANCE-1 (~$167/month total).
RISE-1 is adequate for dev/test or low-volume use (~$127/month total).

---

## AWS — Component Breakdown

| Component | Configuration | Est. Monthly | Notes |
|---|---|---|---|
| S3 — samples bucket | ~100GB, Standard storage | ~$3 | Scales with corpus size |
| S3 — reports bucket | ~50GB, Standard storage | ~$2 | Cape JSON reports; compressible |
| RDS PostgreSQL | db.t4g.micro, 20GB gp3, single-AZ | ~$14 | Upgrade to t4g.small (~$25) if query load increases |
| Lambda | ~1k invocations/day | ~$2 | Likely near free tier at low volume |
| API Gateway (HTTP API) | ~1k req/day | <$1 | HTTP API is ~70% cheaper than REST API |
| NAT Gateway | Removed — replaced by VPC endpoints | $0 | See ADR-006 |
| VPC Interface Endpoints | SQS + Secrets Manager (2x) | ~$14 | ~$7/endpoint/month |
| SQS | Standard queue, low volume | <$1 | Within free tier (1M req/month) |
| KMS | 1 CMK + API calls | ~$1 | Single key used across S3, RDS, Lambda logs |
| Secrets Manager | ~6 secrets | ~$2 | DSDT, Cape key, DB password, WireGuard keys |
| Secrets Manager rotation | RDS rotation Lambda (SAR) | ~$0 | 1 invocation/month; within Lambda free tier |
| CloudWatch Logs | Lambda logs (30d retention) + VPC flow logs | ~$3 | |
| CloudWatch alarm | DLQ depth alarm | ~$0 | First 10 alarms free per account |
| AWS Budgets | Monthly spend alert | $0 | First 2 budgets per account always free |
| DynamoDB | PAY_PER_REQUEST (TF state lock only) | <$1 | Negligible |
| **AWS Total** | | **~$43/month** | |

---

## OVH Bare Metal — Options

| Tier | Specs | Est. Monthly | Suitable For |
|---|---|---|---|
| RISE-1 | 4c/8t, 32GB RAM, 2×2TB HDD | ~$65 | Dev/test, low-volume analysis |
| ADVANCE-1 | 8c/16t, 32GB RAM, 2×512GB NVMe | ~$105 | Active analysis, multiple concurrent VMs |
| ADVANCE-2 | 8c/16t, 64GB RAM, 2×512GB NVMe | ~$125 | High-throughput analysis |

Cape can run 2–4 concurrent analysis VMs on ADVANCE-1. RISE-1 is limited to 1–2.
NVMe storage on ADVANCE series significantly improves VM snapshot and disk I/O speed.

---

## Cost Optimization Opportunities

### RDS instance sizing
db.t4g.micro (~$14/month) is sufficient for the IOC database at low-moderate volume.
Only upgrade to t4g.small (~$25/month) if query latency becomes an issue.

### S3 storage classes
Reports older than 90 days can transition to S3 Glacier Instant Retrieval (~$0.004/GB)
vs Standard (~$0.023/GB). Worth adding a lifecycle rule once the corpus grows.
Lifecycle rules are already scaffolded in `aws/modules/s3/`.

---

## Not Yet Costed (future scope)

| Component | Notes |
|---|---|
| Static analysis agent (Ghidra) | Likely Lambda or Fargate; cost TBD |
| Memory forensics agent (Volatility 3) | Likely Lambda; cost TBD |
| Agent orchestration | Step Functions ~$0.025/1k state transitions |
| Windows guest Packer image | No additional infra cost — runs on existing bare metal |
| OVH bandwidth overage | OVH includes generous bandwidth; unlikely to be a factor |
