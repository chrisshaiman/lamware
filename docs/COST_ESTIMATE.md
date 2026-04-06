# COST_ESTIMATE.md — Monthly Infrastructure Cost Tracking

Keep this document current. Update it when components are added, removed, or resized.
All costs are USD/month estimates based on us-east-1 pricing (April 2026).
Actual costs vary with sample volume, analysis frequency, and data transfer.

---

## Summary

| Layer | Est. Monthly |
|---|---|
| AWS supporting infra | ~$43 |
| OVH bare metal (RISE-2 + 64GB upgrade) | ~$92 |
| **Total** | **~$135/month** |

Recommended: RISE-2 with 64GB RAM upgrade (~$135/month total).
One-time setup fee: $80 (waived with 12-month commitment).

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

## OVH Bare Metal — Selected Configuration

| Tier | Specs | Est. Monthly | Notes |
|---|---|---|---|
| **RISE-2 + 64GB** | Xeon E-2388G 8c/16t, 64GB DDR4, 2×512GB NVMe | ~$92 | Best value for 8-core US bare metal |

Alternatives evaluated (April 2026 pricing, US availability only):

| Tier | Specs | Est. Monthly | Why Not |
|---|---|---|---|
| RISE-1 | Xeon E-2386G 6c/12t, 32GB DDR4, 2×512GB NVMe | $70 | Only 6 cores — limits concurrent VMs |
| RISE-S | Ryzen 7 9700X 8c/16t, 64GB DDR5, 2×512GB NVMe | $77 | Not available in US datacenters |
| ADVANCE-1 | EPYC 4244P 6c/12t, 32GB DDR5, 2×960GB NVMe | $115 | Only 6 cores, more expensive than RISE-2 |
| ADVANCE-2 | EPYC 4344P 8c/16t, 64GB DDR5, 2×960GB NVMe | $160 | DDR5 + larger NVMe but $68/mo more |
| Vultr E-2286G | Xeon E-2286G 6c/12t, 32GB, 2×960GB SSD | $185 | Poor value vs OVH |

Cape can run 3-5 concurrent analysis VMs with 64GB RAM.
NVMe storage provides fast VM snapshot creation and restore.

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

## OVH — Additional Notes

OVH bare metal is ordered manually via the OVH manager. Terraform manages configuration
(robot firewall, OS install) but not hardware ordering. The `ovh/` module assumes the
server is already provisioned and references it by service_name.

RISE-2 product page: https://eco.us.ovhcloud.com/rise/rise-2/

Bandwidth: OVH RISE includes 1 Gbps unmetered public bandwidth and anti-DDoS.
S3 transfer costs apply for report uploads from bare metal to AWS (~$0.09/GB out to internet,
free for inbound). At typical malware analysis volumes this is negligible.

---

## Not Yet Costed (future scope)

| Component | Notes |
|---|---|
| Static analysis agent (Ghidra) | Likely Lambda or Fargate; cost TBD |
| Memory forensics agent (Volatility 3) | Likely Lambda; cost TBD |
| Agent orchestration | Step Functions ~$0.025/1k state transitions |
| Windows guest Packer image | No additional infra cost — runs on existing bare metal |
| OVH bandwidth overage | OVH includes generous bandwidth; unlikely to be a factor |
