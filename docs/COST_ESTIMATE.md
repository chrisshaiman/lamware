# COST_ESTIMATE.md — Monthly Infrastructure Cost Tracking

Keep this document current. Update it when components are added, removed, or resized.
All costs are USD/month estimates based on us-east-1 pricing (April 2026).
Actual costs vary with sample volume, analysis frequency, and data transfer.

---

## Summary

| Layer | Est. Monthly |
|---|---|
| OVH bare metal (RISE-2 + 64GB upgrade) | ~$92 |
| AWS (optional — S3 evidence archival only) | ~$5 |
| **Total (without AWS)** | **~$92/month** |
| **Total (with S3 archival)** | **~$97/month** |

AWS data plane (Lambda, SQS, RDS, API Gateway, VPC endpoints, Secrets Manager) has been
removed — see ADR-016. Secrets are managed locally via Ansible Vault. S3 with Object Lock
is retained as an optional standalone component for evidence archival if chain-of-custody
is needed.

---

## AWS — Optional S3 Evidence Archival

| Component | Configuration | Est. Monthly | Notes |
|---|---|---|---|
| S3 — samples bucket | ~100GB, Standard storage | ~$3 | Object Lock GOVERNANCE mode |
| S3 — reports bucket | ~50GB, Standard storage | ~$2 | Cape JSON reports; compressible |
| **AWS Total** | | **~$5/month** | Only if deployed |

All other AWS services (RDS, Lambda, SQS, API GW, VPC, KMS, Secrets Manager, CloudWatch,
CloudTrail) are no longer deployed. Terraform code in `aws/` is retained for reference.

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

### S3 storage classes (if S3 archival is deployed)
Reports older than 90 days can transition to S3 Glacier Instant Retrieval (~$0.004/GB)
vs Standard (~$0.023/GB). Lifecycle rules are already scaffolded in `aws/modules/s3/`.

### OVH KS-5 alternative
KS-5 (Xeon E3-1270 v6, 4c/8t, 32GB, 2x450GB NVMe) at ~$20/month in Vint Hill VA
could potentially run the sandbox or support services. Significantly cheaper but
fewer cores and less RAM than RISE-2. Worth evaluating if budget is the primary
constraint.

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
| Static analysis (Ghidra headless) | Runs on bare metal host; no additional infra cost |
| Memory forensics (Volatility 3) | Runs on bare metal host; no additional infra cost |
| Windows guest Packer image rotation | No additional infra cost — runs on existing bare metal |
| OVH bandwidth overage | OVH includes generous bandwidth; unlikely to be a factor |
