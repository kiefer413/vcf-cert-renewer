# Component Support

| Component | Capability | Mutation route |
|---|---|---|
| VCF Operations | FULL_RENEW | Fleet CSR/import/replace |
| SDDC Manager | FULL_RENEW | Domain resource-certificate API |
| vCenter | FULL_RENEW | Domain resource-certificate API |
| NSX Manager VIP | FULL_RENEW | Native `MGMT_CLUSTER` |
| NSX manager node/API | PLAN_ONLY | No node mutation |
| Identity Broker / ACS | PLAN_ONLY | Writes disabled |
| Runtime / Automation / Logs | PLAN_ONLY | Writes disabled |
| Operations for Networks | DISCOVER_ONLY | No verified mutation route |
| Supervisor | PLAN_ONLY | Writes disabled |
| ESXi | UNSUPPORTED | Outside release scope |
| Other Fleet TLS | DISCOVER_ONLY | Safe classification unavailable |

FULL_RENEW has been live-validated on VCF 9.1.x. Internal roots,
intermediates, trust anchors, and private/internal certificates are non-goals
for public ACME replacement.
