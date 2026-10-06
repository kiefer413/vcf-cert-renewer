# Component Support

| Component | Capability | Mutation route |
|---|---|---|
| VCF Operations | FULL_RENEW | Fleet CSR/import/replace |
| VCF Automation external TLS | FULL_RENEW | Fleet CSR/import/replace; fully managed External CA TLS leaf only |
| VCF Automation internal VMCA/runtime | DISCOVER_ONLY | No mutation route |
| VCF Services Runtime | PLAN_ONLY | Cannot use generic Fleet mutation route |
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

The external VCF Automation TLS replacement workflow and live HTTPS verification have been production-validated on VCF 9.1.x. A later live mutating scheduled batch renewal after that replacement has not been run. Internal roots,
intermediates, trust anchors, and private/internal certificates are non-goals
for public ACME replacement.
