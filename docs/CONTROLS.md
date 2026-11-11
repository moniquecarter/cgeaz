# Control Mappings

Every policy, collector, and gate rule in this repo, mapped to the NIST CSF 2.0
category it serves. This file is what turns the repo from code into a control catalog —
and it's a first-class criterion on the capstone rubric.

**This fork:** rows added or changed by this fork are marked **(fork)**. Design detail
for each is in [ARCHITECTURE.md](ARCHITECTURE.md); accepted gaps are in
[RISK-ACCEPTANCES.md](RISK-ACCEPTANCES.md).

## Stage 01 — Foundation

| Component | What it does | CSF 2.0 |
|---|---|---|
| Management group hierarchy + initiative assignment | Controls inherit to every current and future subscription — compliance by design | GV.PO, GV.OC |
| `cge-require-env-tag-rg` (Audit) | Inventory hygiene; owner accountability feeds the POA&M | ID.AM |
| `cge-deny-public-blob` (Deny) | Prevents public blob exposure at the API, before the resource exists | PR.DS |
| `cge-dine-storage-diagnostics` (DeployIfNotExists) | Routes storage metrics to the workspace and enforces its own coverage. Metrics only: no access logs (see next row) | PR.PS, DE.CM |
| `hbai-dine-blob-access-logs` (AuditIfNotExists → DeployIfNotExists) — **own (fork)** | Blob access logs (read/write/delete) to the GRC workspace; closes the starter's metrics-only gap, so "who touched the evidence" has an answer | DE.CM, PR.PS |
| Remediation identity (user-assigned, whitelist roles) | Every automated change has a named, auditable author | PR.AA, GV.RR |
| Log Analytics workspace + Activity Log routing | Central audit trail beyond the 90-day default | DE.CM, PR.PS |

## Stage 02 — Activation (fork: added to this catalog)

| Component | What it does | CSF 2.0 |
|---|---|---|
| Read-first Defender plan activation (`StorageAccounts`, `KeyVaults`) | Reads every plan's current tier, then enables only the baseline plans that are missing; plans already at Standard are adopted, not recreated | DE.CM, ID.RA |
| NIST CSF 2.0 regulatory standard (subscription assignment) | Defender assesses resources against the framework continuously; these assessments are what the collector captures | ID.RA, GV.OV |

## Stage 03 — Evidence Store

| Component | What it does | CSF 2.0 |
|---|---|---|
| Cosmos DB (assessments / frameworks / mappings) | Owned evidence schema; collect once, crosswalk to every framework | GV.OV, ID.RA |
| WORM immutability policy on `reports` | Artifacts tamper-proof by platform guarantee | PR.DS |
| Shared keys disabled + data-plane RBAC | Identity or nothing; no credentials to steal or rotate. Exception: Functions runtime storage (RA-001) | PR.AA |
| Collector Function (Security Reader + Cosmos write only) | Continuous control-test capture with lineage; cannot alter what it observes | DE.CM, ID.RA |
| Collector/reporter identity split | The recorder of facts cannot author the narrative — SoD by role scopes | PR.AA, GV.RR |
| Pinned deployer identity (`deployer_object_id`) **(fork)** | Evidence-store write access stays with the named owner, not whichever identity runs the plan; CI can't silently grant itself write access | PR.AA, GV.RR |
| HTTPS-only on both Function Apps (collector here, reporter in stage 04) **(fork)** | No plaintext transport to the collector or reporter | PR.DS |
| Framework seeder (`labs/04-evidence/seed_frameworks.py`) | Loads the framework catalog the crosswalk and reports refer to | GV.OC |
| Crosswalk seeder (`labs/04-evidence/seed_mappings.py`) **(fork)** | Maps each Defender assessment to NIST CSF 2.0 and 800-53 Rev. 5 (direct, from Microsoft's initiatives) and to CSA CCM v4.0 and FedRAMP 20x KSI (derived, from Prowler's compliance files). Every row names its source, version and build | GV.OC, GV.OV |

## Stage 04 — Reporting

| Component | What it does | CSF 2.0 |
|---|---|---|
| POA&M generator (daily, SLA-dated) | Weakness management with owners and dates, from the store only | ID.IM, GV.RM |
| SAR generator (weekly) | Assessment reporting where every number traces to a stored document | ID.RA, GV.OV |
| SAR "Findings by framework" **(fork)** | Findings counted per framework from the crosswalk, with the crosswalk build and the stored queries that reproduce each number | GV.OV, ID.RA |

## Stage 06 — Enforcement

| Component | What it does | CSF 2.0 |
|---|---|---|
| `cge-fix-public-blob` (Modify, mode ladder) | Auto-remediation through the dedicated identity; human-approved in dry-run | PR.DS, RS.MI |
| `remediation_mode` variable | Escalation is a reviewed diff — automation acts, humans authorize | GV.PO, GV.RR |

## Repo gates (policy/)

| Rule | Mistake it makes unmergeable | CSF 2.0 |
|---|---|---|
| `storage.rego`: no public blob access | Pipeline storage that allows public blobs | PR.DS |
| `storage.rego`: shared keys disabled | Pipeline storage with shared-key access; the Functions runtime accounts are the one documented exception (RA-001) | PR.AA, PR.DS |
| `policy_identity.rego` | Remediation that silently never runs | PR.PS |
| `broad_roles.rego` | Owner/Contributor grants in governance code | PR.AA |

## CI and change control (fork: added to this catalog)

| Component | What it does | CSF 2.0 |
|---|---|---|
| `gate.yml`: `terraform plan` + conftest on stages 01, 03, 04, 06 | Every pull request is evaluated against the rules above before it can merge. PR #15 shows the gate blocking a non-compliant change | PR.PS, GV.PO |
| conftest 0.71.1 pinned by SHA-256 | The gate's own tooling can't change underneath it; replaced an unpinned third-party action that couldn't parse the policies | PR.PS, GV.SC |
| Branch protection on `main` | Pull request and the four `gate (…)` checks required; no bypass | PR.PS, PR.AA |
| OIDC federation for CI | No stored cloud credentials in GitHub | PR.AA |
| `drift.yml` (nightly, `-detailed-exitcode`) | Out-of-band change opens an issue with the diff | DE.CM, DE.AE |
| Activity Log KQL query (Lab 06) | Answers *who* made an out-of-band change. Run on demand, not scheduled: there is no alert rule yet (see ARCHITECTURE.md, known limits) | DE.AE |
| Prowler IaC scan before every apply | Terraform is scanned before it reaches Azure; findings are fixed or formally accepted | ID.RA, PR.PS |
| Risk acceptances (RA-001 to RA-003) | Accepted findings carry a compensating control, an owner and a review date | GV.RM, ID.RA |
