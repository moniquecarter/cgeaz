# Risk Acceptances

Findings this pipeline knowingly carries, and why. An accepted finding is not a closed
one: each entry names its compensating controls, an owner, and a date it gets looked at
again. Anything not listed here is either fixed or still open on the POA&M.

Source: Prowler 5.43.0 IaC scan (`prowler iac --scan-path stages`, Trivy 0.76.0
underneath), 2026-11-01, after the HTTPS-only fix. That scan reported 13 failed checks;
nine are accepted below, three are fixed in Azure but still reported by the scanner, and
one is a planned fix (see the end of this file).

**Scoring.** Impact comes from the Prowler severity (critical 5, high 4, medium 3, low 2).
Likelihood is analyst judgment, with the reason written down. Rating = likelihood × impact.

**Approval.** This is a single-maintainer sandbox, so the owner is also the approver. In
production, the authorizing official (or delegate) signs each entry, and it is tracked as
a POA&M item with a deviation request.

**Publication.** This register is public because the environment is a sandbox with no
regulated data, and it names no secrets, account names or subscription IDs. In
production it would live in the organization's internal GRC system, not a public
repository: a list of known weaknesses is a map for an attacker.

| ID | Check | Severity | Resources | Rating | Owner | Accepted | Review by |
|---|---|---|---|---|---|---|---|
| RA-001 | AZU-0012 storage network default action is Allow | Critical | 3 storage accounts | 2 × 5 = 10 | @moniquecarter | 2026-11-01 | 2026-11-15 |
| RA-002 | AZU-0061 infrastructure encryption not enabled | Medium | 3 storage accounts | 1 × 3 = 3 | @moniquecarter | 2026-11-01 | 2026-11-15 |
| RA-003 | AZU-0058 storage not geo-redundant | Low | 3 storage accounts | 2 × 2 = 4 | @moniquecarter | 2026-11-01 | 2026-11-15 |

Resources, by Terraform address:
`stages/03-evidence-store`: `azurerm_storage_account.evidence`, `azurerm_storage_account.func_internal`;
`stages/04-reporting`: `azurerm_storage_account.func_internal`.

---

## RA-001: Storage network default action is Allow

**Finding.** None of the three storage accounts has network rules, so they accept
connections from any network (Trivy AZU-0012).

**Why it isn't fixed.** The collector and reporting apps run on the Linux Consumption plan
(Y1). That plan has no VNet integration and no fixed outbound IPs, so a default-deny
firewall would cut both apps off from their own runtime storage and from the evidence
store. The fix is a plan change (Flex Consumption or Premium with VNet integration and
private endpoints), which costs more than this sandbox's $10/month budget allows.

**Compensating controls.**
- Evidence store: shared keys disabled, so every request needs an Entra ID token with a
  data-plane role; only the pipeline's own identities and the deployer hold one.
- WORM immutability on the `reports` container: even a valid identity can't alter or
  delete a report.
- All three accounts: TLS 1.2 minimum, public blob access off, and `cge-deny-public-blob`
  denies turning it on.
- Blob access logs (read, write, delete) from every storage account to `law-grc-sandbox`,
  deployed and kept in place by the own policy `hbai-dine-blob-access-logs` (see AZU-0057
  below), so any use of a leaked key leaves a record.

**Residual risk.** The two Function runtime accounts still allow shared keys, because the
Functions runtime connects with one. Anyone holding a key could reach them from the
internet. This is not hypothetical: on 2026-10-31 the IaC scan found those keys in plain
text in a local `terraform show -json` file left from a conftest run. The file was
gitignored and never committed; it was deleted the same day. Likelihood stays at 2
because keys only exist in Terraform state, app settings and short-lived plan files, and
the pipeline's own secret scan catches the last of these.

**Exit criteria.** Move the apps to a VNet-capable plan with private endpoints, or switch
`AzureWebJobsStorage` to identity-based connections and disable shared keys. The research
enclave is built with private endpoints from the start.

**Mappings.** NIST 800-53 SC-7, AC-17 · CSF 2.0 PR.IR-01, GV.RM

## RA-002: Infrastructure encryption not enabled

**Finding.** The accounts use Azure's platform encryption (AES-256, Microsoft-managed keys)
but not the optional second layer at the infrastructure level (Trivy AZU-0061).

**Why it isn't fixed.** `infrastructure_encryption_enabled` can only be set when an account
is created; in Terraform, changing it destroys and recreates the account. For
`azurerm_storage_account.evidence`, that means deleting the WORM report history the
pipeline exists to keep, and the immutability policy would likely make the destroy fail
partway through. A plan with this change was prepared on 2026-11-01 and withdrawn before
apply for that reason.

**Compensating controls.** Platform encryption at rest is always on; TLS 1.2 in transit;
the evidence store holds compliance metadata, not regulated research data.

**Residual risk.** Low. Double encryption protects against a flaw in one encryption layer
or its keys; the single layer is still FIPS 140-2 validated.

**Exit criteria.** Enabled from day one on every new account, including all research
enclave storage. Existing accounts get it only if they are rebuilt for another reason.

**Mappings.** NIST 800-53 SC-28, SC-28(1) · CSF 2.0 PR.DS-01

## RA-003: Storage not geo-redundant

**Finding.** All three accounts use locally redundant storage (LRS): three copies in one
datacenter (Trivy AZU-0058).

**Why it isn't fixed.** Geo-redundant storage roughly doubles the storage cost, and a
regional outage in a sandbox pauses evidence collection; it does not lose regulated data.

**Compensating controls.** Reports are regenerated from Cosmos DB by design; Cosmos and the
Terraform state are separate services; Terraform rebuilds the infrastructure from code.

**Residual risk.** A loss of the region could lose report history that has not been
exported. Local copies of key reports are kept outside Azure.

**Exit criteria.** GRS or GZRS for any account holding regulated research data, decided
with the enclave's availability requirement.

**Mappings.** NIST 800-53 CP-6, CP-9 · CSF 2.0 PR.DS-11

---

## Not accepted: fixed in Azure, still reported by the scanner

### AZU-0057: Storage logging not enabled (Medium, 3 storage accounts)

**Status: fixed 2026-11-01** by the own policy `hbai-dine-blob-access-logs`
(`stages/01-foundation/policies-hbai.tf`). The IaC scan will keep reporting it; that is a
scanner limitation, not an open risk.

**What we found.** The starter policy `cge-dine-storage-diagnostics` reported Compliant on
all three accounts, but it routes only account-level `Transaction` metrics. Blob access
logs live on the blob service (`blobServices/default`), and the evidence store had no
diagnostic setting there at all. Nobody could answer "who read or deleted evidence?".
Compliant, but not effective.

**What fixed it.** A DeployIfNotExists policy in the baseline initiative routes
`StorageRead`, `StorageWrite` and `StorageDelete` from every blob service in the sandbox
to `law-grc-sandbox`. Rolled out audit first:

| Step | Result |
|---|---|
| AuditIfNotExists | 5 of 5 blob services NonCompliant (includes the seed and Terraform state accounts) |
| Escalation | Reviewed PR: effect to DeployIfNotExists |
| Remediation task (`ReEvaluateCompliance`), run as `id-grc-remediation-dev` | 5 deployed, 0 failed |
| Next evaluation | 5 of 5 Compliant; evidence store shows `ds-blob-access-to-grc` with all three categories |

**Why the scanner still flags it.** Trivy's AZU-0057 passes only on the
`queue_properties { logging {} }` block: classic Storage Analytics logging for the Queue
service, stored in the account's own `$logs` container and deprecated in azurerm 4.x. It
would not log blob access, and it cannot see diagnostic settings deployed by policy.
Prowler's Azure provider has no blob-logging check either (5.43.0), so Azure Policy
compliance is the verification.

**Mappings.** NIST 800-53 AU-2, AU-12 · CSF 2.0 DE.CM, PR.PS

## Not accepted: planned fixes

| Check | Severity | Resources | Plan |
|---|---|---|---|
| AZU-0060 no customer-managed key on the evidence store | Medium | `azurerm_storage_account.evidence` | Capstone phase 3: Key Vault with purge protection, a rotating key, and CMK on the evidence store (CSA AICM CEK-03, CEK-12, CEK-14). |

## History

| Date | Change |
|---|---|
| 2026-11-01 | RA-001 to RA-003 accepted after the Prowler IaC baseline. Fixed in the same pass: AZU-0004 (HTTPS-only on both Function Apps), and the plaintext keys in local plan files (deleted). |
| 2026-11-01 | AZU-0057 fixed by `hbai-dine-blob-access-logs` (audit, escalate, remediate: 5 of 5 Compliant); recorded as a scanner limitation. RA-001 compensating controls updated to include blob access logs. |
