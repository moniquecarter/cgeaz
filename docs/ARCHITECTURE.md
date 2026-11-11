# Pipeline Architecture

How this pipeline is put together: the stage flow, the contracts between stages, where
data goes, and which identity is allowed to touch what. It extends the course starter's
architecture; every place this fork departs from the starter is marked **This fork:**
and says why. Sections 5 to 7 are new.

## 1. Stage flow

```
            ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐
  Lab 1-3   │ 01 foundation│───▶│ 02 activation│    │ 03 evidence store│
            │ MG hierarchy │    │ discover gap │    │ Cosmos + WORM    │
            │ policies     │    │ enable plans │    │ blob + collector │
            │ remediation  │    │ CSF 2.0 std  │    │ + crosswalk data │
            │ identity     │    └──────────────┘    └────────┬─────────┘
            └──────┬───────┘                                 ▼
                   │                                ┌──────────────────┐
                   │                                │ 04 reporting     │
                   │                                │ POA&M + SAR from │
                   │                                │ the store ONLY   │
                   ▼                                └──────────────────┘
            ┌──────────────┐
            │ 06 enforce   │                        05 narrative: not implemented
            │ Modify effect│                        (optional in the course)
            │ audit→dry-run│
            │ →enforce     │
            └──────────────┘
```

Each stage is a Terraform root module with its own state file in the shared `tfstate`
container (bootstrapped once by `labs/03-foundation/bootstrap.sh`, the one piece that
cannot manage itself). Stages are applied in number order and destroyed in reverse.

**This fork:** stage 05 (an AI digest of the reports) is not implemented. The course
treats it as optional, and the rubric gives no penalty for leaving it out.

### The contract between stages

Downstream stages read upstream **outputs** through `terraform_remote_state`. Outputs
are the interface; everything else is private implementation.

| Stage | Reads from | Publishes |
|---|---|---|
| 01 foundation | nothing | `subscription_id`, `management_group_id`, `log_analytics_workspace_id`, `evidence_resource_group_name`, `remediation_identity_id`, `remediation_identity_principal_id` |
| 02 activation | nothing (discovers live state with `azapi` data sources) | Defender plan tiers, the NIST CSF 2.0 assignment |
| 03 evidence store | 01 | `cosmos_endpoint`, `cosmos_account_id/name`, `evidence_storage_account`, `reports_container`, `collector_function_app`, `collector_principal_id` |
| 04 reporting | 01, 03 | `reporting_function_app`, `reporter_principal_id` |
| 06 enforcement | 01 | `remediation_mode` |

Stage 01 adopts the Lab 1–2 resources (management groups, sandbox resource group, Log
Analytics workspace) with `terraform import` rather than recreating them. Stage 02 is
discovery-first: `azapi` data sources read every Defender plan's current tier and
activation converges only the measured gap; a plan already at Standard stays untouched
and becomes change-managed.

**This fork:** stage 03 takes one more input, `deployer_object_id` (see section 3). It
is set in CI and left unset locally.

## 2. Data flow

```
 Defender for Cloud ──(assessments API)──▶ collector Function ──▶ Cosmos: assessments
       │                                   daily 05:00 UTC            /subscriptionId
       │                                   runId + collectedAt
  Azure Policy ──────────────────────────▶ compliance states (portal / CLI)

  Microsoft initiatives (CSF 2.0, 800-53) ─┐
  Prowler compliance files (CCM, KSI) ─────┴─▶ seed_mappings.py ──▶ Cosmos: mappings
                                                                      /frameworkId
                        frameworks ◀── seed_frameworks.py (CSF 2.0 catalog)
                                                                    │
                                                                    ▼
                                           reporting Function ◀── reads Cosmos ONLY
                                           POA&M daily 06:00 (xlsx + json)
                                           SAR Mondays 07:00 (md, with the crosswalk)
                                                                    │
                                                                    ▼
                                           WORM `reports` container (immutable blob)

  every blob service ──(diagnostic setting, own policy)──▶ Log Analytics: StorageBlobLogs
```

Three rules make this defensible:

- **Collect once.** One assessment document serves every framework through the
  `mappings` crosswalk. Adding a framework is a data change, not a collector change.
- **Reports read from the store only.** No report touches a live API. Every number is
  reproducible with a stored query against a pinned `runId`.
- **Immutability is a platform guarantee, not an access rule.** The `reports` container
  carries a 90-day time-based immutability policy. It is unlocked so teardown works;
  production locks it.

**This fork:** the `mappings` container is filled (section 5), the SAR uses it, and
blob access on every storage account is logged (section 6).

**Cosmos holds current state, not history.** Each run upserts on a deterministic ID and
overwrites `runId` and `collectedAt`, so Cosmos answers "what is true at the last
collection". History lives in the dated, immutable reports: the WORM container is the
audit trail.

### Partition keys, justified

| Container | Partition key | Why |
|---|---|---|
| `assessments` | `/subscriptionId` | Every query the reports run is "this subscription, this run". A second and third subscription land as new partitions with no reshaping: the pipeline scales by scope, not by size. |
| `frameworks` | `/frameworkId` | A catalog is read whole, one framework at a time. |
| `mappings` | `/frameworkId` | The SAR asks one question per framework ("which controls does each of this run's findings map to?"), so each framework is one partition and one query. Document ID: `<frameworkId>:<assessmentId>`. |

Document IDs in `assessments` are a hash of `assessmentId|resourceId`, so a re-run
upserts rather than duplicates; lineage comes from `runId` and `collectedAt` on every
document.

## 3. Identity boundaries

Zero stored credentials anywhere in the design. Every actor is a managed identity or an
OIDC federation, and every identity's roles are a whitelist of its job.

| Identity | Kind | Roles (scope) | Can | Cannot |
|---|---|---|---|---|
| **Deployer** (owner) | `az login` user | Owner on the subscription; Storage Blob Data Contributor on the evidence account; Cosmos Data Contributor | Apply stages, seed frameworks and mappings, prove WORM | Nothing is automated through this identity |
| **Remediation** `id-grc-remediation-<env>` | User-assigned MI | Monitoring Contributor (sandbox MG); Storage Account Contributor (sandbox MG) *only* when `remediation_mode != audit` | Create diagnostic settings (starter and own policy); flip `allowBlobPublicAccess` | Create, delete, or read data from anything |
| **Collector** `func-grc-collectors-*` | System-assigned MI | Security Reader (subscription); Cosmos Built-in Data Contributor (evidence account) | Read Defender assessments; write evidence | Change posture; write reports |
| **Reporter** `func-grc-reporting-*` | System-assigned MI | Cosmos Built-in Data Reader (whole account, so also `mappings`); Storage Blob Data Contributor (`reports`) | Read evidence and the crosswalk; write immutable reports | Read live platform data; write evidence |
| **CI** (gate + drift on this fork) | GitHub OIDC federation, fork-scoped | Contributor at `mg-grc`; Storage Blob Data Contributor on the state resource group | `terraform plan`, conftest | Write RBAC; hold a secret; apply stage 03 |

The boundaries that matter:

- **Recorder ≠ narrator.** The collector writes evidence and cannot write reports; the
  reporter reads evidence and cannot touch live services. Separation of duties is
  enforced by role scopes, not by policy text.
- **One named author for every automated change.** Filtering the Activity Log by the
  remediation identity's principal ID gives the complete history of what automation
  did. Humans and CI show up as themselves.
- **Control plane ≠ data plane.** Owner on the subscription does not read a blob or a
  Cosmos document; the deployer and both Functions hold explicit data-plane roles. The
  evidence account disables shared keys and Cosmos disables local auth, so there is no
  key-shaped way around this.
- **Upstream is unarmed.** The workflows skip until `AZURE_CLIENT_ID` is set. Each fork
  federates its own CI against its own subscription (`labs/06-loop/arm-your-fork.sh`).

**This fork: the deployer is pinned, not inferred.** The starter granted the deployer's
data-plane roles to `data.azurerm_client_config.current`, which is whoever runs
Terraform: the owner locally, the CI identity in GitHub. Every CI plan therefore wanted to
move evidence-store write access to the CI identity, and the drift job opened a false
issue every night. Stage 03 now uses `coalesce(var.deployer_object_id, <caller>)`: unset
locally (no change), set in CI from the repository secret `DEPLOYER_OBJECT_ID`. A
validation rule accepts only a GUID, which caught a secret pasted with a trailing newline
before any role was touched. CI and local plans now agree (PR #17).

**Known exception:** the two Functions runtime storage accounts keep shared keys, because
the Consumption-plan runtime connects with one. Accepted as RA-001 in
[RISK-ACCEPTANCES.md](RISK-ACCEPTANCES.md), with compensating controls.

## 4. The two loops

**The pipeline on the environment.** Policy assignments at the sandbox management group
inherit to every current and future subscription. Effects are deliberate: Audit for the
tag rule (onboarding), Deny for public blob (earned), DeployIfNotExists for diagnostics
(logging that enforces its own coverage). Stage 06 adds a Modify effect on an escalation
ladder wired to one variable, `audit` → `dry-run` → `enforce`, where each step up is a
reviewed one-line diff and dry-run keeps a human at the remediation-task approval.

**The pipeline on itself.** The compliance gate (`.github/workflows/gate.yml`) runs
`terraform plan` for stages 01, 03, 04 and 06 on every pull request and refuses plans
that break the repo's own standard (`policy/*.rego`: no public blob, no shared keys
outside the documented runtime exception, no Owner or Contributor grants, an identity on
every policy assignment). Drift detection (`drift.yml`) plans nightly with
`-detailed-exitcode` and opens an issue when reality has moved away from code.

**This fork: both loops had to be repaired before they worked.**

| Problem | Effect | Fix |
|---|---|---|
| `instrumenta/conftest-action@master` bundles an OPA older than 0.59, which cannot parse `import rego.v1` | The gate failed on a parse error for every pull request; no policy was ever evaluated | conftest **0.71.1** (OPA 1.21.1, the version used locally) downloaded from the official release and checked with SHA-256 before it runs; this also removes an unpinned third-party action (PR #14) |
| Matrix fail-fast cancelled the other stages mid-plan when one failed | Cancelled jobs never released their state locks; two stale locks blocked later runs | `fail-fast: false`; locks cleared once with `terraform force-unlock` after checking no run was active |
| `setup-terraform`'s wrapper turned exit code 2 (drift) into success | The drift job never opened an issue | `terraform_wrapper: false` in both workflows (PRs #2, #14) |

Proof that the gate blocks: test PR #15 set `allow_nested_items_to_be_public = true` on a
stage 04 storage account. The plan succeeded, conftest denied it, and the merge button
stayed disabled. `main` requires a pull request and the four `gate (…)` checks, with no
bypass, including for admins.

**Defense in depth.** The same mistake is stopped twice: by conftest before merge, and by
the Deny policy `cge-deny-public-blob` at deploy time if anyone applies around the gate.

**Scanning before deploy.** Terraform is also scanned with Prowler 5.43.0 (`prowler iac`,
Trivy underneath) before it is applied. The scan trail (`00` baseline → `01` after the
HTTPS-only fix → `02` after the own policy, deployer and crosswalk changes) ends at 13
findings, each fixed in Azure, accepted with compensating controls, or planned
([RISK-ACCEPTANCES.md](RISK-ACCEPTANCES.md)).

## 5. The framework crosswalk

`labs/04-evidence/seed_mappings.py` builds the `mappings` container once from versioned
vendor sources. Nothing is typed by hand, and every row names its source and version.

```
Defender assessment ─(metadata: policyDefinitionId)─▶ Azure Policy definition
                                                          │
         Microsoft built-in initiatives (groups) ◀────────┘
         ├─ NIST CSF 2.0 (v1.7.0)             ─▶ direct: CSF subcategories
         └─ NIST SP 800-53 Rev. 5 (v14.21.0)  ─▶ direct: 800-53 controls
                     │                │
       800-53 base controls      CSF subcategories
                     ▼                ▼
         Prowler 5.43.0 compliance files (derived)
         ├─ CSA CCM v4.0.13  (pivots: 800-53 + CSF)  ─▶ CCM controls, incl. AICM CEK IDs
         └─ FedRAMP 20x KSI 2026 (pivot: 800-53)     ─▶ KSIs
```

**Row shape:** `frameworkId` (partition key), `assessmentId`, `controls`, `derivation`
(`direct`, or `via-` plus the pivot frameworks), `pivotControls` for derived rows,
`source` (name and version), `buildId`, `builtAt`. Identifiers are normalized to one
spelling (`PR.AA_05` → `PR.AA-05`, `AT-2.2` and `AT-2 (2)` → `AT-2(2)`).

**Design choices:**
- **Direct and derived are kept apart.** A CCM or KSI link reached through 800-53 or CSF is
  an inference, not Microsoft's mapping. The SAR shows direct controls first and lists
  derived ones as related.
- **Derived links match on 800-53 base controls.** CCM and KSI mostly cite base controls,
  so matching on enhancements would drop most links. The cost is breadth: one finding can
  reach 20 or more CCM controls through broad controls such as AC-2 or SI-4. Each derived
  row keeps the pivot controls that produced it, so a reviewer can see why.
- **CSF pivots match exact subcategories.** Category-level matching (`PR.DS`) would be too
  coarse; subcategories (`PR.DS-01`) line up one-to-one with CCM's references.
- **Re-runs upsert.** A row that a later build no longer produces keeps its older
  `buildId`; the SAR header names the build(s) it used.

**Coverage** (build `116ec3f3`, collection run `7393aa30`, 52 open findings): CSF 2.0 32,
800-53 19, CCM 35, KSI 19. One finding type maps to no framework ("Storage accounts should
prevent shared key access"), because Microsoft's initiatives don't include that policy; it
is covered by RA-001. Run `seed_mappings.py --dry-run` to recompute coverage from the
store without writing.

**In the SAR:** a "Findings by framework" section (coverage, CSF functions and top
subcategories, 800-53 families, CCM CEK controls, top KSIs), the controls on each finding,
and the stored queries that reproduce every number.

## 6. Own control: `hbai-dine-blob-access-logs`

| | |
|---|---|
| **Gap it closes** | The starter's `cge-dine-storage-diagnostics` reported Compliant on every account but routes only account-level `Transaction` metrics. Blob access logs live on `blobServices/default`, and the evidence store had no diagnostic setting there, so "who read or deleted evidence?" had no answer. Compliant, not effective. |
| **What it checks** | Every `Microsoft.Storage/storageAccounts/blobServices` resource in the sandbox management group must have a diagnostic setting that sends `StorageRead`, `StorageWrite` and `StorageDelete` to the GRC workspace. Mode `All`, because blob services have no tags or location. |
| **Where it lives** | `stages/01-foundation/policies-hbai.tf`, in the `cge-grc-baseline` initiative as reference `hbaiBlobAccessLogs`; effect wired to `blob_access_logs_effect`. Mapped in [CONTROLS.md](CONTROLS.md) (DE.CM, PR.PS; NIST 800-53 AU-2, AU-12). |
| **Who acts** | The remediation identity, with Monitoring Contributor it already held. No new role. |
| **Effect, and why** | Started at AuditIfNotExists to measure the gap and the cost; escalated to DeployIfNotExists by a reviewed variable change once both were known. |
| **Blast radius** | Adds one diagnostic setting (`ds-blob-access-to-grc`) per blob service. Changes no data, access or network settings. Cost is Log Analytics ingestion: about 300 MB a month across the sandbox, within the free allowance. |
| **Rollback** | Set `blob_access_logs_effect = "Disabled"`. Settings already deployed stay until removed by hand. |
| **Evidence** | Audit: 5 of 5 blob services NonCompliant. Remediation task (with `ReEvaluateCompliance`): 5 deployed, 0 failed. Re-scan: 5 of 5 Compliant. `StorageBlobLogs` arrives from all five accounts. |

The IaC scanner still reports the matching finding (Trivy AZU-0057): it only recognizes a
deprecated queue-logging block and cannot see settings deployed by policy. Azure Policy
compliance is the verification.

## 7. Operational notes and known limits

- **Zip deploys remove an app setting.** `az functionapp deployment source config-zip
  --build-remote true` deletes `ENABLE_ORYX_BUILD`, which stages 03 and 04 set. Every
  Functions deploy is followed by a plan in that stage, which shows one in-place change to
  apply. The drift job would also catch it overnight.
- **Plan files carry secrets.** A `terraform show -json` file left from a local conftest
  run contained real storage keys (found by the IaC scan, never committed). Plan files are
  deleted straight after use, and `*.tfplan`, `tfplan`, `tf.plan`, `plan.json` and
  `plan.txt` are gitignored.
- **A nightly collector misses short-lived misconfigurations.** During the Lab 06 test,
  public access was on for about an hour between two collections and never reached a
  POA&M. Policy compliance state and the Activity Log caught it. Reports show the state at
  collection time, not continuous coverage.
- **The pipeline can't yet alert on its own failures.** The POA&M timer didn't fire on
  2026-10-20 (`FunctionExecutionCount` 0). The miss was found by reviewing run history, not
  by an alert, because the Function Apps have no Application Insights. Planned: Application
  Insights and a missed-run alert (AU-6, SI-4).
- **Stage 02 runs locally only.** It isn't in the gate or drift matrix; changes to Defender
  plans are planned and applied by the owner.
