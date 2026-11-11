# Azure GRC Evidence Pipeline

An automated governance, risk and compliance (GRC) pipeline for Azure, built as code:
it discovers what is running, enables what is missing, collects security assessments
into an evidence store it owns, writes reports from that store only, maps every finding
to several frameworks, and enforces policy with a human approving each escalation.

Capstone for **CGE-AZ: Certified GRC Engineer — Azure Specialty** (GRC Engineering
Club), built on a fork of [GRCEngClub/cgeaz](https://github.com/GRCEngClub/cgeaz) and
extended with its own controls, crosswalk and fixes
([additions to the starter](#additions-to-the-starter)).

> **Sandbox.** Everything here runs in a single sandbox subscription with no real or
> regulated data. Findings, reports and risk acceptances describe that sandbox.

```
1 Discovery → 2 Activation → 3 Evidence store → 4 Reporting → 6 Enforcement ↺
  what runs     close the       Cosmos DB +        POA&M, SAR     Azure Policy +
                measured gap    WORM Blob +        from the       remediation identity,
                                collector          store only     dry-run first
                                        └── crosswalk: CSF 2.0 · 800-53 · CCM/AICM CEK · FedRAMP 20x KSI
```

Stage 5 of the course (AI narrative) is optional and not implemented.

## How it works

| Stage | Root module | What it does |
|---|---|---|
| Remote state | `labs/03-foundation/bootstrap.sh` | Storage for Terraform state (Entra ID auth). The one piece that is a script, because state can't manage itself. |
| 01 Foundation | `stages/01-foundation` | Management groups `mg-grc` → `mg-grc-sandbox`, resource groups, Log Analytics workspace, the `cge-grc-baseline` initiative assigned at management-group scope, and the remediation identity. |
| 02 Activation | `stages/02-activation` | Reads every Defender plan's tier first, then enables only the baseline plans that are missing. Assigns the NIST CSF 2.0 standard. |
| 03 Evidence store | `stages/03-evidence-store` | Cosmos DB (`assessments`, `frameworks`, `mappings`), a reports container with WORM immutability and shared keys disabled, and the nightly collector Function. |
| 04 Reporting | `stages/04-reporting` | Report Functions: POA&M daily, SAR weekly. Read-only on Cosmos, write-only on the reports container. |
| 06 Enforcement | `stages/06-enforcement` | A remediation policy deployed in **dry-run** (`DoNotEnforce`). Escalation is a reviewed one-line change to `remediation_mode`. |

Every stage has its own state and reads the others only through their outputs. More detail
(data flow, partition keys, identity boundaries): [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

**Schedules (UTC):** collection 05:00 daily, POA&M 06:00 daily, SAR 07:00 Mondays, drift
check 08:00 daily.

**Identities.** No stored credentials: Functions use managed identities, CI uses OIDC
federation. Each identity holds only its job's roles. The collector can write
assessments but not reports. The reporter can read assessments and write reports, and
nothing else. The remediation identity has no Owner or Contributor role. The one
exception, shared keys on the two Functions runtime accounts, is documented in
[RISK-ACCEPTANCES.md](docs/RISK-ACCEPTANCES.md) (RA-001).

## Additions to the starter

| Change | Why | Where |
|---|---|---|
| **Own policy `hbai-dine-blob-access-logs`**, rolled out Audit → DeployIfNotExists → remediation (5 of 5 Compliant) | The starter's diagnostics policy reported Compliant but only routed metrics: nobody could answer "who read or deleted evidence?" | `stages/01-foundation/policies-hbai.tf`, PRs #11, #12 |
| **Framework crosswalk as data**: 706 rows from Microsoft's NIST CSF 2.0 and 800-53 Rev. 5 initiatives (direct), plus CSA CCM v4.0 (with the AICM CEK IDs) and FedRAMP 20x KSI via Prowler's compliance files (derived) | "Collect once, map to many", with every row naming its source and version | `labs/04-evidence/seed_mappings.py`, PR #19 |
| **SAR "Findings by framework"**, with the stored queries that reproduce every number | Makes the crosswalk visible in a report, read from the store only | `functions/reports/function_app.py`, PR #20 |
| **Working CI gate**: conftest 0.71.1 pinned with a SHA-256 check, `fail-fast: false` | The original action bundled an OPA that couldn't parse the policies, so no policy was ever evaluated; it was also an unpinned third-party action | `.github/workflows/gate.yml`, PR #14. A test PR proves it blocks: #15 |
| **Drift detector fix** (`terraform_wrapper: false`) | The wrapper swallowed exit code 2, so drift was never reported | `.github/workflows/drift.yml`, PR #2 |
| **Pinned deployer identity** for stage 03 | CI plans wanted to move evidence-store write access from the owner to the CI identity, a nightly false alarm and a separation-of-duties risk | `stages/03-evidence-store`, PR #17 |
| **Prowler IaC scanning before deploy**, with HTTPS-only enforced on both Function Apps | Shift-left: Terraform is scanned (Prowler 5.43.0 with Trivy) before it reaches Azure; remaining findings are fixed or formally accepted | PR #9, [RISK-ACCEPTANCES.md](docs/RISK-ACCEPTANCES.md) |

## Deploy from an empty subscription

Full walkthroughs with expected output are in `labs/01-sandbox` to `labs/06-loop`. This is
the order and the minimum commands.

### 0. Before you start
- Tools: Azure CLI, Terraform ≥ 1.9, Python 3.12 with `azure-cosmos` and `azure-identity`
  in a virtual environment, and for scanning Prowler 5.43.0 and conftest 0.71.1. Windows
  notes: [docs/SETUP-WINDOWS.md](docs/SETUP-WINDOWS.md).
- **Set a budget alert first.** On a pay-as-you-go subscription it is the only spending
  guardrail ([docs/SETUP.md](docs/SETUP.md), Lab 01).
- Register resource providers: `labs/00-setup/register-providers.sh`.
- Check Functions quota, which is regional: `labs/00-setup/probe-quota.sh`. The defaults
  are `centralus` for Functions and `eastus2` for Cosmos DB.
- Two pieces are set up with the CLI in Labs 01 and 02, not by Terraform: the budget and
  the subscription Activity Log export to the workspace.

### 1. Remote state
```bash
./labs/03-foundation/bootstrap.sh          # writes labs/03-foundation/backend.hcl (gitignored)
export TF_VAR_owner_email=<owner email>    # owner tag on governed resource groups
export TF_VAR_state_storage_account=<state storage account from bootstrap>
```

### 2. Stages, in order
For each of `01-foundation`, `02-activation`, `03-evidence-store`, `04-reporting`,
`06-enforcement`:
```bash
cd stages/<stage>
terraform init -backend-config=../../labs/03-foundation/backend.hcl
terraform plan -out=plan.tfplan
prowler iac --scan-path ..                 # review new findings before applying
terraform apply plan.tfplan && rm plan.tfplan
```
A plan file can contain secrets (storage keys), so delete it straight after use.
(`*.tfplan` is gitignored, so a forgotten one can't be committed by accident.)

After stage 03:
1. Deploy the collector: zip `functions/collect_assessments` and run
   `az functionapp deployment source config-zip --build-remote true` (Lab 04, step 3).
2. Seed the frameworks: `labs/04-evidence/seed_frameworks.py`.
3. Seed the crosswalk: `labs/04-evidence/seed_mappings.py --dry-run` (coverage only),
   then without `--dry-run`.

After stage 04, deploy the report Functions the same way from `functions/reports`
(Lab 05, step 2).

**After every Functions zip deploy, run `terraform plan` in that stage again.**
`--build-remote true` removes the `ENABLE_ORYX_BUILD` app setting that the stage sets, so
the plan shows one in-place change. Apply it locally.

Stage 06 deploys in dry-run by default. Escalate only through a reviewed change to
`remediation_mode`.

### 3. CI on your fork
```bash
./labs/06-loop/arm-your-fork.sh            # OIDC app registration + repository variables
```
Then:
- Add a repository **secret** `DEPLOYER_OBJECT_ID` with your Entra user object ID, with
  no trailing newline: `az ad signed-in-user show --query id -o tsv | tr -d '\r\n'`.
- Protect `main`: require a pull request and the four `gate (…)` checks, and don't allow
  bypassing.

Never apply stage 03 from CI.

## How changes are made

`plan` → `prowler iac` → pull request → the gate runs `terraform plan` and conftest on
all four pipeline stages → merge → `apply` the saved plan locally → delete the plan file.
Nothing changes through the portal; the drift detector opens an issue when Azure and the
code disagree.

## Evidence and reports

- **Assessments:** one document per assessment per resource, upserted on a deterministic
  ID and stamped with `runId` and `collectedAt` (Cosmos `assessments`, partition
  `/subscriptionId`).
- **Reports:** POA&M (`.xlsx` and `.json`) and SAR (`.md`) on dated paths in the WORM
  `reports` container, 90-day retention. A report can't be changed or deleted once written.
- **Tracing a number:** every SAR names its collection run and crosswalk build and lists
  the stored queries behind its counts.

## Documentation

| File | Contents |
|---|---|
| [docs/CONTROLS.md](docs/CONTROLS.md) | Every policy, collector and gate rule mapped to NIST CSF 2.0 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Stage flow, data flow, identity boundaries |
| [docs/RISK-ACCEPTANCES.md](docs/RISK-ACCEPTANCES.md) | Accepted findings, with compensating controls, owner and review date |
| [docs/RUBRIC.md](docs/RUBRIC.md) | The course rubric this capstone is graded against |
| [docs/SETUP.md](docs/SETUP.md), [docs/VALIDATION-LOG.md](docs/VALIDATION-LOG.md) | Course setup and the issues found while validating the labs |

## Repository layout

```
stages/     one Terraform root module per stage, each with its own state
functions/  collector and report generators (Python, timer-triggered, managed identity)
labs/       the course lab guides, setup scripts and the seed scripts
policy/     OPA/conftest rules that gate this repo's own Terraform
docs/       architecture, control mappings, risk acceptances, rubric, setup
.github/    the compliance gate (pull requests) and drift detection (nightly)
```

## Teardown

In reverse order: `06-enforcement` → `04-reporting` → `03-evidence-store` →
`02-activation` (sets the baseline Defender plans back to Free) → `01-foundation`, then
delete the CI app registration. WORM-protected reports can block deleting the evidence
store until their retention period ends.

---

Course material and the starter pipeline: [GRCEngClub/cgeaz](https://github.com/GRCEngClub/cgeaz) ·
[www.grcengclub.com](https://www.grcengclub.com)
