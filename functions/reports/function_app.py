"""CGE-AZ pipeline — Stage 4 report generators.

Reports read from Cosmos ONLY — never from live services. Every number in every
artifact resolves to a stored, timestamped document. A report that reads live data
is a report whose numbers can't be reproduced tomorrow; a report that reads the
store is a fact with a receipt.

Generators here: POA&M (xlsx + json, daily) and SAR (markdown, weekly), both with
HTTP triggers for labs and demos.
"""

import datetime
import io
import json
import logging
import os
from collections import Counter

import azure.functions as func
from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from openpyxl import Workbook

app = func.FunctionApp()

# Severity-based SLAs: a POA&M is a plan, not a list.
SLA_DAYS = {"High": 30, "Medium": 90, "Low": 180}

# The crosswalk (labs/04-evidence/seed_mappings.py), in report order. Direct mappings
# come from Microsoft's initiatives; derived ones pivot through them, so they are
# shown as related controls, never as the primary mapping.
FRAMEWORKS = [
    ("nist-csf-2.0", "NIST CSF 2.0"),
    ("nist-800-53-r5", "NIST SP 800-53 Rev. 5"),
    ("csa-ccm-4.0", "CSA CCM v4.0 (AICM CEK IDs)"),
    ("fedramp-20x-ksi", "FedRAMP 20x KSI"),
]
TOP_N = 8


def _clients():
    credential = DefaultAzureCredential()
    db = CosmosClient(os.environ["COSMOS_ENDPOINT"], credential).get_database_client(
        os.environ["COSMOS_DATABASE"]
    )
    blobs = BlobServiceClient(
        account_url=os.environ["REPORTS_ACCOUNT_URL"], credential=credential
    ).get_container_client(os.environ["REPORTS_CONTAINER"])
    return db.get_container_client("assessments"), blobs, db.get_container_client("mappings")


def _latest_run(cosmos):
    """Pin the report to a specific collection sweep — a statement about a known moment."""
    rows = list(
        cosmos.query_items(
            "SELECT TOP 1 c.runId, c.collectedAt FROM c ORDER BY c.collectedAt DESC",
            enable_cross_partition_query=True,
        )
    )
    return (rows[0]["runId"], rows[0]["collectedAt"]) if rows else (None, None)


def _unhealthy(cosmos, run_id):
    return list(
        cosmos.query_items(
            "SELECT * FROM c WHERE c.runId = @run AND c.status = 'Unhealthy'",
            parameters=[{"name": "@run", "value": run_id}],
            enable_cross_partition_query=True,
        )
    )


def _dated_path(prefix: str, ext: str) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    return f"{prefix}/{now:%Y/%m}/{prefix}-{now:%Y-%m-%d}.{ext}"


def _crosswalk(mappings, findings):
    """Mapping rows for this run's findings, read from the store: {frameworkId: {assessmentId: row}}.
    One query per framework, each inside its own partition."""
    ids = sorted({f.get("assessmentId") for f in findings if f.get("assessmentId")})
    xwalk = {fw: {} for fw, _ in FRAMEWORKS}
    if not ids:
        return xwalk
    for fw, _ in FRAMEWORKS:
        for row in mappings.query_items(
            "SELECT c.assessmentId, c.controls, c.derivation, c.buildId, c.builtAt "
            "FROM c WHERE ARRAY_CONTAINS(@ids, c.assessmentId)",
            parameters=[{"name": "@ids", "value": ids}],
            partition_key=fw,
        ):
            xwalk[fw][row["assessmentId"]] = row
    return xwalk


def _short(items, n=6):
    items = list(items)
    if not items:
        return "none"
    more = f" (+{len(items) - n} more)" if len(items) > n else ""
    return ", ".join(items[:n]) + more


def _sar_markdown(run_id, collected_at, findings, xwalk) -> str:
    """Pure formatting: every number below is computed from `findings` (the run's
    Unhealthy assessments) and `xwalk` (their mapping rows), both read from the store."""
    by_severity = Counter(f.get("severity") or "Unknown" for f in findings)
    rows = [r for fw in xwalk.values() for r in fw.values()]
    builds = sorted({(r.get("buildId"), r.get("builtAt")) for r in rows})

    lines = [
        "# Security Assessment Report (SAR)",
        "",
        f"- **Collection run:** `{run_id}`",
        f"- **Collected at:** {collected_at}",
        f"- **Open findings:** {len(findings)}",
        f"- **By severity:** " + (", ".join(f"{k}: {v}" for k, v in sorted(by_severity.items())) or "none"),
        "- **Crosswalk build:** "
        + (", ".join(f"`{b}` ({t})" for b, t in builds) if builds else "none in the store"),
        "",
        "## Findings by framework",
        "",
        "Direct mappings come from Microsoft's built-in initiatives (assessment, Azure Policy,"
        " initiative group). CCM and KSI are derived through those controls (Prowler"
        " compliance files) and are listed as related controls.",
        "",
    ]
    for fw, label in FRAMEWORKS:
        mapped = [f for f in findings if f.get("assessmentId") in xwalk[fw]]
        per_control = Counter(
            c for f in mapped for c in xwalk[fw][f["assessmentId"]]["controls"]
        )
        lines.append(f"### {label}")
        lines.append(f"- Open findings mapped: **{len(mapped)} of {len(findings)}**")
        if fw == "nist-csf-2.0":
            per_function = Counter(
                fn for f in mapped
                for fn in {c.split(".")[0] for c in xwalk[fw][f["assessmentId"]]["controls"]}
            )
            lines.append("- By function: " + _short(
                [f"{k}: {v}" for k, v in sorted(per_function.items())], n=6))
            subs = [(c, n) for c, n in per_control.most_common() if "-" in c]
            lines.append("- Top subcategories: " + _short([f"{c} ({n})" for c, n in subs], n=TOP_N))
        elif fw == "nist-800-53-r5":
            per_family = Counter(
                fam for f in mapped
                for fam in {c.split("-")[0] for c in xwalk[fw][f["assessmentId"]]["controls"]}
            )
            lines.append("- Top families: " + _short(
                [f"{k} ({v})" for k, v in per_family.most_common()], n=TOP_N))
        elif fw == "csa-ccm-4.0":
            cek = sorted((c, n) for c, n in per_control.items() if c.startswith("CEK-"))
            lines.append("- CEK (cryptography, encryption and key management): "
                         + _short([f"{c} ({n})" for c, n in cek], n=TOP_N))
        if fw in ("csa-ccm-4.0", "fedramp-20x-ksi"):
            lines.append("- Top controls: " + _short(
                [f"{c} ({n})" for c, n in per_control.most_common()], n=TOP_N))
        lines.append("")

    lines += ["## Findings", ""]
    for f in sorted(findings, key=lambda x: x.get("severity") or ""):
        aid = f.get("assessmentId")
        ctl = {fw: xwalk[fw][aid]["controls"] if aid in xwalk[fw] else [] for fw, _ in FRAMEWORKS}
        lines += [
            f"### {f.get('displayName')}",
            f"- Severity: {f.get('severity')}",
            f"- Resource: `{f.get('resourceId')}`",
            f"- Assessment ID: `{aid}` (trace: query the assessments container)",
            f"- NIST CSF 2.0: {_short(ctl['nist-csf-2.0'])}",
            f"- NIST 800-53: {_short(ctl['nist-800-53-r5'])}",
            f"- Related (derived): CCM {_short(ctl['csa-ccm-4.0'])} · KSI {_short(ctl['fedramp-20x-ksi'])}",
            "",
        ]

    lines += [
        "## How to reproduce these numbers",
        "",
        "1. Findings: `SELECT * FROM c WHERE c.runId = @run AND c.status = 'Unhealthy'`"
        " on the `assessments` container, with `@run` = the collection run above.",
        "2. Mappings: `SELECT * FROM c WHERE ARRAY_CONTAINS(@ids, c.assessmentId)` on the"
        " `mappings` container, partition = framework ID, with `@ids` = the findings'"
        " `assessmentId` values.",
        "3. A finding counts as mapped to a framework when a row exists for its"
        " `assessmentId` in that partition; control counts are findings per control.",
        "",
    ]
    return "\n".join(lines)


def generate_poam() -> dict:
    cosmos, blobs, _ = _clients()
    run_id, collected_at = _latest_run(cosmos)
    findings = _unhealthy(cosmos, run_id) if run_id else []
    today = datetime.date.today()

    wb = Workbook()
    ws = wb.active
    ws.title = "POA&M"
    ws.append(
        ["POA&M ID", "Weakness", "Affected Resource", "Severity",
         "Detected (run)", "Scheduled Completion", "Owner", "Status"]
    )
    rows = []
    for i, f in enumerate(sorted(findings, key=lambda x: x.get("severity") or ""), 1):
        severity = f.get("severity") or "Medium"
        due = today + datetime.timedelta(days=SLA_DAYS.get(severity, 90))
        row = {
            "poamId": f"POAM-{today:%Y%m%d}-{i:03d}",
            "weakness": f.get("displayName"),
            "resourceId": f.get("resourceId"),
            "severity": severity,
            "detectedRun": run_id,
            "scheduledCompletion": due.isoformat(),
            "owner": "resource-group owner tag",  # resolved during Domain 5's lab extension
            "status": "Open",
        }
        rows.append(row)
        ws.append(list(row.values()))

    xlsx = io.BytesIO()
    wb.save(xlsx)
    xlsx_path = _dated_path("poam", "xlsx")
    json_path = _dated_path("poam", "json")
    blobs.upload_blob(xlsx_path, xlsx.getvalue(), overwrite=False)
    blobs.upload_blob(
        json_path,
        json.dumps({"runId": run_id, "collectedAt": collected_at, "items": rows}, indent=2),
        overwrite=False,
    )
    logging.info("POA&M: %d items -> %s", len(rows), xlsx_path)
    return {"items": len(rows), "runId": run_id, "xlsx": xlsx_path, "json": json_path}


def generate_sar() -> dict:
    cosmos, blobs, mappings = _clients()
    run_id, collected_at = _latest_run(cosmos)
    findings = _unhealthy(cosmos, run_id) if run_id else []
    xwalk = _crosswalk(mappings, findings)

    path = _dated_path("sar", "md")
    blobs.upload_blob(path, _sar_markdown(run_id, collected_at, findings, xwalk), overwrite=False)
    logging.info("SAR: %d findings -> %s", len(findings), path)
    return {"findings": len(findings), "runId": run_id, "path": path}


@app.timer_trigger(schedule="0 0 6 * * *", arg_name="timer", run_on_startup=False)
def poam_daily(timer: func.TimerRequest) -> None:
    generate_poam()


@app.timer_trigger(schedule="0 0 7 * * 1", arg_name="timer", run_on_startup=False)
def sar_weekly(timer: func.TimerRequest) -> None:
    generate_sar()


@app.route(route="poam", auth_level=func.AuthLevel.FUNCTION)
def poam_now(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(generate_poam()) + "\n", status_code=200)


@app.route(route="sar", auth_level=func.AuthLevel.FUNCTION)
def sar_now(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(generate_sar()) + "\n", status_code=200)
