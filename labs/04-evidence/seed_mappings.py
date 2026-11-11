#!/usr/bin/env python3
"""Seed the mappings container: the framework crosswalk, as data.

Collect once, map to many. The nightly collector stores Defender assessments; this
script stores, once, which framework controls each assessment type speaks to. Reports
join the two from the store. Nothing here is typed by hand: every row comes from a
versioned vendor source, and every row says which one.

  direct            assessment -> Azure Policy -> Microsoft built-in initiative group
                    (NIST CSF 2.0, NIST SP 800-53 Rev. 5)
  via-...           direct controls -> Prowler compliance files (CSA CCM v4.0, which
                    carries the AICM CEK IDs; FedRAMP 20x KSI). Two pivots:
                    800-53 base controls (CCM and KSI) and CSF 2.0 subcategories,
                    matched exactly (CCM only; the KSI file has no CSF references).
                    Coarser than direct, so it is labeled as derived and keeps the
                    pivot controls that produced each link.

Run as YOU (az login); the deployer's Cosmos data role comes from stage 03:

    export ARM_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
    export COSMOS_ENDPOINT=$(cd ../../stages/03-evidence-store && terraform output -raw cosmos_endpoint)
    python seed_mappings.py --dry-run     # coverage only, writes nothing
    python seed_mappings.py               # upsert into mappings

Prowler's compliance files are read from the local Prowler install (5.43.0 via uv);
override with PROWLER_COMPLIANCE_DIR.
"""

import argparse
import datetime
import glob
import json
import os
import re
import sys
import uuid

import requests
from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential

ARM = "https://management.azure.com"
INITIATIVES = {
    # frameworkId: (built-in policy set definition name, group-name prefix)
    "nist-csf-2.0": ("184a0e05-7b06-4a68-bbbe-13b8353bc613", "NIST_CSF_v2.0_"),
    "nist-800-53-r5": ("179d1daa-458f-4e47-8086-2a68d0d6c38f", "NIST_SP_800-53_R5_"),
}
PROWLER_FILES = {
    # frameworkId: compliance file, relative to Prowler's compliance directory
    "csa-ccm-4.0": "csa_ccm_4.0.json",
    "fedramp-20x-ksi": "fedramp_20x_ksi_2026.json",
}


# --- ARM reads ---------------------------------------------------------------

def _get_all(url, token):
    """GET every page: ARM list calls stop at 1,000 items and hand back a nextLink."""
    items = []
    while url:
        resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=60)
        resp.raise_for_status()
        payload = resp.json()
        items += payload.get("value", [])
        url = payload.get("nextLink")
    return items


def assessment_policies(subscription_id, token):
    """Assessment key -> (display name, policy definition ID), for policy-backed types."""
    url = (f"{ARM}/subscriptions/{subscription_id}"
           f"/providers/Microsoft.Security/assessmentMetadata?api-version=2021-06-01")
    out = {}
    for item in _get_all(url, token):
        props = item.get("properties", {})
        if props.get("policyDefinitionId"):
            out[item["name"]] = (props.get("displayName"), props["policyDefinitionId"].lower())
    return out


def initiative(set_id, token):
    url = (f"{ARM}/providers/Microsoft.Authorization/policySetDefinitions/{set_id}"
           f"?api-version=2023-04-01")
    resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=60)
    resp.raise_for_status()
    return resp.json()


# --- control-ID normalization -----------------------------------------------

def csf_id(group, prefix):
    """NIST_CSF_v2.0_PR.AA_05 -> PR.AA-05; NIST_CSF_v2.0_PR.AA -> PR.AA."""
    return group[len(prefix):].replace("_", "-")


def sp80053_id(raw):
    """One spelling for 800-53: 'AC-2(1)', 'AC-2 (1)' and 'AC-2.1' all -> 'AC-2(1)'."""
    raw = raw.strip().upper().replace(" ", "")
    m = re.fullmatch(r"([A-Z]{2})-(\d+)(?:\((\d+)\)|\.(\d+))?", raw)
    if not m:
        return None
    fam, num, enh = m.group(1), m.group(2), m.group(3) or m.group(4)
    return f"{fam}-{num}({enh})" if enh else f"{fam}-{num}"


def base_control(ctrl):
    """AC-2(1) -> AC-2. The pivot matches on base controls (see module docstring)."""
    return ctrl.split("(")[0]


# --- Prowler compliance files -------------------------------------------------

def prowler_dir():
    if os.environ.get("PROWLER_COMPLIANCE_DIR"):
        return os.environ["PROWLER_COMPLIANCE_DIR"]
    appdata = os.environ.get("APPDATA", os.path.expanduser("~/.local/share"))
    return os.path.join(appdata, "uv", "tools", "prowler", "Lib", "site-packages",
                        "prowler", "compliance")


def prowler_version(compliance_dir):
    site = os.path.dirname(os.path.dirname(compliance_dir))
    found = glob.glob(os.path.join(site, "prowler-*.dist-info"))
    return os.path.basename(found[0])[len("prowler-"):-len(".dist-info")] if found else None


def prowler_index(path):
    """Pivot indexes for one Prowler framework, keyed by the pivot framework:
    'nist-800-53-r5' (base control) and 'nist-csf-2.0' (subcategory) -> requirement IDs."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    index = {"nist-800-53-r5": {}, "nist-csf-2.0": {}}
    for req in doc["requirements"]:
        attrs = req.get("attributes", {})
        raw = []
        if "NISTControls" in attrs:                                   # FedRAMP 20x KSI
            raw = attrs["NISTControls"].split(",")
        for scope in attrs.get("ScopeApplicability", []):             # CSA CCM v4.0
            if scope.get("ReferenceId") == "NIST 800-53 rev 5":
                raw += scope.get("Identifiers", [])
            elif scope.get("ReferenceId") == "NIST CSF v2.0":
                for sub in scope.get("Identifiers", []):
                    index["nist-csf-2.0"].setdefault(sub.strip().upper(), set()).add(req["id"])
        for ctrl in filter(None, (sp80053_id(r) for r in raw)):
            index["nist-800-53-r5"].setdefault(base_control(ctrl), set()).add(req["id"])
    return doc.get("name"), doc.get("version"), index


# --- build ---------------------------------------------------------------------

def build(subscription_id, token):
    build_id = str(uuid.uuid4())
    built_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    assessments = assessment_policies(subscription_id, token)
    docs = []

    # direct: Microsoft's own policy -> control grouping
    direct = {fw: {} for fw in INITIATIVES}       # frameworkId -> assessment key -> controls
    for fw, (set_id, prefix) in INITIATIVES.items():
        ini = initiative(set_id, token)
        props = ini["properties"]
        source = {"type": "azure-policy-initiative", "id": ini["id"],
                  "name": props.get("displayName"), "version": props.get("version")}
        by_policy = {}
        for ref in props.get("policyDefinitions", []):
            pid = ref["policyDefinitionId"].lower()
            for group in ref.get("groupNames", []):
                if group.startswith(prefix):
                    ctrl = (csf_id(group, prefix) if fw == "nist-csf-2.0"
                            else sp80053_id(group[len(prefix):]))
                    if ctrl:
                        by_policy.setdefault(pid, set()).add(ctrl)
        for key, (name, pid) in assessments.items():
            if pid in by_policy:
                controls = sorted(by_policy[pid])
                docs.append(_doc(fw, key, name, pid, controls, "direct", None,
                                 source, build_id, built_at))
                direct[fw][key] = controls

    # derived: 800-53 base controls and CSF 2.0 subcategories pivot into CCM (AICM CEK)
    # and KSI. A link records every pivot control that produced it.
    pivot_keys = {
        "nist-800-53-r5": lambda controls: {base_control(c) for c in controls},
        "nist-csf-2.0": lambda controls: {c for c in controls if "-" in c},  # subcategories only
    }
    cdir = prowler_dir()
    pver = prowler_version(cdir)
    for fw, filename in PROWLER_FILES.items():
        name_fw, ver_fw, index = prowler_index(os.path.join(cdir, filename))
        source = {"type": "prowler-compliance", "file": filename, "name": name_fw,
                  "version": ver_fw, "prowlerVersion": pver}
        for key in set(direct["nist-800-53-r5"]) | set(direct["nist-csf-2.0"]):
            pivots, reqs = {}, set()
            for pivot_fw, keys_of in pivot_keys.items():
                for k in keys_of(direct[pivot_fw].get(key, [])):
                    if k in index[pivot_fw]:
                        pivots.setdefault(pivot_fw, set()).add(k)
                        reqs |= index[pivot_fw][k]
            if reqs:
                name, pid = assessments[key]
                derivation = "via-" + "+".join(sorted(pivots))
                docs.append(_doc(fw, key, name, pid, sorted(reqs), derivation,
                                 {p: sorted(v) for p, v in sorted(pivots.items())},
                                 source, build_id, built_at))
    return docs, len(assessments), build_id


def _doc(fw, key, name, pid, controls, derivation, pivots, source, build_id, built_at):
    doc = {
        "id": f"{fw}:{key}",
        "frameworkId": fw,
        "assessmentId": key,
        "assessmentName": name,
        "policyDefinitionId": pid,
        "controls": controls,
        "derivation": derivation,
        "source": source,
        "buildId": build_id,
        "builtAt": built_at,
    }
    if pivots:
        doc["pivotControls"] = pivots
    return doc


# --- coverage, from the store ----------------------------------------------

def coverage(db, docs):
    store = db.get_container_client("assessments")
    latest = list(store.query_items(
        "SELECT TOP 1 c.runId FROM c ORDER BY c.collectedAt DESC",
        enable_cross_partition_query=True))
    if not latest:
        print("no collection run in the store yet")
        return
    run_id = latest[0]["runId"]
    rows = list(store.query_items(
        "SELECT c.assessmentId, c.displayName, c.status FROM c WHERE c.runId = @run",
        parameters=[{"name": "@run", "value": run_id}], enable_cross_partition_query=True))
    unhealthy = [r for r in rows if r["status"] == "Unhealthy"]
    mapped = {}
    for d in docs:
        mapped.setdefault(d["frameworkId"], set()).add(d["assessmentId"])
    print(f"\nlatest collection run {run_id}: {len(rows)} findings, {len(unhealthy)} Unhealthy")
    for fw in list(INITIATIVES) + list(PROWLER_FILES):
        ids = mapped.get(fw, set())
        print(f"  {fw:<16} all: {sum(r['assessmentId'] in ids for r in rows):>3}/{len(rows)}"
              f"   Unhealthy: {sum(r['assessmentId'] in ids for r in unhealthy):>3}/{len(unhealthy)}")
    any_fw = set().union(*mapped.values()) if mapped else set()
    gaps = sorted({r["displayName"] for r in unhealthy if r["assessmentId"] not in any_fw})
    if gaps:
        n = sum(r["assessmentId"] not in any_fw for r in unhealthy)
        print(f"\nUnhealthy findings mapped to no framework: {n} findings, {len(gaps)} types:")
        for g in gaps:
            print(f"  - {g}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--dry-run", action="store_true", help="report coverage, write nothing")
    args = parser.parse_args()

    subscription_id = os.environ.get("ARM_SUBSCRIPTION_ID")
    endpoint = os.environ.get("COSMOS_ENDPOINT")
    if not subscription_id or not endpoint:
        print("Set ARM_SUBSCRIPTION_ID and COSMOS_ENDPOINT (see docstring).", file=sys.stderr)
        return 1

    credential = DefaultAzureCredential()
    token = credential.get_token(f"{ARM}/.default").token
    docs, n_types, build_id = build(subscription_id, token)

    per_fw = {}
    for d in docs:
        per_fw[d["frameworkId"]] = per_fw.get(d["frameworkId"], 0) + 1
    print(f"build {build_id}: {n_types} policy-backed assessment types, {len(docs)} mapping rows")
    for fw, n in sorted(per_fw.items()):
        print(f"  {fw:<16} {n:>4} rows")

    db = (CosmosClient(endpoint, credential)
          .get_database_client(os.environ.get("COSMOS_DATABASE", "grc")))
    coverage(db, docs)

    if args.dry_run:
        print("\n--dry-run: nothing written")
        return 0
    mappings = db.get_container_client("mappings")
    for d in docs:
        mappings.upsert_item(d)
    print(f"\nupserted {len(docs)} rows into mappings (build {build_id})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
