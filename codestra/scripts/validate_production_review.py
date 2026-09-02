#!/usr/bin/env python3
"""Fail-closed checks for Prometheus production review remediations."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import yaml


ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True


def fail(message: str) -> None:
    print(f"PROMETHEUS_PRODUCTION_REVIEW_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def load_collector() -> ModuleType:
    path = ROOT / "codestra" / "scripts" / "collect_staging_intake_evidence.py"
    spec = importlib.util.spec_from_file_location("codestra_staging_evidence", path)
    if spec is None or spec.loader is None:
        fail("cannot load staging evidence collector")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_sample_completeness() -> None:
    module = load_collector()
    metadata = []
    for family in sorted(module.EXPECTED_METRIC_FAMILIES):
        metadata.extend((f"# HELP {family} declared only", f"# TYPE {family} gauge"))
    metadata.extend(
        (
            'codestra_release_info{codestra_business="platform",application="integration",service="middleware-api",environment="staging",release_sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",image_digest="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",schema_or_migration_head="0003_immutable_event_ledger"} 1',
            'intake_inbox_backlog{codestra_business="platform",application="integration",service="middleware-api",environment="staging",queue="inbox"} 0',
        )
    )
    payload = ("\n".join(metadata) + "\n").encode("utf-8")
    try:
        module.analyze_metrics(payload, max_series=5000, max_family_series=500)
    except module.EvidenceError as exc:
        if "required metric families are missing" not in str(exc):
            fail(f"metadata-only fixture failed for the wrong reason: {exc}")
    else:
        fail("metadata declarations without samples were incorrectly certified")


def validate_production_target_isolation() -> None:
    config_path = ROOT / "codestra" / "prometheus" / "prometheus.yml"
    document = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        fail("Prometheus configuration must be an object")
    jobs = {
        item.get("job_name"): item
        for item in document.get("scrape_configs", [])
        if isinstance(item, dict)
    }
    job = jobs.get("codestra-targets")
    if not isinstance(job, dict):
        fail("codestra-targets job is missing")
    file_sd = job.get("file_sd_configs")
    if not isinstance(file_sd, list) or len(file_sd) != 1:
        fail("codestra-targets must define exactly one file discovery source")
    files = file_sd[0].get("files")
    if files != ["/etc/prometheus/targets/production.json"]:
        fail(f"production discovery is not isolated: {files}")
    serialized = config_path.read_text(encoding="utf-8")
    if "/etc/prometheus/targets/*.json" in serialized:
        fail("production configuration still contains wildcard target discovery")


def validate_artifact_bound_activation() -> None:
    path = ROOT / ".github" / "workflows" / "controlled-intake-staging-activation-gate.yml"
    text = path.read_text(encoding="utf-8")
    required = (
        "staging_evidence_run_id:",
        "staging_evidence_artifact_name:",
        "actions: read",
        "gh api \"repos/$GITHUB_REPOSITORY/actions/runs/$STAGING_EVIDENCE_RUN_ID\"",
        "gh run download \"$STAGING_EVIDENCE_RUN_ID\"",
        "computed = \"sha256:\" + hashlib.sha256(evidence_bytes).hexdigest()",
        "if evidence_document[\"overall_result\"] != \"PASS\"",
        "if evidence_document[\"environment\"] != \"staging\"",
        "if evidence_document[\"middleware_release\"][\"image_digest\"] != image",
        "if evidence_document[\"activation\"] != expected_activation",
    )
    for fragment in required:
        if fragment not in text:
            fail(f"activation workflow omits artifact evidence control: {fragment}")


def main() -> int:
    validate_sample_completeness()
    validate_production_target_isolation()
    validate_artifact_bound_activation()
    print("PROMETHEUS_PRODUCTION_REVIEW=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
