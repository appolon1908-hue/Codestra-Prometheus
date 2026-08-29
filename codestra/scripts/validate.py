#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_LABELS = {
    "activation",
    "job_class",
    "environment",
    "server",
    "application",
    "service",
    "tenant_scope",
}
ALLOWED_ENVIRONMENTS = {"development", "test", "staging", "production"}
ALLOWED_ACTIVATION = {"active", "pending"}
ALLOWED_TENANT_SCOPES = {"aggregate", "system", "isolated"}
ALLOWED_SEVERITIES = {"critical", "high", "warning", "informational"}
REQUIRED_ALERT_LABELS = {
    "severity",
    "owner",
    "codestra_business",
    "service",
    "environment",
}
REQUIRED_ALERT_ANNOTATIONS = {"summary", "description", "runbook_url"}
EXPECTED_JOBS = {
    "prometheus",
    "codestra-targets",
    "otel-application-metrics",
    "blackbox",
}
FORBIDDEN = re.compile(
    r"(?i)^(tenant_id|tenant_name|organization_id|organization_name|"
    r"customer_id|customer_name|account_id|user_id|user_name|email|phone|"
    r"consumer|workspace|token|secret|password|session_id|request_id|"
    r"correlation_id|trace_id|span_id|lead_id|order_id|message_id|workflow_id|"
    r"execution_id|webhook_id|idempotency_key|raw_path|path|uri|url|query|"
    r"query_string|client_address|network_peer_address|db_statement|http_target|"
    r"http_url|url_full|service_instance_id|host_id|container_id|image_id|"
    r"process_pid|id)$"
)
REQUIRED_SERVICES = {
    "node-exporter",
    "cadvisor",
    "postgres-exporter",
    "redis-exporter",
    "caddy",
    "kong",
    "middleware",
    "keycloak",
    "n8n",
    "odoo",
    "opentelemetry-collector",
    "alertmanager",
}


def fail(message: str) -> None:
    raise SystemExit(message)


def load_yaml(path: Path):
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"invalid YAML {path.relative_to(ROOT)}: {exc}")


def validate_targets() -> None:
    targets_path = ROOT / "prometheus" / "targets" / "production.json"
    try:
        groups = json.loads(targets_path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"invalid target JSON: {exc}")

    seen = set()
    for group in groups:
        if not group.get("targets"):
            fail("target group without targets")
        labels = group.get("labels", {})
        missing = REQUIRED_LABELS - labels.keys()
        if missing:
            fail(f"target {group['targets']} missing labels {sorted(missing)}")
        if labels["environment"] not in ALLOWED_ENVIRONMENTS:
            fail(f"target {group['targets']} has invalid environment")
        if labels["activation"] not in ALLOWED_ACTIVATION:
            fail(f"target {group['targets']} has invalid activation")
        if labels["tenant_scope"] not in ALLOWED_TENANT_SCOPES:
            fail(f"target {group['targets']} has invalid tenant_scope")
        forbidden = [key for key in labels if FORBIDDEN.fullmatch(key)]
        if forbidden:
            fail(f"target {group['targets']} has forbidden labels {forbidden}")
        seen.add(labels["service"])

    missing_services = REQUIRED_SERVICES - seen
    if missing_services:
        fail(f"missing required services {sorted(missing_services)}")


def validate_scrape_config() -> None:
    config = load_yaml(ROOT / "prometheus" / "prometheus.yml")
    jobs = {job.get("job_name"): job for job in config.get("scrape_configs", [])}
    if set(jobs) != EXPECTED_JOBS:
        fail(f"unexpected scrape jobs {sorted(jobs)}")
    if not config.get("alerting", {}).get("alertmanagers"):
        fail("Alertmanager is required")

    otel_job = jobs["otel-application-metrics"]
    if otel_job.get("honor_labels") is not True:
        fail("OTLP application scrape must preserve sanitized canonical labels")
    static_configs = otel_job.get("static_configs", [])
    if len(static_configs) != 1:
        fail("OTLP application scrape must have one governed static target")
    otel_labels = static_configs[0].get("labels", {})
    if otel_labels.get("activation") != "pending":
        fail("OTLP application scrape must remain pending until staging evidence passes")
    if static_configs[0].get("targets") != ["otel-collector:8889"]:
        fail("OTLP application scrape must target otel-collector:8889")
    metric_rules = otel_job.get("metric_relabel_configs", [])
    if not any(rule.get("action") == "labeldrop" for rule in metric_rules):
        fail("OTLP application scrape requires defense-in-depth label stripping")
    if not any(
        rule.get("action") == "drop" and "target_info" in str(rule.get("regex", ""))
        for rule in metric_rules
    ):
        fail("OTLP application scrape must drop resource metadata helper series")


def validate_rules() -> None:
    records: set[str] = set()
    alerts: set[str] = set()
    for path in sorted((ROOT / "prometheus" / "rules").glob("*.yml")):
        doc = load_yaml(path)
        for group in doc.get("groups", []):
            for rule in group.get("rules", []):
                if not isinstance(rule.get("expr"), str) or not rule["expr"].strip():
                    fail(f"empty rule in {path.name}")
                if "record" in rule:
                    if rule["record"] in records:
                        fail(f"duplicate recording rule {rule['record']}")
                    records.add(rule["record"])
                if "alert" in rule:
                    alert = rule["alert"]
                    if alert in alerts:
                        fail(f"duplicate alert {alert}")
                    alerts.add(alert)
                    labels = rule.get("labels", {})
                    annotations = rule.get("annotations", {})
                    missing_labels = REQUIRED_ALERT_LABELS - labels.keys()
                    missing_annotations = REQUIRED_ALERT_ANNOTATIONS - annotations.keys()
                    if missing_labels:
                        fail(f"alert {alert} missing labels {sorted(missing_labels)}")
                    if missing_annotations:
                        fail(
                            f"alert {alert} missing annotations {sorted(missing_annotations)}"
                        )
                    if labels["severity"] not in ALLOWED_SEVERITIES:
                        fail(f"alert {alert} has invalid severity {labels['severity']}")
                    if not str(annotations["runbook_url"]).startswith("https://"):
                        fail(f"alert {alert} runbook_url must be HTTPS")

    if not records or not alerts:
        fail("recording rules and alerts are required")
    if "CodestraWatchdog" not in alerts:
        fail("CodestraWatchdog is required to prove the end-to-end alert path")


def validate_runtime() -> None:
    compose = load_yaml(ROOT / "compose.yaml")
    for name, service in compose.get("services", {}).items():
        image = service.get("image", "")
        if "${" not in image or "@sha256:" not in image:
            fail(f"{name} must require an immutable image")


def main() -> int:
    validate_targets()
    validate_scrape_config()
    validate_rules()
    validate_runtime()
    print("Codestra Prometheus authority validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
