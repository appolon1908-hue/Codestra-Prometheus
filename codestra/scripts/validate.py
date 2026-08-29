#!/usr/bin/env python3
from __future__ import annotations
import json, re, sys
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_LABELS = {"activation", "job_class", "environment", "server", "application", "service", "tenant_scope"}
ALLOWED_ENVIRONMENTS = {"development", "test", "staging", "production"}
ALLOWED_ACTIVATION = {"active", "pending"}
ALLOWED_TENANT_SCOPES = {"aggregate", "system", "isolated"}
FORBIDDEN = re.compile(r"(?i)^(tenant_id|tenant_name|organization_id|organization_name|customer_id|customer_name|account_id|user_id|user_name|email|phone|consumer|workspace|token|secret|password|session_id|request_id|correlation_id|trace_id|span_id|lead_id|order_id|message_id|workflow_id|execution_id|webhook_id|idempotency_key|raw_path|path|uri|url|query|query_string)$")
REQUIRED_SERVICES = {"node-exporter", "cadvisor", "postgres-exporter", "redis-exporter", "caddy", "kong", "middleware", "keycloak", "n8n", "odoo", "opentelemetry-collector", "alertmanager"}

def fail(message: str) -> None: raise SystemExit(message)
def load_yaml(path: Path):
    try: return yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc: fail(f"invalid YAML {path.relative_to(ROOT)}: {exc}")

def main() -> int:
    targets_path = ROOT / "prometheus" / "targets" / "production.json"
    try: groups = json.loads(targets_path.read_text(encoding="utf-8"))
    except Exception as exc: fail(f"invalid target JSON: {exc}")
    seen = set()
    for group in groups:
        if not group.get("targets"): fail("target group without targets")
        labels = group.get("labels", {})
        missing = REQUIRED_LABELS - labels.keys()
        if missing: fail(f"target {group['targets']} missing labels {sorted(missing)}")
        if labels["environment"] not in ALLOWED_ENVIRONMENTS: fail("invalid environment")
        if labels["activation"] not in ALLOWED_ACTIVATION: fail("invalid activation")
        if labels["tenant_scope"] not in ALLOWED_TENANT_SCOPES: fail("invalid tenant_scope")
        forbidden = [key for key in labels if FORBIDDEN.fullmatch(key)]
        if forbidden: fail(f"forbidden target labels {forbidden}")
        seen.add(labels["service"])
    missing_services = REQUIRED_SERVICES - seen
    if missing_services: fail(f"missing required services {sorted(missing_services)}")

    config = load_yaml(ROOT / "prometheus" / "prometheus.yml")
    jobs = {job.get("job_name") for job in config.get("scrape_configs", [])}
    if jobs != {"prometheus", "codestra-targets", "blackbox"}: fail(f"unexpected scrape jobs {sorted(jobs)}")
    if not config.get("alerting", {}).get("alertmanagers"): fail("Alertmanager is required")

    records, alerts = set(), set()
    for path in sorted((ROOT / "prometheus" / "rules").glob("*.yml")):
        doc = load_yaml(path)
        for group in doc.get("groups", []):
            for rule in group.get("rules", []):
                if not isinstance(rule.get("expr"), str) or not rule["expr"].strip(): fail(f"empty rule in {path.name}")
                if "record" in rule:
                    if rule["record"] in records: fail(f"duplicate recording rule {rule['record']}")
                    records.add(rule["record"])
                if "alert" in rule:
                    if rule["alert"] in alerts: fail(f"duplicate alert {rule['alert']}")
                    alerts.add(rule["alert"])
    if not records or not alerts: fail("recording rules and alerts are required")

    compose = load_yaml(ROOT / "compose.yaml")
    for name, service in compose.get("services", {}).items():
        image = service.get("image", "")
        if "${" not in image or "@sha256:" not in image: fail(f"{name} must require an immutable image")
    print("Codestra Prometheus authority validation passed")
    return 0

if __name__ == "__main__": sys.exit(main())
