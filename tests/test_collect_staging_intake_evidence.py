from __future__ import annotations

import base64
import importlib.util
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).parents[1] / "codestra/scripts/collect_staging_intake_evidence.py"
spec = importlib.util.spec_from_file_location("collector", MODULE_PATH)
collector = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(collector)

SOURCE = "9a96ff1651a324b98f3a7efd60b7a342983ded4e"
DIGEST = "sha256:01a61e6c9761968bce04db855df565e9104338c2ba2056da570cacb9fd21f0f4"


def token(jti: str) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({
        "iat": 100,
        "exp": 400,
        "azp": "monitoring-readonly",
        "aud": ["middleware-api"],
        "scope": "metrics.read health.read",
        "jti": jti,
    }).encode()).decode().rstrip("=")
    return f"{header}.{payload}.signature-{jti}"


def metrics_payload() -> bytes:
    rows: list[str] = []
    for family in sorted(collector.EXPECTED_METRIC_FAMILIES):
        rows.extend((f"# HELP {family} test", f"# TYPE {family} gauge"))
        if family == "codestra_release_info":
            continue
        labels = ""
        if family.startswith(("lead_", "survey_", "intake_")):
            labels = '{codestra_business="platform",application="integration",service="middleware-api",environment="staging"}'
        rows.append(f"{family}{labels} 0")
    rows.append(f'codestra_release_info{{service="middleware-api",component="api",environment="staging",release_sha="{SOURCE}",image_digest="{DIGEST}",schema_or_migration_head="0008_durable_communications",version="0.1.0"}} 1')
    return ("\n".join(rows) + "\n").encode()


def rollback_document(target: str) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "evidence_type": "prometheus-staging-rollback-proof",
        "performed_at": "2026-09-02T00:00:00+00:00",
        "environment": "staging",
        "prometheus_target": target,
        "middleware_source_sha": SOURCE,
        "middleware_image_digest": DIGEST,
        "prometheus_only": True,
        "restored_health": True,
        "production_changed": False,
        "external_effects_triggered": False,
        "klyrow_changed": False,
        "postal_changed": False,
        "result": "PASS",
    }


def safety_document() -> dict[str, object]:
    return {
        "schema_version": "1.1",
        "service": "middleware-api",
        "environment": "staging",
        "runtime_profile_id": "codestra-middleware-staging-v1",
        "release": {
            "source_sha": SOURCE,
            "image_digest": DIGEST,
            "schema_head": "0008_durable_communications",
            "build_time": "2026-09-02T17:41:48Z",
        },
        "persistence": {"in_memory": False},
        "dispatch": {"outbox_enabled": False, "nats_mode": "disabled", "temporal_worker_mode": "disabled"},
        "external_effects": {name: False for name in collector.EXPECTED_EXTERNAL_EFFECT_KEYS},
        "umbrella_controls": {
            name: False for name in collector.EXPECTED_UMBRELLA_CONTROL_KEYS
        },
        "production_dialing": "DISABLED",
        "production_activation_configured": False,
        "provider_effects_disabled": True,
        "all_external_effects_disabled": True,
        "staging_safe": True,
    }


class Handler(BaseHTTPRequestHandler):
    metrics_token = token("metrics")
    health_token = token("health")
    prometheus_target = ""

    def log_message(self, *_args):
        pass

    def do_GET(self):
        authorization = self.headers.get("Authorization", "")
        if self.path == "/api/v1/targets?state=active":
            document = {
                "status": "success",
                "data": {
                    "activeTargets": [
                        {
                            "discoveredLabels": {
                                "__address__": self.prometheus_target,
                            },
                            "labels": {
                                "job": "middleware-intake-staging-readiness",
                                "instance": self.prometheus_target,
                            },
                            "scrapeUrl": f"http://{self.prometheus_target}/metrics",
                            "lastError": "",
                            "lastScrape": "2026-09-02T00:00:00Z",
                            "health": "up",
                        }
                    ]
                },
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(document).encode())
            return
        if self.path.startswith("/api/v1/query?"):
            document = {
                "status": "success",
                "data": {
                    "resultType": "vector",
                    "result": [
                        {
                            "metric": {
                                "job": "middleware-intake-staging-readiness",
                                "instance": self.prometheus_target,
                            },
                            "value": [1_788_307_200, "1"],
                        }
                    ],
                },
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(document).encode())
            return
        if self.path == "/metrics":
            if authorization != f"Bearer {self.metrics_token}":
                self.send_response(401)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.end_headers()
            self.wfile.write(metrics_payload())
            return
        if self.path == "/v1/runtime/safety":
            if authorization != f"Bearer {self.health_token}":
                self.send_response(401)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(safety_document()).encode())
            return
        self.send_response(404)
        self.end_headers()


class CollectorTests(unittest.TestCase):
    def test_unchanged_monitoring_tokens_are_rejected_after_soak(self):
        metrics = collector.decode_jwt_metadata(token("metrics"))
        health = collector.decode_jwt_metadata(token("health"))
        with self.assertRaisesRegex(
            collector.EvidenceError,
            "newly issued credentials",
        ):
            collector.require_token_rotation(metrics, health, metrics, health)

    def test_metric_contract_and_privacy(self):
        result = collector.analyze_metrics(metrics_payload(), max_series=5000, max_family_series=500)
        self.assertEqual(result["missing_metric_families"], [])
        declarations_only = "\n".join(
            f"# TYPE {family} gauge"
            for family in sorted(collector.EXPECTED_METRIC_FAMILIES)
        ).encode()
        with self.assertRaises(collector.EvidenceError):
            collector.analyze_metrics(
                declarations_only,
                max_series=5000,
                max_family_series=500,
            )
        bad = metrics_payload() + b'intake_inbox_backlog{codestra_business="platform",application="integration",service="middleware-api",environment="staging",customer_id="123"} 1\n'
        with self.assertRaises(collector.EvidenceError):
            collector.analyze_metrics(bad, max_series=5000, max_family_series=500)

    def test_identity_labels_are_format_checked_and_scanned(self):
        bad = metrics_payload() + b'codestra_release_info{service="middleware-api",component="api",environment="staging",release_sha="operator@example.invalid",image_digest="sha256:01a61e6c9761968bce04db855df565e9104338c2ba2056da570cacb9fd21f0f4",schema_or_migration_head="0008_durable_communications",version="0.1.0"} 1\n'
        with self.assertRaises(collector.EvidenceError):
            collector.analyze_metrics(bad, max_series=5000, max_family_series=500)

    def test_runtime_safety_rejects_empty_or_unknown_evidence(self):
        empty = safety_document()
        empty["external_effects"] = {}
        with self.assertRaises(collector.EvidenceError):
            collector.validate_runtime_safety(json.dumps(empty).encode(), SOURCE, DIGEST)
        unknown = safety_document()
        unknown["diagnostic"] = {"credential": "must-not-be-persisted"}
        with self.assertRaises(collector.EvidenceError):
            collector.validate_runtime_safety(json.dumps(unknown).encode(), SOURCE, DIGEST)
        missing_umbrella = safety_document()
        missing_umbrella.pop("umbrella_controls")
        with self.assertRaises(collector.EvidenceError):
            collector.validate_runtime_safety(
                json.dumps(missing_umbrella).encode(), SOURCE, DIGEST
            )
        enabled_umbrella = safety_document()
        enabled_umbrella["umbrella_controls"]["EXTERNAL_MODEL_CALLS_ENABLED"] = True
        with self.assertRaises(collector.EvidenceError):
            collector.validate_runtime_safety(
                json.dumps(enabled_umbrella).encode(), SOURCE, DIGEST
            )

    def test_runtime_safety_returns_allowlisted_projection(self):
        projected = collector.validate_runtime_safety(json.dumps(safety_document()).encode(), SOURCE, DIGEST)
        self.assertEqual(set(projected), collector.EXPECTED_RUNTIME_SAFETY_KEYS)
        self.assertEqual(set(projected["external_effects"]), collector.EXPECTED_EXTERNAL_EFFECT_KEYS)
        self.assertTrue(all(value is False for value in projected["external_effects"].values()))
        self.assertEqual(
            set(projected["umbrella_controls"]),
            collector.EXPECTED_UMBRELLA_CONTROL_KEYS,
        )
        self.assertTrue(
            all(value is False for value in projected["umbrella_controls"].values())
        )

    def test_full_get_only_evidence_collection(self):
        initial_metrics_token = token("metrics-initial")
        initial_health_token = token("health-initial")
        Handler.metrics_token = initial_metrics_token
        Handler.health_token = initial_health_token
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                metrics = root / "metrics.token"
                health = root / "health.token"
                metrics.write_text(Handler.metrics_token)
                health.write_text(Handler.health_token)
                os.chmod(metrics, 0o600)
                os.chmod(health, 0o600)
                output = root / "evidence.json"
                checksum = root / "evidence.sha256"
                target = f"127.0.0.1:{server.server_port}"
                Handler.prometheus_target = target
                rollback = root / "rollback.json"
                rollback.write_text(json.dumps(rollback_document(target)))
                def rotate_tokens(_seconds: float) -> None:
                    Handler.metrics_token = token("metrics-refreshed")
                    Handler.health_token = token("health-refreshed")
                    metrics.write_text(Handler.metrics_token)
                    health.write_text(Handler.health_token)

                old = list(__import__("sys").argv)
                __import__("sys").argv = [
                    "collector",
                    "--base-url", f"http://127.0.0.1:{server.server_port}",
                    "--prometheus-url", f"http://127.0.0.1:{server.server_port}",
                    "--metrics-token-file", str(metrics),
                    "--health-token-file", str(health),
                    "--expected-source-sha", SOURCE,
                    "--expected-image-digest", DIGEST,
                    "--rollback-proof-file", str(rollback),
                    "--output", str(output),
                    "--checksum-output", str(checksum),
                    "--scrape-delay-seconds", "300",
                ]
                try:
                    with (
                        patch.dict(
                            os.environ,
                            {
                                "HTTP_PROXY": "http://127.0.0.1:1",
                                "NO_PROXY": "",
                            },
                        ),
                        patch.object(
                            collector,
                            "configured_prometheus_target",
                            return_value=target,
                        ),
                        patch.object(
                            collector,
                            "validate_prometheus_url",
                            return_value=f"http://127.0.0.1:{server.server_port}",
                        ),
                        patch.object(
                            collector,
                            "soak_sleep",
                            side_effect=rotate_tokens,
                        ),
                        patch.object(
                            collector,
                            "monotonic_seconds",
                            side_effect=(0.0, 300.0),
                        ),
                    ):
                        self.assertEqual(collector.main(), 0)
                finally:
                    __import__("sys").argv = old
                evidence_text = output.read_text()
                evidence = json.loads(evidence_text)
                self.assertEqual(evidence["overall_result"], "PASS")
                self.assertEqual(evidence["target"]["methods_used"], ["GET"])
                self.assertNotIn(initial_metrics_token, evidence_text)
                self.assertNotIn(initial_health_token, evidence_text)
                self.assertNotIn(Handler.metrics_token, evidence_text)
                self.assertNotIn(Handler.health_token, evidence_text)
                self.assertEqual(
                    evidence["token_evidence"]["token_rotation"],
                    {
                        "metrics_refreshed_after_soak": True,
                        "health_refreshed_after_soak": True,
                    },
                )
                self.assertEqual(set(evidence["runtime_safety"]), collector.EXPECTED_RUNTIME_SAFETY_KEYS)
                self.assertTrue(checksum.read_text().startswith("sha256:"))
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
