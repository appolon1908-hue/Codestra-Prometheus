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

MODULE_PATH = Path(__file__).parents[1] / "codestra/scripts/collect_staging_intake_evidence.py"
spec = importlib.util.spec_from_file_location("collector", MODULE_PATH)
collector = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(collector)

SOURCE = "f6748a58f8d2590520a4f28776770957061cdea1"
DIGEST = "sha256:695fa3ce3f50ba4d0ae0784976b946a0a683ca731155e4bd3bd9e90a4670b820"


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
    rows.append('intake_inbox_backlog{codestra_business="platform",application="integration",service="middleware-api",environment="staging"} 0')
    return ("\n".join(rows) + "\n").encode()


SAFETY = json.dumps({
    "environment": "staging",
    "runtime_profile_id": "codestra-middleware-staging-intake-observability-v1",
    "release": {"source_sha": SOURCE, "image_digest": DIGEST, "schema_head": "0003_immutable_event_ledger"},
    "persistence": {"in_memory": False},
    "dispatch": {"outbox_enabled": False, "nats_mode": "disabled", "temporal_worker_mode": "disabled"},
    "external_effects": {"LIVE_WRITE": False, "ODOO_WRITE": False, "SEND_EVENTS": False},
    "production_dialing": "DISABLED",
    "production_activation_configured": False,
    "provider_effects_disabled": True,
    "all_external_effects_disabled": True,
    "staging_safe": True,
}).encode()


class Handler(BaseHTTPRequestHandler):
    metrics_token = token("metrics")
    health_token = token("health")

    def log_message(self, *_args):
        pass

    def do_GET(self):
        authorization = self.headers.get("Authorization", "")
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
            self.wfile.write(SAFETY)
            return
        self.send_response(404)
        self.end_headers()


class CollectorTests(unittest.TestCase):
    def test_metric_contract_and_privacy(self):
        result = collector.analyze_metrics(metrics_payload(), max_series=5000, max_family_series=500)
        self.assertEqual(result["missing_metric_families"], [])
        bad = metrics_payload() + b'intake_inbox_backlog{codestra_business="platform",application="integration",service="middleware-api",environment="staging",customer_id="123"} 1\n'
        with self.assertRaises(collector.EvidenceError):
            collector.analyze_metrics(bad, max_series=5000, max_family_series=500)

    def test_full_get_only_evidence_collection(self):
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
                old = list(__import__("sys").argv)
                __import__("sys").argv = [
                    "collector",
                    "--base-url", f"http://127.0.0.1:{server.server_port}",
                    "--metrics-token-file", str(metrics),
                    "--health-token-file", str(health),
                    "--expected-source-sha", SOURCE,
                    "--expected-image-digest", DIGEST,
                    "--output", str(output),
                    "--checksum-output", str(checksum),
                    "--scrape-delay-seconds", "0",
                ]
                try:
                    self.assertEqual(collector.main(), 0)
                finally:
                    __import__("sys").argv = old
                evidence = json.loads(output.read_text())
                self.assertEqual(evidence["overall_result"], "PASS")
                self.assertEqual(evidence["target"]["methods_used"], ["GET"])
                self.assertNotIn(Handler.metrics_token, output.read_text())
                self.assertTrue(checksum.read_text().startswith("sha256:"))
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
