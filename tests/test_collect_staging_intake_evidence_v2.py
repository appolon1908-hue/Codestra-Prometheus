from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import sys
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
WRAPPER_PATH = ROOT / "codestra/scripts/collect_staging_intake_evidence_v2.py"

wrapper_spec = importlib.util.spec_from_file_location("collector_v2", WRAPPER_PATH)
wrapper = importlib.util.module_from_spec(wrapper_spec)
assert wrapper_spec and wrapper_spec.loader
wrapper_spec.loader.exec_module(wrapper)
assert wrapper.collector is None
collector = wrapper.initialize_collector()

SOURCE = "9a96ff1651a324b98f3a7efd60b7a342983ded4e"
DIGEST = "sha256:01a61e6c9761968bce04db855df565e9104338c2ba2056da570cacb9fd21f0f4"


def signing_key(root: Path) -> tuple[Path, Path, str]:
    private = root / "evidence-private.pem"
    public = root / "evidence-public.pem"
    subprocess.run(
        [wrapper.OPENSSL, "genpkey", "-algorithm", "ED25519", "-out", private],
        check=True,
    )
    os.chmod(private, 0o400)
    subprocess.run(
        [wrapper.OPENSSL, "pkey", "-in", private, "-pubout", "-out", public],
        check=True,
    )
    public_der = subprocess.run(
        [wrapper.OPENSSL, "pkey", "-in", private, "-pubout", "-outform", "DER"],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    return private, public, "sha256:" + hashlib.sha256(public_der).hexdigest()


def token(scope: str, jti: str) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(
        json.dumps(
            {
                "iat": 100,
                "exp": 400,
                "azp": "monitoring-readonly",
                "aud": ["middleware-api"],
                "scope": scope,
                "jti": jti,
            }
        ).encode()
    ).decode().rstrip("=")
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
    rows.append(
        f'codestra_release_info{{service="middleware-api",component="api",environment="staging",release_sha="{SOURCE}",image_digest="{DIGEST}",schema_or_migration_head="0008_durable_communications",version="0.1.0"}} 1'
    )
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
        "dispatch": {
            "outbox_enabled": False,
            "nats_mode": "disabled",
            "temporal_worker_mode": "disabled",
        },
        "external_effects": {
            name: False for name in collector.EXPECTED_EXTERNAL_EFFECT_KEYS
        },
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
    metrics_token = token("metrics.read", "metrics")
    health_token = token("health.read", "health")
    prometheus_target = ""
    cross_scope_requests: list[str] = []

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
            if not authorization:
                self.send_response(401)
                self.end_headers()
                return
            if authorization == f"Bearer {self.health_token}":
                self.cross_scope_requests.append("health:/metrics")
                self.send_response(403)
                self.end_headers()
                return
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
            if not authorization:
                self.send_response(401)
                self.end_headers()
                return
            if authorization == f"Bearer {self.metrics_token}":
                self.cross_scope_requests.append("metrics:/v1/runtime/safety")
                self.send_response(403)
                self.end_headers()
                return
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


class ScopeIsolationCollectorTests(unittest.TestCase):
    def test_openssl_environment_disables_external_configuration(self):
        environment = wrapper.trusted_openssl_environment()
        self.assertEqual(environment["OPENSSL_CONF"], "/dev/null")
        self.assertEqual(
            environment["OPENSSL_MODULES"],
            "/nonexistent-codestra-openssl-modules",
        )
        self.assertFalse(Path(environment["OPENSSL_MODULES"]).exists())
        with patch.object(wrapper, "OPENSSL_MODULES", "/tmp"):
            with self.assertRaises(collector.EvidenceError):
                wrapper.trusted_openssl_environment()

    def test_direct_execution_refuses_before_loading_base_collector(self):
        result = subprocess.run(
            [sys.executable, str(WRAPPER_PATH)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("protected deploy_staging_runtime.py", result.stderr)

    def test_exact_scope_metadata_rejects_combined_or_wrong_scope(self):
        self.assertEqual(
            wrapper.exact_scope_metadata(token("metrics.read", "one"), "metrics.read")[
                "scopes"
            ],
            ["metrics.read"],
        )
        with self.assertRaises(collector.EvidenceError):
            wrapper.exact_scope_metadata(
                token("metrics.read health.read", "combined"), "metrics.read"
            )
        with self.assertRaises(collector.EvidenceError):
            wrapper.exact_scope_metadata(token("health.read", "wrong"), "metrics.read")

    def test_exact_evidence_bytes_rejects_checksum_race(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "evidence.json"
            original = b'{"overall_result":"PASS"}\n'
            expected = "sha256:" + hashlib.sha256(original).hexdigest()
            path.write_bytes(original)
            os.chmod(path, 0o600)
            path.write_bytes(b'{"overall_result":"FORGED_PASS"}\n')
            with patch.object(
                wrapper,
                "REQUIRED_SIGNING_OWNER_UID",
                os.geteuid(),
            ):
                with self.assertRaises(collector.EvidenceError):
                    wrapper.exact_evidence_bytes(path, expected)

    def test_full_get_only_scope_isolated_collection(self):
        initial_metrics_token = token("metrics.read", "metrics-initial")
        initial_health_token = token("health.read", "health-initial")
        Handler.metrics_token = initial_metrics_token
        Handler.health_token = initial_health_token
        Handler.cross_scope_requests = []
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
                signature = root / "evidence.sig"
                private_key, public_key, key_id = signing_key(root)
                target = f"127.0.0.1:{server.server_port}"
                Handler.prometheus_target = target
                rollback = root / "rollback.json"
                rollback.write_text(json.dumps(rollback_document(target)))
                def rotate_tokens(_seconds: float) -> None:
                    Handler.metrics_token = token(
                        "metrics.read",
                        "metrics-refreshed",
                    )
                    Handler.health_token = token(
                        "health.read",
                        "health-refreshed",
                    )
                    metrics.write_text(Handler.metrics_token)
                    health.write_text(Handler.health_token)

                old = list(sys.argv)
                sys.argv = [
                    "collector-v2",
                    "--base-url",
                    f"http://127.0.0.1:{server.server_port}",
                    "--prometheus-url",
                    f"http://127.0.0.1:{server.server_port}",
                    "--metrics-token-file",
                    str(metrics),
                    "--health-token-file",
                    str(health),
                    "--expected-source-sha",
                    SOURCE,
                    "--expected-image-digest",
                    DIGEST,
                    "--rollback-proof-file",
                    str(rollback),
                    "--output",
                    str(output),
                    "--checksum-output",
                    str(checksum),
                    "--signing-key-file",
                    str(private_key),
                    "--signature-output",
                    str(signature),
                    "--scrape-delay-seconds",
                    "300",
                ]
                try:
                    with (
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
                        patch.object(
                            wrapper,
                            "EXPECTED_SIGNING_KEY_ID",
                            key_id,
                        ),
                        patch.object(
                            wrapper,
                            "REQUIRED_SIGNING_OWNER_UID",
                            os.geteuid(),
                        ),
                        patch.object(wrapper, "EVIDENCE_OUTPUT_ROOT", root),
                        patch.object(wrapper, "SIGNING_KEY_ROOT", root),
                        patch.object(
                            wrapper,
                            "REQUIRE_ISOLATED_INTERPRETER",
                            False,
                        ),
                        patch.dict(
                            os.environ,
                            {
                                "OPENSSL_CONF": "/untrusted/openssl.cnf",
                                "OPENSSL_MODULES": "/untrusted/modules",
                            },
                        ),
                    ):
                        self.assertEqual(wrapper.main(), 0)
                finally:
                    sys.argv = old
                evidence_text = output.read_text()
                evidence = json.loads(evidence_text)
                self.assertEqual(evidence["schema_version"], "1.1")
                self.assertEqual(evidence["overall_result"], "PASS")
                self.assertEqual(
                    evidence["token_evidence"]["metrics"]["scopes"],
                    ["metrics.read"],
                )
                self.assertEqual(
                    evidence["token_evidence"]["health"]["scopes"],
                    ["health.read"],
                )
                self.assertTrue(evidence["checks"]["health_token_metrics_denied"])
                self.assertTrue(
                    evidence["checks"]["metrics_token_runtime_safety_denied"]
                )
                self.assertEqual(
                    evidence["checks"]["token_scope_isolation"], "PASS"
                )
                self.assertEqual(
                    Handler.cross_scope_requests,
                    [
                        "health:/metrics",
                        "metrics:/v1/runtime/safety",
                        "health:/metrics",
                        "metrics:/v1/runtime/safety",
                    ],
                )
                self.assertNotIn(initial_metrics_token, evidence_text)
                self.assertNotIn(initial_health_token, evidence_text)
                self.assertNotIn(Handler.metrics_token, evidence_text)
                self.assertNotIn(Handler.health_token, evidence_text)
                self.assertTrue(checksum.read_text().startswith("sha256:"))
                signature_raw = base64.b64decode(
                    signature.read_text().strip(), validate=True
                )
                signature_raw_path = root / "evidence.sig.raw"
                signature_raw_path.write_bytes(signature_raw)
                verified = subprocess.run(
                    [
                        wrapper.OPENSSL,
                        "pkeyutl",
                        "-verify",
                        "-pubin",
                        "-inkey",
                        public_key,
                        "-rawin",
                        "-in",
                        output,
                        "-sigfile",
                        signature_raw_path,
                    ],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertEqual(verified.returncode, 0)
        finally:
            server.shutdown()
            server.server_close()

    def test_target_binding_fails_before_any_token_file_is_read(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            old = list(sys.argv)
            sys.argv = [
                "collector-v2",
                "--base-url",
                "http://wrong-private-target:8080",
                "--metrics-token-file",
                str(root / "metrics.token"),
                "--health-token-file",
                str(root / "health.token"),
                "--output",
                str(root / "evidence.json"),
                "--checksum-output",
                str(root / "evidence.sha256"),
                "--signing-key-file",
                str(root / "signing-private.pem"),
                "--signature-output",
                str(root / "evidence.sig"),
            ]
            try:
                with (
                    patch.object(
                        collector,
                        "validate_configured_base_url",
                        side_effect=collector.EvidenceError(
                            "evidence base URL does not match the configured Prometheus target"
                        ),
                    ),
                    patch.object(collector, "read_private_file") as read_secret,
                    patch.object(
                        wrapper,
                        "REQUIRE_ISOLATED_INTERPRETER",
                        False,
                    ),
                ):
                    with self.assertRaises(collector.EvidenceError):
                        wrapper.main()
                    read_secret.assert_not_called()
            finally:
                sys.argv = old


if __name__ == "__main__":
    unittest.main()
