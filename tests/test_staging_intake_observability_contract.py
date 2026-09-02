from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "codestra/scripts"
sys.path.insert(0, str(SCRIPTS))

import validate_staging_intake_observability as source
import validate_staging_intake_observability_activation as activation
import validate_staging_intake_observability_contract as router


def runtime_evidence() -> dict[str, object]:
    scrape = {
        "payload_sha256": "sha256:" + "3" * 64,
        "payload_bytes": 1024,
        "series_count": 100,
        "family_count": len(source.EXPECTED_METRIC_FAMILIES),
        "intake_sample_count": 20,
        "maximum_family_series": 10,
        "required_metric_families": sorted(
            source.EXPECTED_METRIC_FAMILIES
        ),
        "missing_metric_families": [],
        "privacy_findings": [],
    }
    return {
        "schema_version": "1.1",
        "suite_id": "codestra-controlled-intake-monitoring-v1",
        "evidence_type": "private-staging-runtime-certification",
        "generated_at": "2026-09-02T00:00:00+00:00",
        "environment": "staging",
        "target": {
            "hostname": "middleware-intake-staging",
            "prometheus_target": "middleware-intake-staging:8080",
            "private_network_only": True,
            "methods_used": ["GET"],
            "business_writes_performed": False,
        },
        "middleware_release": {
            "source_sha": source.EXPECTED_SOURCE,
            "image_digest": source.EXPECTED_DIGEST,
            "schema_head": "0008_durable_communications",
        },
        "supply_chain": {
            "release_manifest_verification": "PASS_IN_SIGNED_RELEASE_WORKFLOW",
            "signed_release_artifact_sha256": "sha256:56fc7bd5cca57df0bfd04e27eb3e294bd160a8071e4e8ae1974addb6d040f46e",
            "release_workflow_identity": "https://github.com/appolon1908-hue/Middleware-/.github/workflows/release.yml@refs/heads/main",
            "release_oidc_issuer": "https://token.actions.githubusercontent.com",
            "image_signature": "sigstore-keyless",
            "manifest_signature": "sigstore-keyless-bundle",
            "transparency_log_required": True,
        },
        "token_evidence": {
            "metrics": {
                "client_id": "monitoring-readonly",
                "ttl_seconds": 300,
                "scopes": ["metrics.read"],
                "audience": "middleware-api",
                "token_sha256": "sha256:" + "1" * 64,
            },
            "health": {
                "client_id": "monitoring-readonly",
                "ttl_seconds": 300,
                "scopes": ["health.read"],
                "audience": "middleware-api",
                "token_sha256": "sha256:" + "2" * 64,
            },
            "token_values_recorded": False,
            "storage": "ephemeral-files-outside-git",
            "token_rotation": {
                "metrics_refreshed_after_soak": True,
                "health_refreshed_after_soak": True,
            },
            "scope_isolation": {
                "metrics_token_exact_scope": "metrics.read",
                "health_token_exact_scope": "health.read",
                "cross_scope_access_denied": True,
            },
        },
        "checks": {
            "unauthenticated_metrics_denied": True,
            "wrong_token_metrics_denied": True,
            "authenticated_metrics_scrapes": 2,
            "runtime_safety": "PASS",
            "token_scope_isolation": "PASS",
            "health_token_metrics_denied": True,
            "metrics_token_runtime_safety_denied": True,
            "prometheus_target_up": True,
            "prometheus_scrape_http_200": True,
        },
        "metrics": {
            "scrapes": [scrape, scrape],
            "cardinality_budget": {
                "maximum_total_series": 5000,
                "maximum_series_per_family": 500,
            },
            "forbidden_label_findings": [],
            "pii_or_secret_findings": [],
        },
        "operational_proofs": {
            "staging_soak": {
                "minimum_seconds": 300,
                "observed_seconds": 300.0,
                "authenticated_scrapes": 2,
                "failed_scrapes": 0,
                "result": "PASS",
            },
            "rollback": {
                "schema_version": "1.0",
                "evidence_type": "prometheus-staging-rollback-proof",
                "performed_at": "2026-09-02T00:00:00+00:00",
                "environment": "staging",
                "prometheus_target": "middleware-intake-staging:8080",
                "middleware_source_sha": source.EXPECTED_SOURCE,
                "middleware_image_digest": source.EXPECTED_DIGEST,
                "prometheus_only": True,
                "restored_health": True,
                "production_changed": False,
                "external_effects_triggered": False,
                "klyrow_changed": False,
                "postal_changed": False,
                "result": "PASS",
                "artifact_sha256": "sha256:" + "4" * 64,
            },
        },
        "prometheus_scrape": {
            "prometheus_authority": "prometheus-staging:9090",
            "prometheus_target": "middleware-intake-staging:8080",
            "scrape_job": "middleware-intake-staging-readiness",
            "target_health": "up",
            "up_value": 1,
            "last_error_empty": True,
            "targets_api_http_status": 200,
            "query_api_http_status": 200,
            "scrape_http_status": 200,
        },
        "runtime_safety": {
            "schema_version": "1.1",
            "service": "middleware-api",
            "environment": "staging",
            "runtime_profile_id": "codestra-middleware-staging-v1",
            "release": {
                "source_sha": source.EXPECTED_SOURCE,
                "image_digest": source.EXPECTED_DIGEST,
                "schema_head": "0008_durable_communications",
                "build_time": "2026-09-02T00:00:00Z",
            },
            "persistence": {"in_memory": False},
            "dispatch": {
                "outbox_enabled": False,
                "nats_mode": "disabled",
                "temporal_worker_mode": "disabled",
            },
            "umbrella_controls": {
                "LIVE_ADVERTISING_ENABLED": False,
                "EXTERNAL_DELIVERY_ENABLED": False,
                "SOCIAL_PUBLISHING_ENABLED": False,
                "EXTERNAL_MODEL_CALLS_ENABLED": False,
                "N8N_EXTERNAL_PROVIDER_WRITES": False,
            },
            "external_effects": {
                key: False
                for key in sorted(
                    source.EXPECTED_EXTERNAL_EFFECT_KEYS
                )
            },
            "production_dialing": "DISABLED",
            "production_activation_configured": False,
            "provider_effects_disabled": True,
            "all_external_effects_disabled": True,
            "staging_safe": True,
        },
        "activation": {
            "prometheus_target_state": "pending",
            "blackbox_target_state": "pending",
            "production_authorized": False,
        },
        "overall_result": "PASS",
    }


def activate_contract(contract: dict[str, object], evidence_checksum: str) -> None:
    contract["staging_evidence"].update(
        {
            "artifact_path": "integration/staging-runtime-evidence-v1.json",
            "checksum": evidence_checksum,
            "signature_path": "integration/staging-runtime-evidence-v1.sig",
            "state": "VERIFIED_RUNTIME_EVIDENCE",
        }
    )
    contract["activation_policy"]["prometheus_target_current_state"] = "active"
    contract["activation_policy"]["prometheus_target_allowed_next_state"] = None
    for key in (
        "deployment_performed",
        "prometheus_target_activated",
        "tokens_provisioned",
        "staging_evidence_collected",
    ):
        contract["runtime_effects"][key] = True


class StagingIntakeActivationContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_paths = (
            source.TARGETS_PATH,
            source.CONTRACT_PATH,
            source.EVIDENCE_PATH,
            source.EVIDENCE_SIGNATURE_PATH,
            source.EVIDENCE_PUBLIC_KEY_PATH,
            source.PROMETHEUS_CONFIG_PATH,
            source.PRIMARY_PROMETHEUS_CONFIG_PATH,
        )
        self.original_signing_key_id = source.EXPECTED_EVIDENCE_SIGNING_KEY_ID

    def tearDown(self) -> None:
        (
            source.TARGETS_PATH,
            source.CONTRACT_PATH,
            source.EVIDENCE_PATH,
            source.EVIDENCE_SIGNATURE_PATH,
            source.EVIDENCE_PUBLIC_KEY_PATH,
            source.PROMETHEUS_CONFIG_PATH,
            source.PRIMARY_PROMETHEUS_CONFIG_PATH,
        ) = self.original_paths
        source.EXPECTED_EVIDENCE_SIGNING_KEY_ID = self.original_signing_key_id

    def prepare_active_fixture(
        self,
        root: Path,
        *,
        write_evidence: bool,
        write_signature: bool = True,
        evidence_document: dict[str, object] | None = None,
    ) -> None:
        targets = json.loads(self.original_paths[0].read_text())
        targets[0]["labels"]["activation"] = "active"
        target_path = root / "staging.json"
        target_path.write_text(json.dumps(targets))

        evidence_path = root / "staging-runtime-evidence-v1.json"
        encoded = (
            json.dumps(
                evidence_document or runtime_evidence(),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
        contract = json.loads(self.original_paths[1].read_text())
        activate_contract(
            contract, "sha256:" + hashlib.sha256(encoded).hexdigest()
        )
        contract_path = root / "staging-activation-contract-v1.json"
        signature_path = root / "staging-runtime-evidence-v1.sig"
        public_key_path = root / "staging-evidence-signing-public.pem"
        private_key_path = root / "staging-evidence-signing-private.pem"
        subprocess.run(
            [
                source.OPENSSL,
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                private_key_path,
            ],
            check=True,
        )
        subprocess.run(
            [
                source.OPENSSL,
                "pkey",
                "-in",
                private_key_path,
                "-pubout",
                "-out",
                public_key_path,
            ],
            check=True,
        )
        public_der = subprocess.run(
            [
                source.OPENSSL,
                "pkey",
                "-in",
                private_key_path,
                "-pubout",
                "-outform",
                "DER",
            ],
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        signing_key_id = "sha256:" + hashlib.sha256(public_der).hexdigest()
        contract["staging_evidence"]["signing_key_id"] = signing_key_id
        contract_path.write_text(json.dumps(contract))
        signing_input = evidence_path if write_evidence else root / "evidence-to-sign.json"
        if write_evidence:
            evidence_path.write_bytes(encoded)
        else:
            signing_input.write_bytes(encoded)
        signature_raw_path = root / "staging-runtime-evidence-v1.sig.raw"
        subprocess.run(
            [
                source.OPENSSL,
                "pkeyutl",
                "-sign",
                "-inkey",
                private_key_path,
                "-rawin",
                "-in",
                signing_input,
                "-out",
                signature_raw_path,
            ],
            check=True,
        )
        if write_signature:
            signature_path.write_text(
                base64.b64encode(signature_raw_path.read_bytes()).decode("ascii")
                + "\n"
            )

        source.TARGETS_PATH = target_path
        source.CONTRACT_PATH = contract_path
        source.EVIDENCE_PATH = evidence_path
        source.EVIDENCE_SIGNATURE_PATH = signature_path
        source.EVIDENCE_PUBLIC_KEY_PATH = public_key_path
        source.EXPECTED_EVIDENCE_SIGNING_KEY_ID = signing_key_id

    def test_pending_source_state_passes_without_runtime_evidence(self) -> None:
        source.validate("pending")

    def test_pending_source_rejects_weakened_metric_labeldrop_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "prometheus-staging.yml"
            config = yaml.safe_load(self.original_paths[5].read_text())
            jobs = {item["job_name"]: item for item in config["scrape_configs"]}
            jobs["middleware-intake-staging-readiness"]["metric_relabel_configs"] = []
            path.write_text(yaml.safe_dump(config, sort_keys=False))
            source.PROMETHEUS_CONFIG_PATH = path
            with self.assertRaises(AssertionError):
                source.validate("pending")

    def test_pending_source_rejects_primary_staging_scrape_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "prometheus.yml"
            config = yaml.safe_load(self.original_paths[6].read_text())
            jobs = {item["job_name"]: item for item in config["scrape_configs"]}
            jobs["codestra-targets"]["relabel_configs"] = [
                item
                for item in jobs["codestra-targets"]["relabel_configs"]
                if item.get("action") != "drop"
            ]
            path.write_text(yaml.safe_dump(config, sort_keys=False))
            source.PRIMARY_PROMETHEUS_CONFIG_PATH = path
            with self.assertRaises(AssertionError):
                source.validate("pending")

    def test_pending_source_rejects_staging_target_label_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "staging.json"
            targets = json.loads(self.original_paths[0].read_text())
            targets[0]["labels"]["region"] = "unreviewed-region"
            path.write_text(json.dumps(targets))
            source.TARGETS_PATH = path
            with self.assertRaises(AssertionError):
                source.validate("pending")

    def test_active_state_rejects_missing_runtime_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.prepare_active_fixture(Path(directory), write_evidence=False)
            with self.assertRaises(AssertionError):
                source.validate("active")

    def test_verified_active_state_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.prepare_active_fixture(Path(directory), write_evidence=True)
            source.validate("active")
            activation.validate()

    def test_active_state_rejects_missing_host_signature(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.prepare_active_fixture(
                Path(directory),
                write_evidence=True,
                write_signature=False,
            )
            with self.assertRaises(AssertionError):
                source.validate("active")

    def test_active_state_rejects_self_consistent_unsigned_forgery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.prepare_active_fixture(root, write_evidence=True)
            forged = runtime_evidence()
            forged["generated_at"] = "2026-09-02T01:00:00+00:00"
            encoded = (
                json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode()
            source.EVIDENCE_PATH.write_bytes(encoded)
            contract = json.loads(source.CONTRACT_PATH.read_text())
            contract["staging_evidence"]["checksum"] = (
                "sha256:" + hashlib.sha256(encoded).hexdigest()
            )
            source.CONTRACT_PATH.write_text(json.dumps(contract))
            with self.assertRaises(AssertionError):
                source.validate("active")

    def test_active_state_rejects_incomplete_auth_checks(self) -> None:
        evidence = runtime_evidence()
        evidence["checks"].pop("unauthenticated_metrics_denied")
        with tempfile.TemporaryDirectory() as directory:
            self.prepare_active_fixture(
                Path(directory),
                write_evidence=True,
                evidence_document=evidence,
            )
            with self.assertRaises(AssertionError):
                source.validate("active")

    def test_active_state_rejects_evidence_from_another_private_target(self) -> None:
        evidence = runtime_evidence()
        evidence["target"]["prometheus_target"] = "127.0.0.1:8080"
        with tempfile.TemporaryDirectory() as directory:
            self.prepare_active_fixture(
                Path(directory),
                write_evidence=True,
                evidence_document=evidence,
            )
            with self.assertRaises(AssertionError):
                source.validate("active")

    def test_active_state_rejects_short_soak(self) -> None:
        evidence = runtime_evidence()
        evidence["operational_proofs"]["staging_soak"]["observed_seconds"] = 299.9
        with tempfile.TemporaryDirectory() as directory:
            self.prepare_active_fixture(
                Path(directory),
                write_evidence=True,
                evidence_document=evidence,
            )
            with self.assertRaises(AssertionError):
                source.validate("active")

    def test_router_does_not_replay_activation_for_active_base(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.prepare_active_fixture(Path(directory), write_evidence=True)
            with (
                patch.object(router.activation, "validate") as validate,
                patch.object(
                    router.activation, "target_state_at", return_value="active"
                ),
                patch.object(router.activation, "validate_activation_diff") as diff,
                patch.dict(
                    os.environ,
                    {
                        "ACTIVATION_BASE_SHA": "a" * 40,
                        "GITHUB_EVENT_NAME": "pull_request",
                    },
                ),
            ):
                router.main()
            validate.assert_called_once_with()
            diff.assert_not_called()

    def test_router_validates_one_time_pending_to_active_transition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.prepare_active_fixture(Path(directory), write_evidence=True)
            with (
                patch.object(router.activation, "validate") as validate,
                patch.object(
                    router.activation, "target_state_at", return_value="pending"
                ),
                patch.object(router.activation, "validate_activation_diff") as diff,
                patch.dict(
                    os.environ,
                    {
                        "ACTIVATION_BASE_SHA": "b" * 40,
                        "GITHUB_EVENT_NAME": "pull_request",
                    },
                ),
            ):
                router.main()
            validate.assert_called_once_with()
            diff.assert_called_once_with("b" * 40)


if __name__ == "__main__":
    unittest.main()
