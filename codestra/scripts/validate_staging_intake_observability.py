#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CODESTRA = REPO / "codestra"
EXPECTED_SOURCE = "f6748a58f8d2590520a4f28776770957061cdea1"
EXPECTED_DIGEST = "sha256:695fa3ce3f50ba4d0ae0784976b946a0a683ca731155e4bd3bd9e90a4670b820"
STAGING_TOKEN_URL = "https://auth-staging.codestra.co/realms/codestra/protocol/openid-connect/token"
PRODUCTION_TOKEN_URL = "https://auth.codestra.co/realms/codestra/protocol/openid-connect/token"
TARGETS_PATH = CODESTRA / "prometheus/targets/staging.json"
CONTRACT_PATH = REPO / "integration/staging-activation-contract-v1.json"
EVIDENCE_REFERENCE_PATH = (
    REPO / "integration/staging-runtime-evidence-reference-v1.json"
)
EXPECTED_STAGING_RULE_FILES = {
    "/etc/prometheus/rules-staging/intake-recording-rules.yml",
    "/etc/prometheus/rules-staging/intake-alerts.yml",
    "/etc/prometheus/rules-staging/recording-rules.yml",
    "/etc/prometheus/rules-staging/security-alerts.yml",
    "/etc/prometheus/rules-staging/application-alerts.yml",
}
EVIDENCE_ARTIFACT = re.compile(r"^codestra-staging-intake-evidence-[1-9][0-9]*-[1-9][0-9]*$")


def validate_reviewed_git_evidence(contract: dict[str, object]) -> None:
    evidence = contract["reviewed_git_activation_evidence"]
    assert isinstance(evidence, dict)
    assert evidence["schema_version"] == "1.0"
    assert evidence["evidence_type"] == "REVIEWED_GIT_AUTHORITY"
    assert evidence["authority_path"] == "integration/staging-activation-contract-v1.json"
    assert evidence["middleware_source_sha"] == EXPECTED_SOURCE
    assert evidence["middleware_image_digest"] == EXPECTED_DIGEST
    assert evidence["migration"] == "0003_immutable_event_ledger"
    assert evidence["staging_identity"] == "https://auth-staging.codestra.co"
    assert evidence["production_identity_enabled"] is False
    assert evidence["external_effects_enabled"] is False
    assert evidence["blackbox_activation"] == "pending"
    assert evidence["production_activation_authorized"] is False
    assert evidence["scope"] == "SOURCE_ONLY_ACTIVATION_ELIGIBILITY_NO_RUNTIME_EFFECT"
    expected_checksum = evidence["authority_payload_sha256"]
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", expected_checksum)
    payload = {
        key: value
        for key, value in evidence.items()
        if key != "authority_payload_sha256"
    }
    actual_checksum = "sha256:" + hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert actual_checksum == expected_checksum


def parse_timestamp(value: object) -> datetime:
    assert isinstance(value, str)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    assert parsed.tzinfo is not None
    return parsed.astimezone(UTC)


def validate_staging_evidence(
    contract_evidence: dict[str, object], expected_activation: str
) -> None:
    assert contract_evidence["collector_repository"] == (
        "appolon1908-hue/Codestra-Prometheus"
    )
    assert contract_evidence["collector_branch"] == "development"
    assert contract_evidence["reference_path"] == (
        "integration/staging-runtime-evidence-reference-v1.json"
    )
    assert contract_evidence["checksum"] is None
    assert contract_evidence["state"] == "PENDING_RUNTIME_EXECUTION"
    assert {"signed_release_manifest", "sigstore_identity"}.issubset(
        set(contract_evidence["must_verify"])
    )

    reference = json.loads(EVIDENCE_REFERENCE_PATH.read_text(encoding="utf-8"))
    assert reference["schema_version"] == "1.0"
    assert reference["repository"] == "appolon1908-hue/Codestra-Prometheus"
    assert reference["environment"] == "staging"
    assert reference["source_authority"] == {
        "middleware_source_sha": EXPECTED_SOURCE,
        "middleware_image_digest": EXPECTED_DIGEST,
    }
    assert reference["production_activation_authorized"] is False
    assert reference["external_effects_enabled"] is False

    state = reference["state"]
    if state == "PENDING_RUNTIME_EXECUTION":
        assert reference["evidence_checksum"] is None
        assert reference["workflow_run_id"] is None
        assert reference["artifact_name"] is None
        assert reference["generated_at"] is None
        assert reference["expires_at"] is None
        assert reference["independent_review_complete"] is False
        assert expected_activation == "pending"
        return

    assert state == "CERTIFIED_RUNTIME_EVIDENCE"
    assert re.fullmatch(
        r"sha256:[0-9a-f]{64}", str(reference["evidence_checksum"])
    )
    assert isinstance(reference["workflow_run_id"], int)
    assert reference["workflow_run_id"] > 0
    assert EVIDENCE_ARTIFACT.fullmatch(str(reference["artifact_name"]))
    generated_at = parse_timestamp(reference["generated_at"])
    expires_at = parse_timestamp(reference["expires_at"])
    assert generated_at < expires_at
    assert datetime.now(UTC) < expires_at
    assert reference["independent_review_complete"] is True


def validate_production_target_isolation() -> None:
    primary = yaml.safe_load(
        (CODESTRA / "prometheus/prometheus.yml").read_text(encoding="utf-8")
    )
    jobs = {item["job_name"]: item for item in primary["scrape_configs"]}
    target_job = jobs["codestra-targets"]
    relabel = {
        tuple(item.get("source_labels", [])): (
            item.get("regex"),
            item.get("action"),
        )
        for item in target_job["relabel_configs"]
    }
    assert relabel[("activation",)] == ("active", "keep")
    assert relabel[("environment",)] == ("production", "keep")


def validate(expected_activation: str = "pending") -> None:
    assert expected_activation in {"pending", "active"}
    config = yaml.safe_load(
        (CODESTRA / "prometheus/prometheus-staging.yml").read_text(
            encoding="utf-8"
        )
    )
    assert set(config["rule_files"]) == EXPECTED_STAGING_RULE_FILES
    jobs = {item["job_name"]: item for item in config["scrape_configs"]}
    assert set(jobs) == {"prometheus-staging", "middleware-intake-staging"}
    job = jobs["middleware-intake-staging"]
    assert job["scheme"] == "http" and job["metrics_path"] == "/metrics"
    assert job["sample_limit"] == 5000 and job["body_size_limit"] == "8MB"
    assert job["oauth2"] == {
        "client_id": "monitoring-readonly",
        "client_secret_file": "/run/secrets/middleware-staging-monitoring-client-secret",
        "scopes": ["metrics.read"],
        "token_url": STAGING_TOKEN_URL,
    }
    assert PRODUCTION_TOKEN_URL not in json.dumps(config, sort_keys=True)
    assert job["file_sd_configs"] == [
        {
            "files": ["/etc/prometheus/targets/staging.json"],
            "refresh_interval": "30s",
        }
    ]
    assert {
        tuple(item.get("source_labels", [])): (
            item.get("regex"),
            item.get("action"),
        )
        for item in job["relabel_configs"]
    } == {
        ("activation",): ("active", "keep"),
        ("environment",): ("staging", "keep"),
        ("tenant_scope",): ("aggregate", "keep"),
    }

    targets = json.loads(TARGETS_PATH.read_text(encoding="utf-8"))
    assert len(targets) == 1
    assert targets[0]["targets"] == ["middleware-intake-staging:8080"]
    labels = targets[0]["labels"]
    assert labels["activation"] == expected_activation
    assert labels["environment"] == "staging"
    assert labels["tenant_scope"] == "aggregate"
    assert labels["service"] == "middleware-intake"
    assert labels["release_id"] == "f6748a58f8d2-695fa3ce3f50"

    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    authority = contract["middleware_source_authority"]
    assert authority["source_sha"] == EXPECTED_SOURCE
    assert authority["immutable_image_digest"] == EXPECTED_DIGEST
    validate_staging_evidence(contract["staging_evidence"], expected_activation)
    assert (
        contract["activation_policy"]["prometheus_target_current_state"]
        == "pending"
    )
    assert (
        contract["activation_policy"]["blackbox_target_current_state"]
        == "pending"
    )
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", EXPECTED_DIGEST)
    validate_reviewed_git_evidence(contract)
    validate_production_target_isolation()

    collector = (
        CODESTRA / "scripts/collect_staging_intake_evidence.py"
    ).read_text(encoding="utf-8")
    wrapper = (
        CODESTRA / "scripts/collect_staging_intake_evidence_v2.py"
    ).read_text(encoding="utf-8")
    for required in (
        "unauthenticated /metrics",
        "wrong-token /metrics",
        "all_external_effects_disabled",
        "umbrella_controls",
        "EXPECTED_UMBRELLA_CONTROL_KEYS",
        "staging_safe",
        "EVIDENCE_SHA256",
    ):
        assert required in collector
    for required in (
        'METRICS_SCOPE = "metrics.read"',
        'HEALTH_SCOPE = "health.read"',
        "health.read token /metrics",
        "metrics.read token /v1/runtime/safety",
        '"token_scope_isolation": "PASS"',
        'evidence["schema_version"] = "1.1"',
    ):
        assert required in wrapper, required

    workflow = (
        REPO / ".github/workflows/stage6-intake-observability.yml"
    ).read_text(encoding="utf-8")
    assert "collect_staging_intake_evidence_v2.py" in workflow
    assert "test_collect_staging_intake_evidence*.py" in workflow
    assert "staging-runtime-evidence-reference-v1.json" in workflow
    assert (
        "github.event.pull_request.base.sha || github.event.before" in workflow
    )


def main() -> None:
    validate("pending")
    print("PROMETHEUS_SOURCE_GATE=PASS")
    print("BLACKBOX_ACTIVATION_GATE=NOT_YET_REQUIRED")


if __name__ == "__main__":
    main()
