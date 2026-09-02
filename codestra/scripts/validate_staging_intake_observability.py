#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CODESTRA = REPO / "codestra"
EXPECTED_SOURCE = "9a96ff1651a324b98f3a7efd60b7a342983ded4e"
EXPECTED_DIGEST = "sha256:01a61e6c9761968bce04db855df565e9104338c2ba2056da570cacb9fd21f0f4"
STAGING_TOKEN_URL = "https://auth-staging.codestra.co/realms/codestra/protocol/openid-connect/token"
PRODUCTION_TOKEN_URL = "https://auth.codestra.co/realms/codestra/protocol/openid-connect/token"
TARGETS_PATH = CODESTRA / "prometheus/targets/staging.json"
CONTRACT_PATH = REPO / "integration/staging-activation-contract-v1.json"
EVIDENCE_PATH = REPO / "integration/staging-runtime-evidence-v1.json"
PROMETHEUS_CONFIG_PATH = CODESTRA / "prometheus/prometheus-staging.yml"
PRIMARY_PROMETHEUS_CONFIG_PATH = CODESTRA / "prometheus/prometheus.yml"
EXPECTED_METRIC_LABELDROP_REGEX = (
    "(?i)^(tenant_id|tenant_name|organization_id|organization_name|customer_id|"
    "customer_name|account_id|user_id|user_name|email|phone|consumer|workspace|"
    "token|secret|password|session_id|request_id|correlation_id|trace_id|span_id|"
    "lead_id|order_id|message_id|workflow_id|execution_id|webhook_id|"
    "idempotency_key|raw_path|uri|url|query|query_string|client_address|"
    "network_peer_address|db_statement|http_target|http_url|url_full|"
    "service_instance_id|host_id|container_id|image_id|process_pid|pod_uid|"
    "exception_message|id)$"
)
EXPECTED_METRIC_FAMILIES = {
    "codestra_http_requests",
    "codestra_http_request_duration_seconds",
    "codestra_http_active_requests",
    "codestra_auth_denials",
    "codestra_readiness",
    "codestra_release_info",
    "codestra_start_time_seconds",
    "lead_submissions",
    "lead_duplicates",
    "lead_validation_failures",
    "lead_processing_duration_seconds",
    "lead_odoo_delivery",
    "lead_odoo_delivery_failures",
    "survey_responses",
    "survey_validation_failures",
    "survey_processing_duration_seconds",
    "intake_inbox_backlog",
    "intake_outbox_backlog",
    "intake_oldest_pending_seconds",
    "intake_backlog_collection_success",
    "intake_rate_limit_rejections",
    "intake_spam_rejections",
}
EXPECTED_EXTERNAL_EFFECT_KEYS = {
    "SEND_EVENTS",
    "ENABLE_EXTERNAL_DELIVERY",
    "LIVE_WRITE",
    "LIVE_WRITES",
    "ODOO_WRITE",
    "CALLBACK_DISPATCH",
    "N8N_DELIVERY_ENABLED",
    "VICIDIAL_WRITES_ENABLED",
    "EXTERNAL_DIAL_ENABLED",
    "PRODUCTION_CALLBACKS_ENABLED",
    "N8N_PRODUCTION_WORKFLOWS_ENABLED",
    "FORM_ODOO_DELIVERY_ENABLED",
    "CRAWLER_ODOO_DELIVERY_ENABLED",
    "SCRAPPER_ODOO_DELIVERY_ENABLED",
    "CRAWLER_EXTERNAL_CONTACT_ENABLED",
    "SCRAPPER_EXTERNAL_CONTACT_ENABLED",
    "SMS_DELIVERY_ENABLED",
    "EMAIL_DELIVERY_ENABLED",
    "SOCIAL_DELIVERY_ENABLED",
    "CRAWLER_EXECUTION_ENABLED",
    "SCRAPPER_EXECUTION_ENABLED",
    "LIVE_SMS_DELIVERY",
    "LIVE_EMAIL_DELIVERY",
    "UNRESTRICTED_CRAWLING",
}
EXPECTED_UMBRELLA_CONTROL_KEYS = {
    "LIVE_ADVERTISING_ENABLED",
    "EXTERNAL_DELIVERY_ENABLED",
    "SOCIAL_PUBLISHING_ENABLED",
    "EXTERNAL_MODEL_CALLS_ENABLED",
    "N8N_EXTERNAL_PROVIDER_WRITES",
}
EXPECTED_RUNTIME_SAFETY_KEYS = {
    "schema_version",
    "service",
    "environment",
    "runtime_profile_id",
    "release",
    "persistence",
    "dispatch",
    "external_effects",
    "umbrella_controls",
    "production_dialing",
    "production_activation_configured",
    "provider_effects_disabled",
    "all_external_effects_disabled",
    "staging_safe",
}
EXPECTED_MUST_VERIFY = {
    "exact_middleware_source_sha",
    "immutable_image_digest",
    "signed_release_manifest",
    "sigstore_identity",
    "private_network_only",
    "metrics_read_scope",
    "health_read_scope",
    "unauthorized_request_denied",
    "wrong_token_denied",
    "complete_metric_catalogue",
    "bounded_cardinality",
    "no_pii_or_secret_exposure",
    "all_external_effects_disabled",
    "staging_soak",
    "rollback_proof",
}


def validate_runtime_evidence(contract: dict[str, object]) -> None:
    evidence_control = contract["staging_evidence"]
    assert isinstance(evidence_control, dict)
    assert evidence_control["state"] == "VERIFIED_RUNTIME_EVIDENCE"
    assert evidence_control["artifact_path"] == (
        "integration/staging-runtime-evidence-v1.json"
    )
    expected_checksum = evidence_control["checksum"]
    assert isinstance(expected_checksum, str)
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", expected_checksum)
    assert EVIDENCE_PATH.is_file() and not EVIDENCE_PATH.is_symlink()
    assert EVIDENCE_PATH.parent.resolve() == CONTRACT_PATH.parent.resolve()
    assert EVIDENCE_PATH.resolve().is_relative_to(CONTRACT_PATH.parent.resolve())
    encoded = EVIDENCE_PATH.read_bytes()
    assert hashlib.sha256(encoded).hexdigest() == expected_checksum.removeprefix(
        "sha256:"
    )
    evidence = json.loads(encoded)
    assert set(evidence) == {
        "schema_version",
        "suite_id",
        "evidence_type",
        "generated_at",
        "environment",
        "target",
        "middleware_release",
        "supply_chain",
        "token_evidence",
        "checks",
        "metrics",
        "operational_proofs",
        "prometheus_scrape",
        "runtime_safety",
        "activation",
        "overall_result",
    }
    assert evidence["schema_version"] == "1.1"
    assert evidence["suite_id"] == "codestra-controlled-intake-monitoring-v1"
    assert evidence["evidence_type"] == "private-staging-runtime-certification"
    assert evidence["environment"] == "staging"
    assert evidence["overall_result"] == "PASS"
    configured_targets = json.loads(TARGETS_PATH.read_text(encoding="utf-8"))
    configured_target = configured_targets[0]["targets"][0]
    assert configured_target == "middleware-intake-staging:8080"
    assert evidence["target"]["hostname"] == "middleware-intake-staging"
    assert evidence["target"]["prometheus_target"] == configured_target
    assert evidence["target"]["private_network_only"] is True
    assert evidence["target"]["methods_used"] == ["GET"]
    assert evidence["target"]["business_writes_performed"] is False
    assert evidence["middleware_release"]["source_sha"] == EXPECTED_SOURCE
    assert evidence["middleware_release"]["image_digest"] == EXPECTED_DIGEST
    authority = contract["middleware_source_authority"]
    supply_chain = evidence["supply_chain"]
    assert supply_chain == {
        "release_manifest_verification": authority[
            "release_manifest_verification"
        ],
        "signed_release_artifact_sha256": authority[
            "signed_release_artifact_sha256"
        ],
        "release_workflow_identity": authority["release_workflow_identity"],
        "release_oidc_issuer": authority["release_oidc_issuer"],
        "image_signature": authority["image_signature"],
        "manifest_signature": authority["manifest_signature"],
        "transparency_log_required": True,
    }
    tokens = evidence["token_evidence"]
    assert tokens["token_values_recorded"] is False
    assert tokens["storage"] == "ephemeral-files-outside-git"
    for name, scope in (("metrics", "metrics.read"), ("health", "health.read")):
        metadata = tokens[name]
        assert metadata["client_id"] == "monitoring-readonly"
        assert metadata["audience"] == "middleware-api"
        assert metadata["scopes"] == [scope]
        assert isinstance(metadata["ttl_seconds"], int)
        assert 60 <= metadata["ttl_seconds"] <= 300
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", metadata["token_sha256"])
    assert tokens["metrics"]["token_sha256"] != tokens["health"]["token_sha256"]
    assert tokens["token_rotation"] == {
        "metrics_refreshed_after_soak": True,
        "health_refreshed_after_soak": True,
    }
    assert tokens["scope_isolation"] == {
        "metrics_token_exact_scope": "metrics.read",
        "health_token_exact_scope": "health.read",
        "cross_scope_access_denied": True,
    }
    checks = evidence["checks"]
    assert set(checks) == {
        "unauthenticated_metrics_denied",
        "wrong_token_metrics_denied",
        "authenticated_metrics_scrapes",
        "runtime_safety",
        "token_scope_isolation",
        "health_token_metrics_denied",
        "metrics_token_runtime_safety_denied",
        "prometheus_target_up",
        "prometheus_scrape_http_200",
    }
    assert checks["unauthenticated_metrics_denied"] is True
    assert checks["wrong_token_metrics_denied"] is True
    assert checks["prometheus_target_up"] is True
    assert checks["prometheus_scrape_http_200"] is True
    assert checks["authenticated_metrics_scrapes"] == 2
    assert checks["runtime_safety"] == "PASS"
    assert checks["token_scope_isolation"] == "PASS"
    assert checks["health_token_metrics_denied"] is True
    assert checks["metrics_token_runtime_safety_denied"] is True
    metrics = evidence["metrics"]
    assert metrics["forbidden_label_findings"] == []
    assert metrics["pii_or_secret_findings"] == []
    assert len(metrics["scrapes"]) == 2
    for scrape in metrics["scrapes"]:
        assert set(scrape) == {
            "payload_sha256",
            "payload_bytes",
            "series_count",
            "family_count",
            "intake_sample_count",
            "maximum_family_series",
            "required_metric_families",
            "missing_metric_families",
            "privacy_findings",
        }
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", scrape["payload_sha256"])
        assert 0 < scrape["payload_bytes"] <= 8 * 1024 * 1024
        assert 0 < scrape["series_count"] <= metrics["cardinality_budget"]["maximum_total_series"]
        assert scrape["maximum_family_series"] <= metrics["cardinality_budget"]["maximum_series_per_family"]
        assert scrape["required_metric_families"] == sorted(EXPECTED_METRIC_FAMILIES)
        assert scrape["missing_metric_families"] == []
        assert scrape["privacy_findings"] == []
    operational = evidence["operational_proofs"]
    assert set(operational) == {"staging_soak", "rollback"}
    assert operational["staging_soak"] == {
        "minimum_seconds": 300,
        "observed_seconds": operational["staging_soak"]["observed_seconds"],
        "authenticated_scrapes": 2,
        "failed_scrapes": 0,
        "result": "PASS",
    }
    assert isinstance(operational["staging_soak"]["observed_seconds"], (int, float))
    assert operational["staging_soak"]["observed_seconds"] >= 300
    rollback = operational["rollback"]
    assert set(rollback) == {
        "schema_version",
        "evidence_type",
        "performed_at",
        "environment",
        "prometheus_target",
        "middleware_source_sha",
        "middleware_image_digest",
        "prometheus_only",
        "restored_health",
        "production_changed",
        "external_effects_triggered",
        "klyrow_changed",
        "postal_changed",
        "result",
        "artifact_sha256",
    }
    assert rollback["schema_version"] == "1.0"
    assert rollback["evidence_type"] == "prometheus-staging-rollback-proof"
    assert isinstance(rollback["performed_at"], str) and rollback["performed_at"].strip()
    assert rollback["environment"] == "staging"
    assert rollback["prometheus_target"] == configured_target
    assert rollback["middleware_source_sha"] == EXPECTED_SOURCE
    assert rollback["middleware_image_digest"] == EXPECTED_DIGEST
    assert rollback["prometheus_only"] is True
    assert rollback["restored_health"] is True
    assert rollback["production_changed"] is False
    assert rollback["external_effects_triggered"] is False
    assert rollback["klyrow_changed"] is False
    assert rollback["postal_changed"] is False
    assert rollback["result"] == "PASS"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", rollback["artifact_sha256"])
    assert evidence["prometheus_scrape"] == {
        "prometheus_authority": "prometheus-staging:9090",
        "prometheus_target": configured_target,
        "scrape_job": "middleware-intake-staging-readiness",
        "target_health": "up",
        "up_value": 1,
        "last_error_empty": True,
        "targets_api_http_status": 200,
        "query_api_http_status": 200,
        "scrape_http_status": 200,
    }
    safety = evidence["runtime_safety"]
    assert set(safety) == EXPECTED_RUNTIME_SAFETY_KEYS
    assert safety["schema_version"] == "1.1"
    assert safety["service"] == "middleware-api"
    assert safety["environment"] == "staging"
    assert safety["runtime_profile_id"] == "codestra-middleware-staging-v1"
    assert safety["release"]["source_sha"] == EXPECTED_SOURCE
    assert safety["release"]["image_digest"] == EXPECTED_DIGEST
    assert safety["release"]["schema_head"] == "0008_durable_communications"
    assert isinstance(safety["release"]["build_time"], str)
    assert safety["release"]["build_time"].strip()
    assert safety["persistence"] == {"in_memory": False}
    assert safety["dispatch"] == {
        "outbox_enabled": False,
        "nats_mode": "disabled",
        "temporal_worker_mode": "disabled",
    }
    assert set(safety["external_effects"]) == EXPECTED_EXTERNAL_EFFECT_KEYS
    assert all(value is False for value in safety["external_effects"].values())
    assert set(safety["umbrella_controls"]) == EXPECTED_UMBRELLA_CONTROL_KEYS
    assert all(value is False for value in safety["umbrella_controls"].values())
    assert safety["production_dialing"] == "DISABLED"
    assert safety["production_activation_configured"] is False
    assert safety["provider_effects_disabled"] is True
    assert safety["all_external_effects_disabled"] is True
    assert safety["staging_safe"] is True
    assert evidence["activation"] == {
        "prometheus_target_state": "pending",
        "blackbox_target_state": "pending",
        "production_authorized": False,
    }


def validate_reviewed_git_evidence(contract: dict[str, object]) -> None:
    evidence = contract["reviewed_git_activation_evidence"]
    assert isinstance(evidence, dict)
    assert evidence["schema_version"] == "1.0"
    assert evidence["evidence_type"] == "REVIEWED_GIT_AUTHORITY"
    assert evidence["authority_path"] == "integration/staging-activation-contract-v1.json"
    assert evidence["middleware_source_sha"] == EXPECTED_SOURCE
    assert evidence["middleware_image_digest"] == EXPECTED_DIGEST
    assert evidence["migration"] == "0008_durable_communications"
    assert evidence["staging_identity"] == "https://auth-staging.codestra.co"
    assert evidence["production_identity_enabled"] is False
    assert evidence["external_effects_enabled"] is False
    assert evidence["blackbox_activation"] == "pending"
    assert evidence["production_activation_authorized"] is False
    assert evidence["scope"] == "SOURCE_ONLY_ACTIVATION_ELIGIBILITY_NO_RUNTIME_EFFECT"
    expected_checksum = evidence["authority_payload_sha256"]
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", expected_checksum)
    payload = {key: value for key, value in evidence.items() if key != "authority_payload_sha256"}
    actual_checksum = "sha256:" + hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert actual_checksum == expected_checksum


def validate(expected_activation: str = "pending") -> None:
    assert expected_activation in {"pending", "active"}
    primary_config = yaml.safe_load(PRIMARY_PROMETHEUS_CONFIG_PATH.read_text())
    primary_jobs = {
        item["job_name"]: item for item in primary_config["scrape_configs"]
    }
    assert primary_jobs["codestra-targets"]["file_sd_configs"] == [
        {
            "files": ["/etc/prometheus/targets/*.json"],
            "refresh_interval": "30s",
        }
    ]
    assert primary_jobs["codestra-targets"]["relabel_configs"] == [
        {
            "source_labels": ["environment"],
            "regex": "staging",
            "action": "drop",
        },
        {
            "source_labels": ["activation"],
            "regex": "active",
            "action": "keep",
        },
    ]
    config = yaml.safe_load(PROMETHEUS_CONFIG_PATH.read_text())
    jobs = {item["job_name"]: item for item in config["scrape_configs"]}
    assert set(jobs) == {
        "prometheus-staging",
        "middleware-intake-staging-readiness",
        "middleware-intake-staging",
    }
    assert PRODUCTION_TOKEN_URL not in json.dumps(config, sort_keys=True)
    for job_name, activation in (
        ("middleware-intake-staging-readiness", "pending"),
        ("middleware-intake-staging", "active"),
    ):
        job = jobs[job_name]
        assert job["scheme"] == "http" and job["metrics_path"] == "/metrics"
        assert job["sample_limit"] == 5000 and job["body_size_limit"] == "8MB"
        assert job["oauth2"] == {
            "client_id": "monitoring-readonly",
            "client_secret_file": "/run/secrets/middleware-staging-monitoring-client-secret",
            "scopes": ["metrics.read"],
            "token_url": STAGING_TOKEN_URL,
        }
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
            ("activation",): (activation, "keep"),
            ("environment",): ("staging", "keep"),
            ("tenant_scope",): ("aggregate", "keep"),
        }
        assert job["metric_relabel_configs"] == [
            {
                "action": "labeldrop",
                "regex": EXPECTED_METRIC_LABELDROP_REGEX,
            }
        ]

    targets = json.loads(TARGETS_PATH.read_text())
    assert len(targets) == 1
    assert targets[0]["targets"] == ["middleware-intake-staging:8080"]
    labels = targets[0]["labels"]
    assert labels == {
        "activation": expected_activation,
        "job_class": "backend",
        "codestra_business": "platform",
        "environment": "staging",
        "region": "hetzner-eu",
        "deployment": "middleware-9a96ff16",
        "server": "codestra-staging-private-01",
        "application": "integration",
        "service": "middleware-intake",
        "tenant_scope": "aggregate",
        "release_id": "9a96ff1651a3-01a61e6c9761",
    }

    contract = json.loads(CONTRACT_PATH.read_text())
    authority = contract["middleware_source_authority"]
    assert authority["source_sha"] == EXPECTED_SOURCE
    assert authority["immutable_image_digest"] == EXPECTED_DIGEST
    assert contract["staging_evidence"]["collector_repository"] == (
        "appolon1908-hue/Codestra-Prometheus"
    )
    assert contract["staging_evidence"]["collector_branch"] == "main"
    must_verify = contract["staging_evidence"]["must_verify"]
    assert isinstance(must_verify, list)
    assert len(must_verify) == len(EXPECTED_MUST_VERIFY)
    assert set(must_verify) == EXPECTED_MUST_VERIFY
    if expected_activation == "pending":
        assert contract["staging_evidence"]["checksum"] is None
        assert contract["staging_evidence"]["artifact_path"] is None
        assert contract["staging_evidence"]["state"] == "PENDING_RUNTIME_EXECUTION"
        assert (
            contract["activation_policy"]["prometheus_target_current_state"]
            == "pending"
        )
        assert contract["activation_policy"]["prometheus_target_allowed_next_state"] == "active"
        assert all(value is False for value in contract["runtime_effects"].values())
    else:
        validate_runtime_evidence(contract)
        assert (
            contract["activation_policy"]["prometheus_target_current_state"]
            == "active"
        )
        assert contract["activation_policy"]["prometheus_target_allowed_next_state"] is None
        effects = contract["runtime_effects"]
        assert effects["deployment_performed"] is True
        assert effects["prometheus_target_activated"] is True
        assert effects["tokens_provisioned"] is True
        assert effects["staging_evidence_collected"] is True
        for key, value in effects.items():
            if key not in {
                "deployment_performed",
                "prometheus_target_activated",
                "tokens_provisioned",
                "staging_evidence_collected",
            }:
                assert value is False, key
    assert (
        contract["activation_policy"]["blackbox_target_current_state"]
        == "pending"
    )
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", EXPECTED_DIGEST)
    validate_reviewed_git_evidence(contract)

    collector = (CODESTRA / "scripts/collect_staging_intake_evidence.py").read_text()
    wrapper = (
        CODESTRA / "scripts/collect_staging_intake_evidence_v2.py"
    ).read_text()
    for required in (
        "unauthenticated /metrics",
        "wrong-token /metrics",
        "configured_prometheus_target",
        "MINIMUM_SOAK_SECONDS",
        "rollback_proof",
        "ProxyHandler({})",
        "prometheus_scrape_evidence",
        "validate_prometheus_url",
        '"prometheus_target_up"',
        '"prometheus_scrape_http_200"',
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

    workflow = (REPO / ".github/workflows/stage6-intake-observability.yml").read_text()
    assert "collect_staging_intake_evidence_v2.py" in workflow
    assert "test_collect_staging_intake_evidence*.py" in workflow
    assert workflow.count("integration/staging-runtime-evidence-v1.json") == 2
    legacy_workflow = (
        REPO / ".github/workflows/controlled-intake-staging-activation-gate.yml"
    ).read_text()
    assert "validate_staging_intake_observability_contract.py" in legacy_workflow
    assert 'activation == "active"' in legacy_workflow


def main() -> None:
    validate("pending")
    print("PROMETHEUS_SOURCE_GATE=PASS")
    print("BLACKBOX_ACTIVATION_GATE=NOT_YET_REQUIRED")


if __name__ == "__main__":
    main()
