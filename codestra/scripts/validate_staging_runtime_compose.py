#!/usr/bin/env python3
"""Validate the dedicated staging Prometheus runtime authority."""

from __future__ import annotations

import re
from pathlib import Path

import yaml


CODESTRA = Path(__file__).resolve().parents[1]
COMPOSE = CODESTRA / "deploy" / "compose.staging.yaml"
PROMETHEUS_CONFIG = CODESTRA / "prometheus" / "prometheus-staging.yml"
IMAGE = (
    "prom/prometheus:v3.5.0@sha256:"
    "63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996"
)


def main() -> None:
    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    assert document["name"] == "codestra-prometheus-staging"
    assert set(document["services"]) == {"prometheus-staging"}
    service = document["services"]["prometheus-staging"]
    assert service["image"] == IMAGE
    assert service["container_name"] == "codestra-prometheus-staging"
    assert service["init"] is True
    assert service["user"] == "65534:65534"
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service.get("privileged") in {None, False}
    assert "ports" not in service
    assert service["expose"] == ["9090"]
    assert set(service["networks"]) == {
        "codestra_observability",
        "middleware_staging",
    }
    assert service["networks"]["codestra_observability"]["aliases"] == [
        "prometheus-staging"
    ]
    assert service["healthcheck"]["test"] == [
        "CMD",
        "/bin/promtool",
        "check",
        "healthy",
    ]
    assert not any(
        "/etc/prometheus/rules" in str(volume)
        for volume in service.get("volumes", [])
    )
    prometheus_config = yaml.safe_load(
        PROMETHEUS_CONFIG.read_text(encoding="utf-8")
    )
    assert "rule_files" not in prometheus_config
    assert service["secrets"] == [
        {
            "source": "middleware_staging_monitoring_client_secret",
            "target": "middleware-staging-monitoring-client-secret",
            "mode": 0o400,
        }
    ]
    assert not any(
        "seccomp" in str(value).lower() for value in service["security_opt"]
    )
    assert document["networks"] == {
        "codestra_observability": {
            "external": True,
            "name": "codestra-observability",
        },
        "middleware_staging": {
            "external": True,
            "name": "codestra-intake-observability-staging_private",
        },
    }
    assert service["labels"]["com.codestra.source.sha"] == (
        "${PROMETHEUS_SOURCE_SHA:?exact merged source SHA is required}"
    )
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", IMAGE.rsplit("@", 1)[1])
    text = COMPOSE.read_text(encoding="utf-8").lower()
    assert "seccomp=unconfined" not in text
    assert "privileged: true" not in text
    assert "klyrow" not in text
    assert "postal" not in text
    deployer = (CODESTRA / "scripts" / "deploy_staging_runtime.py").read_text(
        encoding="utf-8"
    )
    for required in (
        'SHA40 = re.compile(r"^[0-9a-f]{40}$")',
        'git_output("rev-parse", "HEAD") != source_sha',
        'CANONICAL_REPOSITORY = "https://github.com/appolon1908-hue/Codestra-Prometheus.git"',
        'CANONICAL_DEVELOPMENT_REF = "refs/remotes/codestra-canonical/development"',
        'f"+refs/heads/development:{CANONICAL_DEVELOPMENT_REF}"',
        '"merge-base",',
        "secret != normalized",
        "not 16 <= len(normalized) <= 4096",
        'b"\\x00" in normalized',
        '"--force-recreate"',
        '"--wait-timeout"',
        '"prometheus-staging"',
    ):
        assert required in deployer
    print("PROMETHEUS_STAGING_RUNTIME_SOURCE=PASS")
    print("SECCOMP_DISABLED=NO")


if __name__ == "__main__":
    main()
