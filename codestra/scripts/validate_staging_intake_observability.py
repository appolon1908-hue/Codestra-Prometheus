#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CODESTRA = REPO / "codestra"
EXPECTED_SOURCE = "f6748a58f8d2590520a4f28776770957061cdea1"
EXPECTED_DIGEST = "sha256:695fa3ce3f50ba4d0ae0784976b946a0a683ca731155e4bd3bd9e90a4670b820"


def main() -> None:
    config = yaml.safe_load((CODESTRA / "prometheus/prometheus-staging.yml").read_text())
    jobs = {item["job_name"]: item for item in config["scrape_configs"]}
    assert set(jobs) == {"prometheus-staging", "middleware-intake-staging"}
    job = jobs["middleware-intake-staging"]
    assert job["scheme"] == "http" and job["metrics_path"] == "/metrics"
    assert job["sample_limit"] == 5000 and job["body_size_limit"] == "8MB"
    assert job["oauth2"] == {
        "client_id": "monitoring-readonly",
        "client_secret_file": "/run/secrets/middleware-staging-monitoring-client-secret",
        "token_url": "https://auth.codestra.co/realms/codestra/protocol/openid-connect/token",
    }
    assert job["file_sd_configs"] == [{"files": ["/etc/prometheus/targets/staging.json"], "refresh_interval": "30s"}]
    assert {tuple(item.get("source_labels", [])): (item.get("regex"), item.get("action")) for item in job["relabel_configs"]} == {
        ("activation",): ("active", "keep"),
        ("environment",): ("staging", "keep"),
        ("tenant_scope",): ("aggregate", "keep"),
    }

    targets = json.loads((CODESTRA / "prometheus/targets/staging.json").read_text())
    assert len(targets) == 1
    assert targets[0]["targets"] == ["middleware-intake-staging:8080"]
    labels = targets[0]["labels"]
    assert labels["activation"] == "pending"
    assert labels["environment"] == "staging"
    assert labels["tenant_scope"] == "aggregate"
    assert labels["service"] == "middleware-intake"
    assert labels["release_id"] == "f6748a58f8d2-695fa3ce3f50"

    contract = json.loads((REPO / "integration/staging-activation-contract-v1.json").read_text())
    authority = contract["middleware_source_authority"]
    assert authority["source_sha"] == EXPECTED_SOURCE
    assert authority["immutable_image_digest"] == EXPECTED_DIGEST
    assert contract["staging_evidence"]["checksum"] is None
    assert contract["activation_policy"]["prometheus_target_current_state"] == "pending"
    assert contract["activation_policy"]["blackbox_target_current_state"] == "pending"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", EXPECTED_DIGEST)

    collector = (CODESTRA / "scripts/collect_staging_intake_evidence.py").read_text()
    for required in ("unauthenticated /metrics", "wrong-token /metrics", "all_external_effects_disabled", "staging_safe", "EVIDENCE_SHA256"):
        assert required in collector
    print("STAGING_INTAKE_OBSERVABILITY_SOURCE=PASS")


if __name__ == "__main__":
    main()
