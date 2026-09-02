#!/usr/bin/env python3
"""Stage 6 token-scope isolation wrapper for the Middleware evidence collector.

This wrapper keeps the original GET-only collector as the data-plane authority,
but adds exact one-scope token validation and proves that each token is denied
from the other protected endpoint before canonical evidence is accepted.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
from pathlib import Path
from typing import Any

import collect_staging_intake_evidence as collector

METRICS_SCOPE = "metrics.read"
HEALTH_SCOPE = "health.read"


def exact_scope_metadata(token: str, expected_scope: str) -> dict[str, Any]:
    metadata = collector.decode_jwt_metadata(token)
    if metadata["scopes"] != [expected_scope]:
        raise collector.EvidenceError(
            f"monitoring token scopes must equal only {expected_scope}: "
            + " ".join(metadata["scopes"])
        )
    return metadata


def scope_isolation_checks(base_url: str, metrics_token: str, health_token: str) -> dict[str, Any]:
    health_on_metrics, _, _ = collector.request(base_url + "/metrics", health_token)
    if health_on_metrics != 403:
        raise collector.EvidenceError(
            f"health.read token /metrics returned {health_on_metrics}, expected 403"
        )
    metrics_on_safety, _, _ = collector.request(
        base_url + "/v1/runtime/safety", metrics_token
    )
    if metrics_on_safety != 403:
        raise collector.EvidenceError(
            "metrics.read token /v1/runtime/safety returned "
            f"{metrics_on_safety}, expected 403"
        )
    return {
        "health_token_metrics_denied": True,
        "metrics_token_runtime_safety_denied": True,
        "token_scope_isolation": "PASS",
    }


def parse_wrapper_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--metrics-token-file", type=Path, required=True)
    parser.add_argument("--health-token-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--checksum-output", type=Path, required=True)
    args, _ = parser.parse_known_args(argv)
    return args


def main() -> int:
    args = parse_wrapper_args(sys.argv[1:])
    base_url, _, _ = collector.validate_configured_base_url(args.base_url)
    metrics_token = collector.read_private_file(args.metrics_token_file)
    health_token = collector.read_private_file(args.health_token_file)
    metrics_metadata = exact_scope_metadata(metrics_token, METRICS_SCOPE)
    health_metadata = exact_scope_metadata(health_token, HEALTH_SCOPE)
    if metrics_metadata["token_sha256"] == health_metadata["token_sha256"]:
        raise collector.EvidenceError("metrics and health tokens must be independently issued")

    isolation = scope_isolation_checks(base_url, metrics_token, health_token)

    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        result = collector.main()
    if result != 0:
        raise collector.EvidenceError("base evidence collector did not pass")

    evidence = json.loads(args.output.read_text(encoding="utf-8"))
    if evidence.get("overall_result") != "PASS":
        raise collector.EvidenceError("base evidence document did not pass")
    refreshed_metrics_token = collector.read_private_file(args.metrics_token_file)
    refreshed_health_token = collector.read_private_file(args.health_token_file)
    refreshed_metrics_metadata = exact_scope_metadata(
        refreshed_metrics_token,
        METRICS_SCOPE,
    )
    refreshed_health_metadata = exact_scope_metadata(
        refreshed_health_token,
        HEALTH_SCOPE,
    )
    if evidence["token_evidence"]["metrics"] != refreshed_metrics_metadata:
        raise collector.EvidenceError(
            "evidence metrics token metadata does not match the refreshed credential"
        )
    if evidence["token_evidence"]["health"] != refreshed_health_metadata:
        raise collector.EvidenceError(
            "evidence health token metadata does not match the refreshed credential"
        )
    # The base collector requires credential rotation during the soak. Re-prove
    # cross-scope denial with the credentials that are actually certified in
    # the final evidence rather than carrying forward the initial-token result.
    isolation = scope_isolation_checks(
        base_url,
        refreshed_metrics_token,
        refreshed_health_token,
    )
    evidence["schema_version"] = "1.1"
    evidence["checks"].update(isolation)
    evidence["token_evidence"]["scope_isolation"] = {
        "metrics_token_exact_scope": METRICS_SCOPE,
        "health_token_exact_scope": HEALTH_SCOPE,
        "cross_scope_access_denied": True,
    }

    checksum = collector.canonical_write(args.output, evidence)
    args.checksum_output.parent.mkdir(parents=True, exist_ok=True)
    args.checksum_output.write_text(checksum + "\n", encoding="utf-8")
    os.chmod(args.checksum_output, 0o600)
    print("STAGING_INTAKE_EVIDENCE_V2=PASS")
    print(f"EVIDENCE_SHA256={checksum}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except collector.EvidenceError as exc:
        print(f"STAGING_INTAKE_EVIDENCE_V2=FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
