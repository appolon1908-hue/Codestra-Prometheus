#!/usr/bin/env python3
"""Stage 6 token-scope isolation wrapper for the Middleware evidence collector.

This wrapper keeps the original GET-only collector as the data-plane authority,
but adds exact one-scope token validation and proves that each token is denied
from the other protected endpoint before canonical evidence is accepted.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import collect_staging_intake_evidence as collector

METRICS_SCOPE = "metrics.read"
HEALTH_SCOPE = "health.read"
EXPECTED_SIGNING_KEY_ID = (
    "sha256:926880e6fec1981b93492dbe9004f3381367500f4df4ca3ffaa1c944572dcc20"
)
OPENSSL = "/usr/bin/openssl"
REQUIRED_SIGNING_OWNER_UID = 0
WRAPPER_ONLY_OPTIONS = {"--signing-key-file", "--signature-output"}


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
    parser.add_argument("--signing-key-file", type=Path, required=True)
    parser.add_argument("--signature-output", type=Path, required=True)
    args, _ = parser.parse_known_args(argv)
    return args


def collector_argv(argv: list[str]) -> list[str]:
    """Remove only wrapper-owned options before invoking the base collector."""
    filtered: list[str] = []
    index = 0
    while index < len(argv):
        item = argv[index]
        if item in WRAPPER_ONLY_OPTIONS:
            if index + 1 >= len(argv):
                raise collector.EvidenceError(f"{item} requires a value")
            index += 2
            continue
        if any(item.startswith(option + "=") for option in WRAPPER_ONLY_OPTIONS):
            index += 1
            continue
        filtered.append(item)
        index += 1
    return filtered


def validate_signing_key(path: Path) -> Path:
    if path.is_symlink() or not path.is_file():
        raise collector.EvidenceError("evidence signing key must be a regular file")
    metadata = path.stat()
    if (
        metadata.st_uid != REQUIRED_SIGNING_OWNER_UID
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise collector.EvidenceError(
            "evidence signing key must be root-owned with no group/other access"
        )
    resolved = path.resolve(strict=True)
    command = subprocess.run(
        [OPENSSL, "pkey", "-in", str(resolved), "-pubout", "-outform", "DER"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if command.returncode != 0 or not command.stdout:
        raise collector.EvidenceError("evidence signing key is not a valid private key")
    key_id = "sha256:" + hashlib.sha256(command.stdout).hexdigest()
    if key_id != EXPECTED_SIGNING_KEY_ID:
        raise collector.EvidenceError("evidence signing key does not match source authority")
    return resolved


def sign_evidence(evidence_path: Path, signing_key: Path, output: Path) -> None:
    parent = output.parent.resolve(strict=True)
    parent_metadata = parent.stat()
    if (
        parent_metadata.st_uid != REQUIRED_SIGNING_OWNER_UID
        or stat.S_IMODE(parent_metadata.st_mode) & 0o022
    ):
        raise collector.EvidenceError(
            "signature output parent must be root-owned and not group/other writable"
        )
    if output.is_symlink() or output.exists():
        raise collector.EvidenceError("signature output already exists or is symbolic")
    command = subprocess.run(
        [
            OPENSSL,
            "pkeyutl",
            "-sign",
            "-inkey",
            str(signing_key),
            "-rawin",
            "-in",
            str(evidence_path.resolve(strict=True)),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if command.returncode != 0 or len(command.stdout) != 64:
        raise collector.EvidenceError("runtime evidence signature generation failed")
    encoded = base64.b64encode(command.stdout).decode("ascii") + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(output, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as stream:
        stream.write(encoded)


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

    original_argv = sys.argv
    captured = io.StringIO()
    try:
        sys.argv = [original_argv[0], *collector_argv(original_argv[1:])]
        with contextlib.redirect_stdout(captured):
            result = collector.main()
    finally:
        sys.argv = original_argv
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
    signing_key = validate_signing_key(args.signing_key_file)
    sign_evidence(args.output, signing_key, args.signature_output)
    print("STAGING_INTAKE_EVIDENCE_V2=PASS")
    print(f"EVIDENCE_SHA256={checksum}")
    print("EVIDENCE_SIGNATURE=PASS")
    print(f"EVIDENCE_SIGNING_KEY_ID={EXPECTED_SIGNING_KEY_ID}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except collector.EvidenceError as exc:
        print(f"STAGING_INTAKE_EVIDENCE_V2=FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
