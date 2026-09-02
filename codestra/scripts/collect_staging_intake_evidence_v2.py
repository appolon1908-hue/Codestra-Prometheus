#!/usr/bin/env python3
"""Stage 6 token-scope isolation wrapper for the Middleware evidence collector.

This wrapper keeps the original GET-only collector as the data-plane authority,
but adds exact one-scope token validation and proves that each token is denied
from the other protected endpoint before canonical evidence is accepted.
"""
from __future__ import annotations

import sys

if __name__ == "__main__" and not sys.flags.isolated:
    print(
        "STAGING_INTAKE_EVIDENCE_V2=FAIL: invoke with /usr/bin/python3 -I",
        file=sys.stderr,
    )
    raise SystemExit(2)

import argparse
import base64
import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any

COLLECTOR_PATH = Path(__file__).with_name("collect_staging_intake_evidence.py")
COLLECTOR_SPEC = importlib.util.spec_from_file_location(
    "codestra_staging_intake_evidence_collector",
    COLLECTOR_PATH,
)
if COLLECTOR_SPEC is None or COLLECTOR_SPEC.loader is None:
    raise RuntimeError("unable to load the trusted base evidence collector")
collector = importlib.util.module_from_spec(COLLECTOR_SPEC)
COLLECTOR_SPEC.loader.exec_module(collector)

METRICS_SCOPE = "metrics.read"
HEALTH_SCOPE = "health.read"
EXPECTED_SIGNING_KEY_ID = (
    "sha256:926880e6fec1981b93492dbe9004f3381367500f4df4ca3ffaa1c944572dcc20"
)
OPENSSL = "/usr/bin/openssl"
OPENSSL_CONFIG = "/etc/ssl/openssl.cnf"
OPENSSL_MODULES = "/usr/lib/x86_64-linux-gnu/ossl-modules"
REQUIRED_SIGNING_OWNER_UID = 0
EVIDENCE_OUTPUT_ROOT = Path("/var/lib/codestra/staging/prometheus-evidence")
SIGNING_KEY_ROOT = Path("/var/lib/codestra/staging/prometheus-evidence-signing")
REQUIRE_ISOLATED_INTERPRETER = True
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


def trusted_openssl_environment() -> dict[str, str]:
    for item, expected_type in (
        (Path(OPENSSL), "file"),
        (Path(OPENSSL_CONFIG), "file"),
        (Path(OPENSSL_MODULES), "directory"),
    ):
        if item.is_symlink():
            raise collector.EvidenceError(f"trusted OpenSSL {expected_type} is symbolic")
        metadata = item.stat()
        correct_type = item.is_file() if expected_type == "file" else item.is_dir()
        if not correct_type or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise collector.EvidenceError(
                f"trusted OpenSSL {expected_type} is absent or writable"
            )
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "OPENSSL_CONF": OPENSSL_CONFIG,
        "OPENSSL_MODULES": OPENSSL_MODULES,
    }


def validate_protected_directory(directory: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(directory))
    resolved = absolute.resolve(strict=True)
    if absolute != resolved:
        raise collector.EvidenceError(f"{label} ancestry must not be symbolic")
    current = resolved
    while True:
        metadata = current.stat()
        mode = stat.S_IMODE(metadata.st_mode)
        allowed_owner = metadata.st_uid in {0, REQUIRED_SIGNING_OWNER_UID}
        sticky_system_parent = metadata.st_uid == 0 and bool(mode & stat.S_ISVTX)
        if (
            not current.is_dir()
            or not allowed_owner
            or (mode & 0o022 and not sticky_system_parent)
        ):
            raise collector.EvidenceError(f"{label} ancestry is not protected")
        if current == current.parent:
            break
        current = current.parent
    return resolved


def validate_protected_output(path: Path, *, must_be_absent: bool) -> None:
    configured_root = validate_protected_directory(
        EVIDENCE_OUTPUT_ROOT,
        "evidence output",
    )
    absolute_parent = Path(os.path.abspath(path.parent))
    if absolute_parent != configured_root:
        raise collector.EvidenceError(
            "evidence outputs must be direct children of the configured protected root"
        )
    if path.is_symlink():
        raise collector.EvidenceError("evidence output must not be symbolic")
    if must_be_absent and path.exists():
        raise collector.EvidenceError("signature output already exists")
    if path.exists():
        metadata = path.stat()
        if (
            not path.is_file()
            or metadata.st_uid != REQUIRED_SIGNING_OWNER_UID
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise collector.EvidenceError(
                "existing evidence output must be protected and regular"
            )


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
    configured_root = validate_protected_directory(SIGNING_KEY_ROOT, "signing key")
    if resolved.parent != configured_root:
        raise collector.EvidenceError(
            "evidence signing key must be inside the configured protected root"
        )
    command = subprocess.run(
        [OPENSSL, "pkey", "-in", str(resolved), "-pubout", "-outform", "DER"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=trusted_openssl_environment(),
    )
    if command.returncode != 0 or not command.stdout:
        raise collector.EvidenceError("evidence signing key is not a valid private key")
    key_id = "sha256:" + hashlib.sha256(command.stdout).hexdigest()
    if key_id != EXPECTED_SIGNING_KEY_ID:
        raise collector.EvidenceError("evidence signing key does not match source authority")
    return resolved


def exact_evidence_bytes(path: Path, expected_checksum: str) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != REQUIRED_SIGNING_OWNER_UID
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise collector.EvidenceError(
                "runtime evidence must be a protected regular file"
            )
        encoded = stream.read(8 * 1024 * 1024 + 1)
    if len(encoded) > 8 * 1024 * 1024:
        raise collector.EvidenceError("runtime evidence exceeds the maximum size")
    actual_checksum = "sha256:" + hashlib.sha256(encoded).hexdigest()
    if actual_checksum != expected_checksum:
        raise collector.EvidenceError(
            "runtime evidence bytes do not match the collector checksum"
        )
    return encoded


def sign_evidence(evidence: bytes, signing_key: Path, output: Path) -> None:
    descriptor = os.memfd_create(
        "codestra-staging-evidence",
        flags=os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    try:
        remaining = memoryview(evidence)
        while remaining:
            written = os.write(descriptor, remaining)
            remaining = remaining[written:]
        fcntl.fcntl(
            descriptor,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        command = subprocess.run(
            [
                OPENSSL,
                "pkeyutl",
                "-sign",
                "-inkey",
                str(signing_key),
                "-rawin",
                "-in",
                f"/proc/self/fd/{descriptor}",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=trusted_openssl_environment(),
            pass_fds=(descriptor,),
        )
    finally:
        os.close(descriptor)
    if command.returncode != 0 or len(command.stdout) != 64:
        raise collector.EvidenceError("runtime evidence signature generation failed")
    encoded = base64.b64encode(command.stdout).decode("ascii") + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(output, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as stream:
        stream.write(encoded)


def main() -> int:
    if REQUIRE_ISOLATED_INTERPRETER and not sys.flags.isolated:
        raise collector.EvidenceError(
            "evidence collection requires /usr/bin/python3 -I"
        )
    args = parse_wrapper_args(sys.argv[1:])
    base_url, _, _ = collector.validate_configured_base_url(args.base_url)
    validate_protected_output(args.output, must_be_absent=False)
    validate_protected_output(args.checksum_output, must_be_absent=False)
    validate_protected_output(args.signature_output, must_be_absent=True)
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
    evidence_bytes = exact_evidence_bytes(args.output, checksum)
    sign_evidence(evidence_bytes, signing_key, args.signature_output)
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
