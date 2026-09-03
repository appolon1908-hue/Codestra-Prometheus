#!/usr/bin/env python3
"""Validate the fail-closed Codestra Prometheus production-source contract."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "production-readiness" / "production-readiness.v1.json"
GUIDE = ROOT / "production-readiness" / "PRODUCTION_READINESS.md"
ALIASES = ROOT / "codestra" / "catalog" / "repository-name-aliases.v1.json"
SERVICES = ROOT / "codestra" / "catalog" / "services.yml"
TARGETS = ROOT / "codestra" / "prometheus" / "targets" / "production.json"
COMPOSE = ROOT / "codestra" / "compose.yaml"
CORPORATE_WORKFLOW = ROOT / ".github" / "workflows" / "codestra-observability.yml"

EXPECTED_REPOSITORY = "appolon1908-hue/Codestra-Prometheus"
EXPECTED_REPOSITORY_ID = 1350767800
EXPECTED_SERVER = "37.27.128.39"
PRIVATE_PROMETHEUS = "prometheus:9090"
PRIVATE_EXPORTER = "postgres-exporter:9187"
RETIRED_EXPORTER_HOST = "pgex" + ".codestra.media"


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    if not path.is_file():
        fail(f"required JSON file is missing: {path.relative_to(ROOT)}")
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
        )
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        fail(f"invalid JSON {path.relative_to(ROOT)}: {exc}")


def require_object(value: Any, source: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{source} must be an object")
    return value


def require_exact(document: dict[str, Any], expected: dict[str, Any], source: str) -> None:
    for key, value in expected.items():
        if document.get(key) != value:
            fail(f"{source} field {key!r} is incorrect")


def validate_manifest() -> dict[str, Any]:
    document = require_object(load_json(MANIFEST), "production readiness manifest")
    require_exact(
        document,
        {
            "schema_version": "1.0",
            "repository_id": EXPECTED_REPOSITORY_ID,
            "repository": EXPECTED_REPOSITORY,
            "component": "prometheus",
            "authority": "CODESTRA_PROMETHEUS_PRODUCTION_SOURCE",
            "target_server": EXPECTED_SERVER,
            "public_hostname": None,
            "source_state": "PRODUCTION_SOURCE_CANDIDATE",
            "runtime_state": "NOT_CERTIFIED_NOT_DEPLOYED_BY_THIS_CHANGE",
            "private_service_identity": PRIVATE_PROMETHEUS,
        },
        "production readiness manifest",
    )

    exporter = document.get("private_postgresql_exporter")
    if not isinstance(exporter, dict):
        fail("private PostgreSQL Exporter contract is missing")
    require_exact(
        exporter,
        {
            "service_identity": PRIVATE_EXPORTER,
            "public_hostname": None,
            "public_route_allowed": False,
            "host_public_port_allowed": False,
        },
        "private PostgreSQL Exporter contract",
    )

    release_policy = document.get("release_policy")
    if not isinstance(release_policy, dict) or not release_policy:
        fail("release policy is missing")
    for key in (
        "protected_source_sha_required",
        "immutable_image_digests_required",
        "floating_image_tags_forbidden",
        "configuration_checksum_required",
        "promtool_validation_required",
        "sensitive_label_validation_required",
        "isolated_staging_required",
        "snapshot_or_supported_backup_required",
        "restore_rehearsal_required",
        "rollback_configuration_required",
        "post_deploy_runtime_readback_required",
        "production_environment_approval_required",
    ):
        if release_policy.get(key) is not True:
            fail(f"required release policy is not true: {key}")

    runtime_safety = document.get("runtime_safety")
    if not isinstance(runtime_safety, dict):
        fail("runtime safety policy is missing")
    for key in (
        "public_prometheus_ui_allowed",
        "public_alertmanager_ui_allowed",
        "public_postgresql_exporter_allowed",
        "admin_api_activation_authorized_by_source_merge",
        "alert_delivery_activation_authorized_by_source_merge",
        "remote_write_activation_authorized_by_source_merge",
        "workload_restart_authorized_by_source_merge",
    ):
        if runtime_safety.get(key) is not False:
            fail(f"runtime safety field must remain false: {key}")

    required_files = document.get("required_source_files")
    if not isinstance(required_files, list) or not required_files:
        fail("required source file inventory is missing")
    if len(required_files) != len(set(required_files)):
        fail("required source file inventory contains duplicates")
    for relative in required_files:
        if not isinstance(relative, str) or not relative:
            fail("required source file entry is invalid")
        if not (ROOT / relative).exists():
            fail(f"required production source is missing: {relative}")

    for key in ("required_source_checks", "production_exit_criteria"):
        values = document.get(key)
        if not isinstance(values, list) or len(values) < 5:
            fail(f"{key} is incomplete")
        if not all(isinstance(item, str) and item for item in values):
            fail(f"{key} contains an invalid entry")

    return document


def validate_private_exporter_authority() -> None:
    document = require_object(load_json(ALIASES), "repository alias authority")
    postgres = document.get("postgres_exporter")
    if not isinstance(postgres, dict):
        fail("PostgreSQL Exporter authority is missing")
    require_exact(
        postgres,
        {
            "repository_id": 1350839865,
            "repository": "appolon1908-hue/Codestra-Postgres-Exporter",
            "public_hostname": None,
            "forbidden_public_hostname": RETIRED_EXPORTER_HOST,
            "private_service_identity": PRIVATE_EXPORTER,
            "exposure": "PRIVATE_INTERNAL_ONLY",
            "public_route_allowed": False,
            "host_public_port_allowed": False,
        },
        "PostgreSQL Exporter authority",
    )

    targets = load_json(TARGETS)
    if not isinstance(targets, list):
        fail("production targets must be an array")
    matches = [
        item
        for item in targets
        if isinstance(item, dict)
        and isinstance(item.get("labels"), dict)
        and item["labels"].get("service") == "postgres-exporter"
    ]
    if len(matches) != 1:
        fail("exactly one PostgreSQL Exporter target is required")
    if matches[0].get("targets") != [PRIVATE_EXPORTER]:
        fail("PostgreSQL Exporter target must use the private identity")
    if matches[0]["labels"].get("activation") != "active":
        fail("private PostgreSQL Exporter target must remain explicitly active")


def validate_compose_and_workflow() -> None:
    compose = COMPOSE.read_text(encoding="utf-8")
    lowered = compose.lower()
    for fragment in (
        ":latest",
        "0.0.0.0:9090",
        "0.0.0.0:9093",
        "0.0.0.0:9187",
        "[::]:9090",
        "[::]:9093",
        "[::]:9187",
        "privileged: true",
        "network_mode: host",
        "/var/run/docker.sock",
    ):
        if fragment in lowered:
            fail(f"Compose contains forbidden production fragment: {fragment}")
    if PRIVATE_EXPORTER not in compose:
        fail("Compose source does not preserve the private PostgreSQL Exporter identity")
    if "sha256" not in lowered:
        fail("Compose source does not require immutable runtime image identities")
    for required in ("healthcheck:", "observability", "postgres-exporter"):
        if required not in lowered:
            fail(f"Compose source is missing production control: {required}")

    workflow = CORPORATE_WORKFLOW.read_text(encoding="utf-8")
    for required in (
        "promtool",
        "docker compose",
        "persist-credentials: false",
    ):
        if required not in workflow.lower():
            fail(f"corporate workflow is missing production validation: {required}")


def validate_catalog() -> None:
    text = SERVICES.read_text(encoding="utf-8")
    for required in (
        "postgres-exporter:9187",
        "appolon1908-hue/Codestra-Postgres-Exporter",
        "postgres_exporter:",
    ):
        if required not in text:
            fail(f"service catalog is missing private exporter authority: {required}")
    if RETIRED_EXPORTER_HOST in text.lower():
        fail("service catalog contains the retired public exporter hostname")


def validate_guide() -> None:
    text = GUIDE.read_text(encoding="utf-8")
    for required in (
        "SOURCE_STATE=PRODUCTION_SOURCE_CANDIDATE",
        "RUNTIME_STATE=NOT_CERTIFIED_NOT_DEPLOYED_BY_THIS_CHANGE",
        "PROMETHEUS_IMAGE=<approved image>@sha256:<digest>",
        "SIGNATURE_VERIFICATION=PASS",
        "TARGET_SERVER=37.27.128.39",
        "PROMETHEUS_READINESS=PASS",
        "POSTGRES_EXPORTER_PRIVATE_RESOLUTION=PASS",
        "PUBLIC_POSTGRES_EXPORTER_ROUTE=ABSENT",
        "SOURCE_READY_RUNTIME_NOT_CERTIFIED",
    ):
        if required not in text:
            fail(f"production readiness guide is missing evidence field: {required}")


def validate_repository_scan() -> None:
    allowed_retired = {ALIASES.resolve()}
    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts:
            continue
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".woff", ".woff2", ".pyc"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if RETIRED_EXPORTER_HOST in text.lower() and path.resolve() not in allowed_retired:
            fail(f"retired exporter hostname remains outside its denial authority: {path.relative_to(ROOT)}")
        if re.search(r"(?im)^\s*image\s*:\s*[^#\n]*:latest\s*$", text):
            fail(f"floating latest image is forbidden: {path.relative_to(ROOT)}")


def main() -> None:
    validate_manifest()
    validate_private_exporter_authority()
    validate_compose_and_workflow()
    validate_catalog()
    validate_guide()
    validate_repository_scan()
    print("Codestra Prometheus production source readiness: PASS")


if __name__ == "__main__":
    main()
