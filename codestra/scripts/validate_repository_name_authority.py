#!/usr/bin/env python3
"""Fail closed on repository-name drift and public PostgreSQL Exporter exposure."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ALIASES = ROOT / "codestra" / "catalog" / "repository-name-aliases.v1.json"
SERVICES = ROOT / "codestra" / "catalog" / "services.yml"
TARGETS = ROOT / "codestra" / "prometheus" / "targets" / "production.json"
COMPOSE = ROOT / "codestra" / "compose.yaml"
CURRENT_REPOSITORY = "appolon1908-hue/Frontend-Resturant-"
TARGET_REPOSITORY = "appolon1908-hue/restaurant-frontend"
PRIVATE_POSTGRES_IDENTITY = "postgres-exporter:9187"
FORBIDDEN_POSTGRES_HOST = "pgex" + ".codestra.media"


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"invalid JSON {path.relative_to(ROOT)}: {exc}")


def is_ignored_source_path(path: Path) -> bool:
    return (
        path.suffix.lower()
        in {".png", ".jpg", ".jpeg", ".gif", ".woff", ".woff2", ".pyc"}
        or ".git" in path.parts
        or "__pycache__" in path.parts
    )


def indented_block(text: str, header: str, indent: int) -> str | None:
    """Return a YAML mapping block without accepting sibling content."""
    lines = text.splitlines()
    expected = " " * indent + header + ":"
    for index, line in enumerate(lines):
        if not line.startswith(expected):
            continue
        suffix = line[len(expected) :]
        if suffix.strip():
            return suffix.strip()
        body: list[str] = []
        for candidate in lines[index + 1 :]:
            stripped = candidate.lstrip(" ")
            candidate_indent = len(candidate) - len(stripped)
            if stripped and candidate_indent <= indent:
                break
            body.append(candidate)
        return "\n".join(body)
    return None


def validate_postgres_operational_identity(
    targets: object,
    services: str,
    compose: str,
) -> None:
    if not isinstance(targets, list):
        fail("production targets root must be an array")
    postgres_targets = [
        item
        for item in targets
        if isinstance(item, dict)
        and isinstance(item.get("labels"), dict)
        and item["labels"].get("service") == "postgres-exporter"
    ]
    if len(postgres_targets) != 1:
        fail("production targets must contain one PostgreSQL Exporter target")
    target = postgres_targets[0]
    if target.get("targets") != [PRIVATE_POSTGRES_IDENTITY]:
        fail("production target does not use the private exporter identity")
    if target["labels"].get("activation") != "active":
        fail("private PostgreSQL Exporter target must remain explicitly active")

    service_records = [
        line.strip()
        for line in services.splitlines()
        if "service: postgres-exporter" in line
    ]
    if len(service_records) != 1 or (
        f'endpoint: "{PRIVATE_POSTGRES_IDENTITY}"' not in service_records[0]
    ):
        fail("services catalog does not use the private exporter identity")

    service = indented_block(compose, "postgres-exporter", 2)
    if service is None:
        fail("Compose PostgreSQL Exporter service is missing")
    if re.search(r"(?m)^    ports\s*:", service):
        fail("PostgreSQL Exporter must not publish a host port")
    if not re.search(r'(?m)^    expose:\n      - "9187"\s*$', service):
        fail("PostgreSQL Exporter must expose port 9187 privately")

    networks = indented_block(service, "networks", 4)
    if networks is None:
        fail("Compose PostgreSQL Exporter networks are missing")
    observability = indented_block(networks, "observability", 6)
    if observability is None or not re.search(
        r"(?m)^          - postgres-exporter\s*$",
        observability,
    ):
        fail("Compose private exporter alias is missing")


def validate() -> None:
    data = load_json(ALIASES)

    if data.get("schema_version") != "1.0":
        fail("repository alias schema_version must be 1.0")
    if data.get("status") != "PREPARED_NOT_RENAMED":
        fail("repository aliases must remain prepared until GitHub cutover")
    if data.get("identity_key") != "repository_id":
        fail("repository_id must be the stable identity key")

    postgres = data.get("postgres_exporter", {})
    if postgres.get("repository_id") != 1350839865:
        fail("PostgreSQL Exporter repository ID is incorrect")
    if postgres.get("repository") != "appolon1908-hue/Codestra-Postgres-Exporter":
        fail("PostgreSQL Exporter principal repository is incorrect")
    if postgres.get("public_hostname") is not None:
        fail("PostgreSQL Exporter may not have a public hostname")
    if postgres.get("forbidden_public_hostname") != FORBIDDEN_POSTGRES_HOST:
        fail("retired PostgreSQL Exporter hostname must remain forbidden")
    if postgres.get("private_service_identity") != PRIVATE_POSTGRES_IDENTITY:
        fail("PostgreSQL Exporter private identity is incorrect")
    if postgres.get("exposure") != "PRIVATE_INTERNAL_ONLY":
        fail("PostgreSQL Exporter must remain private/internal only")
    for field in ("public_route_allowed", "host_public_port_allowed"):
        if postgres.get(field) is not False:
            fail(f"PostgreSQL Exporter {field} must remain false")

    mappings = data.get("mappings", [])
    if mappings != [
        {
            "repository_id": 1221155447,
            "current_repository": CURRENT_REPOSITORY,
            "target_repository_after_cutover": TARGET_REPOSITORY,
            "status": "PREPARED_NOT_RENAMED",
        }
    ]:
        fail("Prometheus repository alias mapping does not match the approved migration")

    services = SERVICES.read_text(encoding="utf-8")
    if CURRENT_REPOSITORY not in services:
        fail("services catalog lost the current restaurant frontend before cutover")
    if TARGET_REPOSITORY in services:
        fail("services catalog uses the target restaurant frontend before cutover")

    validate_postgres_operational_identity(
        load_json(TARGETS),
        services,
        COMPOSE.read_text(encoding="utf-8"),
    )

    for path in (ROOT / "codestra").rglob("*"):
        if not path.is_file() or is_ignored_source_path(path):
            continue
        if path.resolve() == ALIASES.resolve():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if FORBIDDEN_POSTGRES_HOST in text.lower():
            fail(
                "retired PostgreSQL Exporter public hostname remains in active "
                f"Prometheus source: {path.relative_to(ROOT)}"
            )


def main() -> None:
    validate()
    print("Prometheus repository-name and private exporter authority: PASS")


if __name__ == "__main__":
    main()
