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


def anchored_mapping(text: str, alias: str) -> str | None:
    """Return the source mapping carrying an exact YAML anchor."""

    lines = text.splitlines()
    pattern = re.compile(
        rf"^(?P<indent>\s*)[^#\n]+:\s*&{re.escape(alias)}(?:\s+(?P<inline>.*))?$"
    )
    for index, line in enumerate(lines):
        match = pattern.match(line)
        if match is None:
            continue
        indent = len(match.group("indent"))
        body = [match.group("inline") or ""]
        for candidate in lines[index + 1 :]:
            stripped = candidate.lstrip(" ")
            candidate_indent = len(candidate) - len(stripped)
            if stripped and candidate_indent <= indent:
                break
            body.append(candidate)
        return "\n".join(body)
    return None


def mapping_declares_ports(mapping: str, compose: str) -> bool:
    """Resolve YAML merge anchors and detect direct or inherited host ports."""

    ports_key = r"[\"']?ports[\"']?\s*:"
    if re.search(rf"(?m)(?:^|[{{,])\s*{ports_key}", mapping):
        return True
    if not re.search(r"(?m)^\s*<<\s*:", mapping):
        return False

    aliases = set(re.findall(r"\*([A-Za-z0-9_.-]+)", mapping))
    if not aliases:
        fail("Compose PostgreSQL Exporter uses an unsupported YAML merge")
    for alias in aliases:
        inherited = anchored_mapping(compose, alias)
        if inherited is None:
            fail(f"Compose PostgreSQL Exporter merge anchor is unresolved: {alias}")
        if mapping_declares_ports(inherited, compose):
            return True
    return False


def inline_service_record(services: str, service_name: str) -> dict[str, str]:
    records: list[dict[str, str]] = []
    for line in services.splitlines():
        match = re.match(r"^\s*-\s*\{(?P<body>.*)\}\s*$", line)
        if match is None:
            continue
        record: dict[str, str] = {}
        for item in match.group("body").split(","):
            key, separator, value = item.partition(":")
            if not separator:
                fail("services catalog contains a malformed inline record")
            record[key.strip()] = value.strip().strip('"\'')
        if record.get("service") == service_name:
            records.append(record)
    if len(records) != 1:
        fail(f"services catalog must contain exactly one {service_name} record")
    return records[0]


def validate_postgres_operational_identity(
    targets: object,
    services: str,
    compose: str,
    *,
    postgres_repository: str,
) -> None:
    restaurant_service = inline_service_record(services, "restaurant-backend")
    if restaurant_service.get("repo") != CURRENT_REPOSITORY:
        fail("restaurant service record lost the current frontend repository")
    if TARGET_REPOSITORY in services:
        fail("services catalog uses the target restaurant frontend before cutover")

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

    catalog_service = inline_service_record(services, "postgres-exporter")
    if catalog_service.get("endpoint") != PRIVATE_POSTGRES_IDENTITY:
        fail("services catalog does not use the private exporter identity")
    if catalog_service.get("repo") != postgres_repository:
        fail("services catalog PostgreSQL Exporter repository drifted")
    authority_match = re.search(
        r"(?m)^\s{2}postgres_exporter:\s*(\S+)\s*$",
        services,
    )
    if authority_match is None or authority_match.group(1) != postgres_repository:
        fail("services catalog PostgreSQL Exporter authority drifted")

    exporter_service = indented_block(compose, "postgres-exporter", 2)
    if exporter_service is None:
        fail("Compose PostgreSQL Exporter service is missing")
    if mapping_declares_ports(exporter_service, compose):
        fail("PostgreSQL Exporter must not publish a host port")
    if not re.search(r'(?m)^    expose:\n      - "9187"\s*$', exporter_service):
        fail("PostgreSQL Exporter must expose port 9187 privately")

    exporter_networks = indented_block(exporter_service, "networks", 4)
    if exporter_networks is None:
        fail("Compose PostgreSQL Exporter networks are missing")
    exporter_observability = indented_block(exporter_networks, "observability", 6)
    if exporter_observability is None or not re.search(
        r"(?m)^          - postgres-exporter\s*$",
        exporter_observability,
    ):
        fail("Compose private exporter alias is missing")

    prometheus_service = indented_block(compose, "prometheus", 2)
    if prometheus_service is None:
        fail("Compose Prometheus service is missing")
    prometheus_networks = indented_block(prometheus_service, "networks", 4)
    if prometheus_networks is None:
        fail("Compose Prometheus networks are missing")
    prometheus_observability = indented_block(
        prometheus_networks,
        "observability",
        6,
    )
    if prometheus_observability is None:
        fail("Prometheus must share the observability network with PostgreSQL Exporter")


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
    validate_postgres_operational_identity(
        load_json(TARGETS),
        services,
        COMPOSE.read_text(encoding="utf-8"),
        postgres_repository=postgres["repository"],
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
