#!/usr/bin/env python3
"""Fail closed on repository-name drift and public PostgreSQL Exporter exposure."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import yaml
from yaml.resolver import BaseResolver

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


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that resolves aliases but rejects duplicate keys."""


def _construct_unique_mapping(
    loader: UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"unhashable mapping key: {key!r}",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate mapping key: {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Build one JSON object while rejecting duplicate security-sensitive keys."""

    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json_text(text: str, source: str) -> object:
    try:
        return json.loads(text, object_pairs_hook=_unique_json_object)
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        fail(f"invalid JSON in {source}: {exc}")


def load_json(path: Path) -> object:
    return load_json_text(
        path.read_text(encoding="utf-8"),
        str(path.relative_to(ROOT)),
    )


def load_yaml_text(text: str, source: str) -> object:
    try:
        return yaml.load(text, Loader=UniqueKeyLoader)
    except (yaml.YAMLError, ValueError, TypeError) as exc:
        fail(f"invalid YAML in {source}: {exc}")


def require_mapping(value: object, source: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{source} must be a YAML mapping")
    if not all(isinstance(key, str) for key in value):
        fail(f"{source} contains a non-string mapping key")
    return value


def is_ignored_source_path(path: Path) -> bool:
    return (
        path.suffix.lower()
        in {".png", ".jpg", ".jpeg", ".gif", ".woff", ".woff2", ".pyc"}
        or ".git" in path.parts
        or "__pycache__" in path.parts
    )


def catalog_service_record(
    catalog: dict[str, Any],
    service_name: str,
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for section in ("infrastructure_services", "application_services"):
        values = catalog.get(section)
        if not isinstance(values, list):
            fail(f"services catalog {section} must be a list")
        for item in values:
            if not isinstance(item, dict):
                fail(f"services catalog {section} contains a non-object record")
            if item.get("service") == service_name:
                records.append(item)
    if len(records) != 1:
        fail(f"services catalog must contain exactly one {service_name} record")
    return records[0]


def compose_service_record(
    compose_document: dict[str, Any],
    service_name: str,
) -> dict[str, Any]:
    services = compose_document.get("services")
    if not isinstance(services, dict):
        fail("Compose services mapping is missing")
    value = services.get(service_name)
    if not isinstance(value, dict):
        fail(f"Compose {service_name} service is missing")
    return value


def network_names(networks: object, service_name: str) -> set[str]:
    if isinstance(networks, dict):
        if not all(isinstance(name, str) for name in networks):
            fail(f"Compose {service_name} has an invalid network name")
        return set(networks)
    if isinstance(networks, list) and all(isinstance(name, str) for name in networks):
        return set(networks)
    fail(f"Compose {service_name} networks are missing or invalid")
    return set()


def network_aliases(network_value: object, service_name: str, network: str) -> set[str]:
    if network_value is None:
        return set()
    if not isinstance(network_value, dict):
        fail(f"Compose {service_name}.{network} network options are invalid")
    aliases = network_value.get("aliases", [])
    if not isinstance(aliases, list) or not all(isinstance(item, str) for item in aliases):
        fail(f"Compose {service_name}.{network} aliases are invalid")
    return set(aliases)


def validate_postgres_operational_identity(
    targets: object,
    services: str,
    compose: str,
    *,
    postgres_repository: str,
) -> None:
    catalog = require_mapping(
        load_yaml_text(services, "codestra/catalog/services.yml"),
        "services catalog",
    )
    compose_document = require_mapping(
        load_yaml_text(compose, "codestra/compose.yaml"),
        "Compose document",
    )

    restaurant_service = catalog_service_record(catalog, "restaurant-backend")
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

    catalog_service = catalog_service_record(catalog, "postgres-exporter")
    if catalog_service.get("endpoint") != PRIVATE_POSTGRES_IDENTITY:
        fail("services catalog does not use the private exporter identity")
    if catalog_service.get("repo") != postgres_repository:
        fail("services catalog PostgreSQL Exporter repository drifted")

    authorities = catalog.get("authorities")
    if not isinstance(authorities, dict):
        fail("services catalog authorities mapping is missing")
    if authorities.get("postgres_exporter") != postgres_repository:
        fail("services catalog PostgreSQL Exporter authority drifted")

    exporter_service = compose_service_record(compose_document, "postgres-exporter")
    if "extends" in exporter_service:
        fail(
            "PostgreSQL Exporter may not use Compose extends because inherited "
            "host-port publication cannot be accepted"
        )
    if "ports" in exporter_service:
        fail("PostgreSQL Exporter must not publish a host port")
    expose = exporter_service.get("expose")
    if not isinstance(expose, list) or [str(value) for value in expose] != ["9187"]:
        fail("PostgreSQL Exporter must expose only port 9187 privately")

    exporter_networks_value = exporter_service.get("networks")
    exporter_networks = network_names(exporter_networks_value, "postgres-exporter")
    if "observability" not in exporter_networks:
        fail("PostgreSQL Exporter must join the observability network")
    if not isinstance(exporter_networks_value, dict):
        fail("PostgreSQL Exporter observability aliases are missing")
    exporter_aliases = network_aliases(
        exporter_networks_value.get("observability"),
        "postgres-exporter",
        "observability",
    )
    if "postgres-exporter" not in exporter_aliases:
        fail("Compose private exporter alias is missing")

    prometheus_service = compose_service_record(compose_document, "prometheus")
    prometheus_networks = network_names(
        prometheus_service.get("networks"),
        "prometheus",
    )
    if "observability" not in prometheus_networks:
        fail("Prometheus must share the observability network with PostgreSQL Exporter")


def validate() -> None:
    data = load_json(ALIASES)
    if not isinstance(data, dict):
        fail("repository alias authority must be a JSON object")

    if data.get("schema_version") != "1.0":
        fail("repository alias schema_version must be 1.0")
    if data.get("status") != "PREPARED_NOT_RENAMED":
        fail("repository aliases must remain prepared until GitHub cutover")
    if data.get("identity_key") != "repository_id":
        fail("repository_id must be the stable identity key")

    postgres = data.get("postgres_exporter", {})
    if not isinstance(postgres, dict):
        fail("PostgreSQL Exporter authority must be an object")
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
