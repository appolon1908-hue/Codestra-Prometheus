#!/usr/bin/env python3
"""Fail closed on repository-name drift and public PostgreSQL Exporter exposure."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ALIASES = ROOT / "codestra" / "catalog" / "repository-name-aliases.v1.json"
SERVICES = ROOT / "codestra" / "catalog" / "services.yml"
CURRENT_REPOSITORY = "appolon1908-hue/Frontend-Resturant-"
TARGET_REPOSITORY = "appolon1908-hue/restaurant-frontend"
PRIVATE_POSTGRES_IDENTITY = "postgres-exporter:9187"
FORBIDDEN_POSTGRES_HOST = "pgex" + ".codestra.media"


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def validate() -> None:
    try:
        data = json.loads(ALIASES.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"invalid repository alias manifest: {exc}")

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
    if postgres.get("private_service_identity") != PRIVATE_POSTGRES_IDENTITY:
        fail("PostgreSQL Exporter private identity is incorrect")
    if postgres.get("exposure") != "PRIVATE_INTERNAL_ONLY":
        fail("PostgreSQL Exporter must remain private/internal only")

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

    for path in (ROOT / "codestra").rglob("*"):
        if not path.is_file() or path.suffix.lower() in {
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".woff",
            ".woff2",
        }:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if FORBIDDEN_POSTGRES_HOST in text:
            fail(
                "retired PostgreSQL Exporter public hostname remains in active "
                f"Prometheus source: {path.relative_to(ROOT)}"
            )


def main() -> None:
    validate()
    print("Prometheus repository-name and private exporter authority: PASS")


if __name__ == "__main__":
    main()
