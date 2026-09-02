from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "repository_name_authority",
    ROOT / "codestra" / "scripts" / "validate_repository_name_authority.py",
)
assert SPEC is not None and SPEC.loader is not None
AUTHORITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTHORITY)


class RepositoryNameAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.targets = json.loads(
            (
                ROOT / "codestra" / "prometheus" / "targets" / "production.json"
            ).read_text(encoding="utf-8")
        )
        self.services = (
            ROOT / "codestra" / "catalog" / "services.yml"
        ).read_text(encoding="utf-8")
        self.compose = (ROOT / "codestra" / "compose.yaml").read_text(
            encoding="utf-8"
        )

    def test_current_operational_identity_passes(self) -> None:
        AUTHORITY.validate_postgres_operational_identity(
            self.targets,
            self.services,
            self.compose,
        )

    def test_public_target_is_denied(self) -> None:
        changed = json.loads(json.dumps(self.targets))
        postgres = next(
            item
            for item in changed
            if item["labels"].get("service") == "postgres-exporter"
        )
        postgres["targets"] = ["PGEX" + ".CODESTRA.MEDIA:9187"]
        with self.assertRaises(SystemExit):
            AUTHORITY.validate_postgres_operational_identity(
                changed,
                self.services,
                self.compose,
            )

    def test_host_port_publication_is_denied(self) -> None:
        changed = self.compose.replace(
            '    expose:\n      - "9187"',
            '    ports:\n      - "9187:9187"',
        )
        with self.assertRaises(SystemExit):
            AUTHORITY.validate_postgres_operational_identity(
                self.targets,
                self.services,
                changed,
            )


if __name__ == "__main__":
    unittest.main()
