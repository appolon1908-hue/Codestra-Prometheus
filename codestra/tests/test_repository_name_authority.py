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
        self.postgres_repository = "appolon1908-hue/Codestra-Postgres-Exporter"

    def validate(self, *, targets=None, services=None, compose=None) -> None:
        AUTHORITY.validate_postgres_operational_identity(
            self.targets if targets is None else targets,
            self.services if services is None else services,
            self.compose if compose is None else compose,
            postgres_repository=self.postgres_repository,
        )

    def test_current_operational_identity_passes(self) -> None:
        self.validate()

    def test_public_target_is_denied(self) -> None:
        changed = json.loads(json.dumps(self.targets))
        postgres = next(
            item
            for item in changed
            if item["labels"].get("service") == "postgres-exporter"
        )
        postgres["targets"] = ["PGEX" + ".CODESTRA.MEDIA:9187"]
        with self.assertRaises(SystemExit):
            self.validate(targets=changed)

    def test_host_port_publication_is_denied(self) -> None:
        changed = self.compose.replace(
            '    expose:\n      - "9187"',
            '    ports:\n      - "9187:9187"',
        )
        with self.assertRaises(SystemExit):
            self.validate(compose=changed)

    def test_inline_host_port_publication_is_denied(self) -> None:
        changed = self.compose.replace(
            '    expose:\n      - "9187"',
            '    expose:\n      - "9187"\n    ports: ["0.0.0.0:9187:9187"]',
        )
        with self.assertRaises(SystemExit):
            self.validate(compose=changed)

    def test_yaml_merge_host_port_publication_is_denied(self) -> None:
        changed = (
            "x-published: &published\n"
            "  ports:\n"
            "    - '127.0.0.1:9187:9187'\n\n"
            + self.compose.replace(
                "  postgres-exporter:\n",
                "  postgres-exporter:\n    <<: *published\n",
            )
        )
        with self.assertRaises(SystemExit):
            self.validate(compose=changed)

    def test_alias_on_database_network_does_not_satisfy_authority(self) -> None:
        changed = self.compose.replace(
            "      observability:\n        aliases:\n          - postgres-exporter\n"
            "      database: {}",
            "      observability: {}\n"
            "      database:\n        aliases:\n          - postgres-exporter",
        )
        with self.assertRaises(SystemExit):
            self.validate(compose=changed)

    def test_catalog_repository_must_match_exporter_authority(self) -> None:
        changed = self.services.replace(
            "repo: appolon1908-hue/Codestra-Postgres-Exporter, "
            "codestra_business: platform, application: databases, "
            "service: postgres-exporter",
            "repo: appolon1908-hue/unapproved-exporter, "
            "codestra_business: platform, application: databases, "
            "service: postgres-exporter",
        )
        with self.assertRaises(SystemExit):
            self.validate(services=changed)

    def test_catalog_authority_must_match_exporter_authority(self) -> None:
        changed = self.services.replace(
            "  postgres_exporter: appolon1908-hue/Codestra-Postgres-Exporter",
            "  postgres_exporter: appolon1908-hue/unapproved-exporter",
        )
        with self.assertRaises(SystemExit):
            self.validate(services=changed)

    def test_generated_bytecode_is_excluded_from_source_scan(self) -> None:
        self.assertTrue(
            AUTHORITY.is_ignored_source_path(
                ROOT / "codestra" / "tests" / "__pycache__" / "validator.pyc"
            )
        )


if __name__ == "__main__":
    unittest.main()
