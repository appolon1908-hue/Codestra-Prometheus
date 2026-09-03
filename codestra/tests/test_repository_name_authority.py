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

    def test_duplicate_json_authority_keys_fail_closed(self) -> None:
        with self.assertRaises(SystemExit):
            AUTHORITY.load_json_text(
                '{"public_hostname":"public.example","public_hostname":null}',
                "synthetic-authority.json",
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

    def test_quoted_inline_host_port_publication_is_denied(self) -> None:
        changed = self.compose.replace(
            '    expose:\n      - "9187"',
            '    expose:\n      - "9187"\n    "ports": ["127.0.0.1:9187:9187"]',
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

    def test_yaml_key_alias_host_port_publication_is_denied(self) -> None:
        changed = (
            "port-key: &port-key ports\n\n"
            + self.compose.replace(
                '    expose:\n      - "9187"',
                '    expose:\n      - "9187"\n'
                '    *port-key: ["127.0.0.1:9187:9187"]',
            )
        )
        with self.assertRaises(SystemExit):
            self.validate(compose=changed)

    def test_compose_extends_is_denied(self) -> None:
        changed = self.compose.replace(
            "  postgres-exporter:\n",
            "  postgres-exporter:\n"
            "    extends:\n"
            "      file: exporter-base.yml\n"
            "      service: postgres-exporter-base\n",
            1,
        )
        with self.assertRaises(SystemExit):
            self.validate(compose=changed)

    def test_duplicate_compose_keys_fail_closed(self) -> None:
        changed = self.compose.replace(
            '    expose:\n      - "9187"',
            '    expose:\n      - "9187"\n    expose: ["9187"]',
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

    def test_prometheus_must_share_observability_network(self) -> None:
        changed = self.compose.replace(
            "    networks:\n      observability:\n        aliases:\n          - prometheus\n",
            "    networks:\n      database: {}\n",
            1,
        )
        with self.assertRaises(SystemExit):
            self.validate(compose=changed)

    def test_prometheus_decoy_outside_services_cannot_mask_drift(self) -> None:
        changed = (
            "x-prometheus-decoy:\n"
            "  prometheus:\n"
            "    networks:\n"
            "      observability: {}\n\n"
            + self.compose.replace(
                "    networks:\n      observability:\n        aliases:\n          - prometheus\n",
                "    networks:\n      database: {}\n",
                1,
            )
        )
        with self.assertRaises(SystemExit):
            self.validate(compose=changed)

    def test_prometheus_extra_hosts_cannot_shadow_exporter(self) -> None:
        changed = self.compose.replace(
            "  prometheus:\n",
            "  prometheus:\n"
            "    extra_hosts:\n"
            "      postgres-exporter: 203.0.113.10\n",
            1,
        )
        with self.assertRaises(SystemExit):
            self.validate(compose=changed)

    def test_competing_observability_alias_is_denied_case_insensitively(self) -> None:
        changed = self.compose.replace(
            "services:\n",
            "services:\n"
            "  exporter-shadow:\n"
            "    image: busybox:1.36\n"
            "    networks:\n"
            "      observability:\n"
            "        aliases:\n"
            "          - POSTGRES-EXPORTER.\n",
            1,
        )
        with self.assertRaises(SystemExit):
            self.validate(compose=changed)

    def test_prometheus_resolution_file_mount_is_denied(self) -> None:
        changed = self.compose.replace(
            "  prometheus:\n",
            "  prometheus:\n"
            "    volumes:\n"
            "      - ./hosts:/etc/hosts:ro\n",
            1,
        )
        with self.assertRaises(SystemExit):
            self.validate(compose=changed)

    def test_prometheus_extends_is_denied(self) -> None:
        changed = self.compose.replace(
            "  prometheus:\n",
            "  prometheus:\n"
            "    extends:\n"
            "      file: prometheus-base.yml\n"
            "      service: prometheus-base\n",
            1,
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

    def test_catalog_authority_must_be_in_authorities_mapping(self) -> None:
        authority = "  postgres_exporter: appolon1908-hue/Codestra-Postgres-Exporter"
        changed = self.services.replace(authority + "\n", "", 1)
        changed += "\nshadow_authorities:\n" + authority + "\n"
        with self.assertRaises(SystemExit):
            self.validate(services=changed)

    def test_restaurant_service_repository_is_exact(self) -> None:
        changed = self.services.replace(
            "repo: appolon1908-hue/Frontend-Resturant-, "
            "codestra_business: restaurant, application: restaurant, "
            "service: restaurant-backend",
            "repo: appolon1908-hue/unapproved-restaurant, "
            "codestra_business: restaurant, application: restaurant, "
            "service: restaurant-backend",
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
