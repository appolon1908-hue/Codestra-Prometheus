from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import validate_repository_alias_authority as authority  # noqa: E402


class RepositoryAliasAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.aliases = authority.require_mapping(
            authority.load_json_text(
                authority.read_regular(authority.ALIASES_PATH),
                "aliases",
            ),
            "aliases",
        )
        self.catalog = authority.require_mapping(
            authority.load_yaml_text(
                authority.read_regular(authority.SERVICES_PATH),
                "services",
            ),
            "services",
        )
        self.targets = authority.load_json_text(
            authority.read_regular(authority.TARGETS_PATH),
            "targets",
        )
        self.compose = authority.require_mapping(
            authority.load_yaml_text(
                authority.read_regular(authority.COMPOSE_PATH),
                "compose",
            ),
            "compose",
        )
        self.sources = authority.load_operational_sources()

    def validate(
        self,
        *,
        aliases: dict[str, object] | None = None,
        catalog: dict[str, object] | None = None,
        targets: object | None = None,
        compose: dict[str, object] | None = None,
        sources: dict[str, str] | None = None,
    ) -> None:
        authority.validate_documents(
            self.aliases if aliases is None else aliases,
            self.catalog if catalog is None else catalog,
            self.targets if targets is None else targets,
            self.compose if compose is None else compose,
            self.sources if sources is None else sources,
        )

    def test_repository_passes(self) -> None:
        authority.validate_repository()

    def test_public_exporter_hostname_is_rejected(self) -> None:
        aliases = copy.deepcopy(self.aliases)
        aliases["postgres_exporter"]["public_hostname"] = "metrics.example.test"
        with self.assertRaisesRegex(authority.AuthorityError, "Exporter authority drifted"):
            self.validate(aliases=aliases)

    def test_active_production_exporter_target_is_rejected(self) -> None:
        targets = copy.deepcopy(self.targets)
        for group in targets:
            if group.get("labels", {}).get("service") == "postgres-exporter":
                group["labels"]["activation"] = "active"
        with self.assertRaisesRegex(authority.AuthorityError, "must remain pending"):
            self.validate(targets=targets)

    def test_prometheus_repository_cannot_own_exporter_runtime(self) -> None:
        compose = copy.deepcopy(self.compose)
        compose["services"]["postgres-exporter"] = {
            "image": "example.invalid/exporter@sha256:" + "0" * 64,
            "expose": ["9187"],
        }
        with self.assertRaisesRegex(authority.AuthorityError, "may own only"):
            self.validate(compose=compose)

    def test_restaurant_repository_cannot_change_before_cutover(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        for record in catalog["application_services"]:
            if record.get("service") == "restaurant-backend":
                record["repo"] = authority.RESTAURANT_TARGET_REPOSITORY
        with self.assertRaisesRegex(authority.AuthorityError, "before controlled cutover"):
            self.validate(catalog=catalog)

    def test_catalog_exporter_authority_drift_is_rejected(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["authorities"]["postgres_exporter"] = "appolon1908-hue/Codestra-Prometheus"
        with self.assertRaisesRegex(authority.AuthorityError, "authority drifted"):
            self.validate(catalog=catalog)

    def test_stale_public_hostname_in_operational_source_is_rejected(self) -> None:
        sources = dict(self.sources)
        sources["codestra/prometheus/prometheus.yml"] += (
            "\n# " + "pgex" + ".codestra.media\n"
        )
        with self.assertRaisesRegex(authority.AuthorityError, "retired public"):
            self.validate(sources=sources)

    def test_encoded_public_hostname_variants_are_rejected(self) -> None:
        variants = (
            "https://" + "pgex" + "%2e" + "codestra.media/metrics",
            "https://" + "pgex" + "%252e" + "codestra.media/metrics",
            "https://" + "pgex" + "&#46;" + "codestra.media/metrics",
            "pgex" + "\u3002" + "codestra.media",
        )
        for value in variants:
            with self.subTest(value=value):
                sources = dict(self.sources)
                sources["codestra/prometheus/prometheus.yml"] += f"\n# {value}\n"
                with self.assertRaisesRegex(authority.AuthorityError, "retired public"):
                    self.validate(sources=sources)

    def test_json_escaped_public_hostname_is_rejected_after_decode(self) -> None:
        sources = dict(self.sources)
        sources["codestra/prometheus/targets/production.json"] = (
            r'[{"targets":["pgex\u002ecodestra.media:9187"],'
            r'"labels":{"service":"postgres-exporter"}}]'
        )
        with self.assertRaisesRegex(authority.AuthorityError, "retired public"):
            authority.validate_operational_hostnames(sources)

    def test_documentation_repository_id_drift_is_rejected(self) -> None:
        aliases = copy.deepcopy(self.aliases)
        aliases["documentation_authority"]["repository_id"] = 0
        with self.assertRaisesRegex(authority.AuthorityError, "documentation repository authority"):
            self.validate(aliases=aliases)

    def test_name_resolution_override_is_rejected(self) -> None:
        for field, value in (
            ("extra_hosts", ["postgres-exporter:203.0.113.10"]),
            ("dns", ["203.0.113.53"]),
            ("hostname", "postgres-exporter"),
            ("extends", {"file": "base.yml", "service": "base"}),
        ):
            compose = copy.deepcopy(self.compose)
            compose["services"]["prometheus"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                authority.AuthorityError,
                "override private name resolution",
            ):
                self.validate(compose=compose)

    def test_resolver_file_mounts_are_rejected(self) -> None:
        cases = (
            ("volumes", ["./hosts:/etc/hosts:ro"]),
            ("configs", [{"source": "hosts", "target": "/etc/hosts"}]),
            ("secrets", [{"source": "resolver", "target": "/etc/resolv.conf"}]),
            ("tmpfs", ["/etc:rw,size=1m"]),
        )
        for field, value in cases:
            compose = copy.deepcopy(self.compose)
            compose["services"]["prometheus"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                authority.AuthorityError,
                "resolver path",
            ):
                self.validate(compose=compose)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(authority.AuthorityError, "duplicate JSON key"):
            authority.load_json_text('{"repository_id":1,"repository_id":2}', "fixture")

    def test_duplicate_yaml_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(authority.AuthorityError, "duplicate mapping key"):
            authority.load_yaml_text("services: {}\nservices: {}\n", "fixture")


if __name__ == "__main__":
    unittest.main()
