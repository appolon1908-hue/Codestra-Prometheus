from __future__ import annotations

import importlib.util
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

import yaml


ROOT = Path(__file__).parents[1]
DEPLOYER_PATH = ROOT / "codestra/scripts/deploy_staging_runtime.py"
SPEC = importlib.util.spec_from_file_location(
    "deploy_staging_runtime_routing_test",
    DEPLOYER_PATH,
)
assert SPEC and SPEC.loader
DEPLOYER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEPLOYER)


class PrometheusRuntimeRoutingControlsTest(unittest.TestCase):
    @staticmethod
    def inspection(source_sha: str = "a" * 40) -> dict[str, object]:
        return {
            "Id": "b" * 64,
            "State": {
                "Running": True,
                "Pid": 1234,
                "StartedAt": "2026-09-03T12:00:00.000000000Z",
            },
            "HostConfig": {
                "SecurityOpt": ["no-new-privileges:true"],
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "Privileged": False,
                "PidsLimit": 256,
                "Init": True,
                "PublishAllPorts": False,
                "PortBindings": {},
                "ExtraHosts": None,
                "Dns": [],
                "DnsOptions": [],
                "DnsSearch": [],
                "Links": None,
            },
            "NetworkSettings": {
                "Networks": {
                    "codestra-observability": {"IPAddress": "172.24.0.6"},
                    "codestra-intake-observability-staging_private": {
                        "IPAddress": "10.44.0.6"
                    },
                },
                "Ports": {"9090/tcp": None},
            },
            "Config": {
                "Image": DEPLOYER.EXPECTED_IMAGE,
                "User": "65534:0",
                "Entrypoint": DEPLOYER.EXPECTED_ENTRYPOINT,
                "Cmd": DEPLOYER.EXPECTED_COMMAND,
                "Env": ["PATH=/bin"],
                "ExposedPorts": {"9090/tcp": {}},
                "Healthcheck": {
                    "Test": ["CMD", "/bin/promtool", "check", "healthy"]
                },
                "Labels": {
                    "com.codestra.source.sha": source_sha,
                    "com.codestra.source.repository": (
                        "appolon1908-hue/Codestra-Prometheus"
                    ),
                    "com.codestra.environment": "staging",
                    "com.codestra.service": "prometheus",
                    "com.docker.compose.project": "codestra-prometheus-staging",
                    "com.docker.compose.service": "prometheus-staging",
                    "com.docker.compose.oneoff": "False",
                },
            },
        }

    def validate(self, inspection: dict[str, object]) -> dict[str, object]:
        with (
            patch.object(
                DEPLOYER,
                "_docker_inspect",
                side_effect=[inspection, deepcopy(inspection)],
            ),
            patch.object(
                DEPLOYER,
                "_read_process_status",
                return_value=(
                    "NoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n"
                ),
            ),
            patch.object(
                DEPLOYER,
                "_validate_runtime_mounts",
                return_value="sha256:" + "c" * 64,
            ),
        ):
            return DEPLOYER.validate_running_container_security("a" * 40, {})

    def test_accepts_exact_entrypoint_and_noncanonical_private_subnets(self) -> None:
        receipt = self.validate(self.inspection())
        self.assertEqual(
            receipt["network_addresses"],
            {
                "codestra-intake-observability-staging_private": "10.44.0.6",
                "codestra-observability": "172.24.0.6",
            },
        )

    def test_rejects_entrypoint_override(self) -> None:
        inspection = self.inspection()
        inspection["Config"]["Entrypoint"] = ["/bin/sh", "-c"]
        with self.assertRaises(DEPLOYER.PreflightError):
            self.validate(inspection)

    def test_rejects_host_and_dns_routing_overrides(self) -> None:
        cases = {
            "ExtraHosts": ["middleware-intake-staging:10.99.0.8"],
            "Dns": ["10.99.0.53"],
            "DnsOptions": ["ndots:0"],
            "DnsSearch": ["attacker.invalid"],
            "Links": ["attacker:middleware-intake-staging"],
        }
        for key, value in cases.items():
            with self.subTest(key=key):
                inspection = self.inspection()
                inspection["HostConfig"][key] = value
                with self.assertRaises(DEPLOYER.PreflightError):
                    self.validate(inspection)

    def test_rejects_proxy_and_host_alias_environment(self) -> None:
        for name, value in {
            "HTTP_PROXY": "http://10.99.0.9:3128",
            "HTTPS_PROXY": "http://10.99.0.9:3128",
            "ALL_PROXY": "socks5://10.99.0.9:1080",
            "HOSTALIASES": "/tmp/hostaliases",
            "LOCALDOMAIN": "attacker.invalid",
            "RES_OPTIONS": "ndots:0",
        }.items():
            with self.subTest(name=name):
                inspection = self.inspection()
                inspection["Config"]["Env"].append(f"{name}={value}")
                with self.assertRaises(DEPLOYER.PreflightError):
                    self.validate(inspection)

    def test_compose_declares_no_target_routing_override(self) -> None:
        document = yaml.safe_load(
            (ROOT / "codestra/deploy/compose.staging.yaml").read_text(
                encoding="utf-8"
            )
        )
        service = document["services"]["prometheus-staging"]
        for key in (
            "extra_hosts",
            "dns",
            "dns_opt",
            "dns_search",
            "links",
            "external_links",
            "network_mode",
        ):
            self.assertNotIn(key, service)
        environment = service.get("environment", {})
        self.assertFalse(
            set(environment) & DEPLOYER.FORBIDDEN_ROUTING_ENVIRONMENT_KEYS
        )


if __name__ == "__main__":
    unittest.main()
