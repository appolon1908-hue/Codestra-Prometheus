from __future__ import annotations

import argparse
import contextlib
import importlib.util
from copy import deepcopy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).parents[1]
LAUNCHER_PATH = (
    ROOT / "codestra/scripts/staging_runtime_authority_launcher.py"
)
launcher_spec = importlib.util.spec_from_file_location(
    "staging_runtime_authority_launcher",
    LAUNCHER_PATH,
)
launcher = importlib.util.module_from_spec(launcher_spec)
assert launcher_spec and launcher_spec.loader
launcher_spec.loader.exec_module(launcher)

DEPLOYER_PATH = ROOT / "codestra/scripts/deploy_staging_runtime.py"
deployer_spec = importlib.util.spec_from_file_location(
    "deploy_staging_runtime",
    DEPLOYER_PATH,
)
deployer = importlib.util.module_from_spec(deployer_spec)
assert deployer_spec and deployer_spec.loader
deployer_spec.loader.exec_module(deployer)


class StagingRuntimeAuthorityLauncherTests(unittest.TestCase):
    @staticmethod
    def secure_inspection(source_sha: str = "a" * 40) -> dict[str, object]:
        return {
            "Id": "b" * 64,
            "State": {
                "Running": True,
                "Pid": 1234,
                "StartedAt": "2026-09-02T20:00:00.000000000Z",
            },
            "HostConfig": {"SecurityOpt": ["no-new-privileges:true"]},
            "NetworkSettings": {
                "Networks": {
                    "codestra-observability": {},
                    "codestra-intake-observability-staging_private": {},
                }
            },
            "Config": {
                "Image": deployer.EXPECTED_IMAGE,
                "Labels": {"com.codestra.source.sha": source_sha},
            },
        }

    def test_repository_copy_refuses_before_parsing_operation_arguments(self):
        marker = "/sensitive/path/must-not-be-reported"
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                str(LAUNCHER_PATH),
                "--mode",
                "collect",
                "--source-sha",
                "a" * 40,
                "--",
                "--signing-key-file",
                marker,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("separately installed staging source authority", result.stderr)
        self.assertNotIn(marker, result.stderr)

    def test_privileged_arguments_require_explicit_boundary(self):
        with self.assertRaises(launcher.AuthorityError):
            launcher.parse_args(
                ["--mode", "collect", "--source-sha", "a" * 40]
            )
        parsed, operation = launcher.parse_args(
            [
                "--mode",
                "collect",
                "--source-sha",
                "a" * 40,
                "--",
                "--base-url",
                "http://middleware-intake-staging:8080",
            ]
        )
        self.assertEqual(parsed.mode, "collect")
        self.assertEqual(parsed.source_sha, "a" * 40)
        self.assertEqual(
            operation,
            ["--base-url", "http://middleware-intake-staging:8080"],
        )

    def test_verified_loader_compiles_supplied_bytes_not_checkout_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "candidate.py"
            path.write_text("VALUE = 'unverified-path'\n", encoding="utf-8")
            module = launcher.load_verified_module(
                "verified_candidate",
                path,
                b"VALUE = 'verified-bytes'\n",
            )
        self.assertEqual(module.VALUE, "verified-bytes")

    def test_installed_launcher_must_match_canonical_bytes(self):
        expected = {launcher.LAUNCHER_SOURCE: b"canonical launcher"}
        expected.update(
            {
                path: f"canonical {path}".encode("utf-8")
                for path in launcher.COLLECTOR_SOURCES
            }
        )
        with (
            patch.object(
                launcher,
                "canonical_paths",
                return_value=tuple(expected),
            ),
            patch.object(
                launcher,
                "canonical_blob",
                side_effect=lambda _git, _sha, relative: expected[relative],
            ),
            patch.object(
                launcher,
                "read_protected_source",
                return_value=b"different installed launcher",
            ),
        ):
            with self.assertRaises(launcher.AuthorityError):
                launcher.verify_execution_closure(
                    Path("/trusted.git"),
                    "a" * 40,
                    "collect",
                )

    def test_authority_validation_precedes_fetch_verify_and_dispatch(self):
        events: list[object] = []
        parsed = argparse.Namespace(mode="collect", source_sha="a" * 40)
        with tempfile.TemporaryDirectory() as temporary:
            with (
                patch.object(
                    launcher,
                    "validate_launcher_identity",
                    side_effect=lambda: events.append("identity"),
                ),
                patch.object(
                    launcher,
                    "parse_args",
                    side_effect=lambda _argv: (
                        events.append("parse") or (parsed, ["--test"])
                    ),
                ),
                patch.object(
                    launcher.tempfile,
                    "TemporaryDirectory",
                    return_value=contextlib.nullcontext(temporary),
                ),
                patch.object(
                    launcher,
                    "initialize_canonical_authority",
                    side_effect=lambda _root, _sha: (
                        events.append("canonical") or Path("/trusted.git")
                    ),
                ),
                patch.object(
                    launcher,
                    "verify_execution_closure",
                    side_effect=lambda _git, _sha, _mode: (
                        events.append("verify") or {"verified": b"bytes"}
                    ),
                ),
                patch.object(
                    launcher,
                    "dispatch",
                    side_effect=lambda _mode, _sha, _args, _verified: (
                        events.append("dispatch") or 0
                    ),
                ),
            ):
                self.assertEqual(launcher.main(), 0)
        self.assertEqual(
            events,
            ["identity", "parse", "canonical", "verify", "dispatch"],
        )

    def test_deploy_security_accepts_exact_kernel_and_network_state(self):
        inspection = self.secure_inspection()
        with (
            patch.object(
                deployer,
                "_docker_inspect",
                side_effect=[inspection, deepcopy(inspection)],
            ),
            patch.object(
                deployer,
                "_read_process_status",
                return_value=(
                    "NoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n"
                ),
            ),
        ):
            receipt = deployer.validate_running_container_security("a" * 40, {})
        self.assertEqual(receipt["source_sha"], "a" * 40)
        self.assertEqual(receipt["seccomp_mode"], "filter")
        self.assertTrue(receipt["no_new_privileges"])
        self.assertEqual(receipt["networks"], sorted(deployer.EXPECTED_NETWORKS))
        self.assertRegex(receipt["container_identity_sha256"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(receipt["process_identity_sha256"], r"^sha256:[0-9a-f]{64}$")

    def test_deploy_security_rejects_unconfined_or_changed_container(self):
        unconfined = self.secure_inspection()
        unconfined["HostConfig"]["SecurityOpt"].append("seccomp=unconfined")
        with patch.object(deployer, "_docker_inspect", return_value=unconfined):
            with self.assertRaises(deployer.PreflightError):
                deployer.validate_running_container_security("a" * 40, {})

        disabled = self.secure_inspection()
        with (
            patch.object(deployer, "_docker_inspect", return_value=disabled),
            patch.object(
                deployer,
                "_read_process_status",
                return_value=(
                    "NoNewPrivs:\t0\nSeccomp:\t0\nSeccomp_filters:\t0\n"
                ),
            ),
        ):
            with self.assertRaises(deployer.PreflightError):
                deployer.validate_running_container_security("a" * 40, {})

        before = self.secure_inspection()
        after = deepcopy(before)
        after["State"]["Pid"] = 4321
        with (
            patch.object(deployer, "_docker_inspect", side_effect=[before, after]),
            patch.object(
                deployer,
                "_read_process_status",
                return_value=(
                    "NoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n"
                ),
            ),
        ):
            with self.assertRaises(deployer.PreflightError):
                deployer.validate_running_container_security("a" * 40, {})

    def test_failed_security_check_removes_only_prometheus_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            secret = Path(temporary) / "client-secret"
            with (
                patch.object(deployer, "validate_isolated_interpreter"),
                patch.object(deployer, "validate_deployment_identity"),
                patch.object(deployer, "validate_secret_file", return_value=secret),
                patch.object(
                    deployer.subprocess,
                    "run",
                    return_value=argparse.Namespace(returncode=0),
                ),
                patch.object(
                    deployer,
                    "validate_running_container_security",
                    side_effect=deployer.PreflightError("unsafe runtime"),
                ),
                patch.object(
                    deployer,
                    "remove_failed_prometheus",
                    return_value=True,
                ) as cleanup,
            ):
                with self.assertRaises(deployer.PreflightError):
                    deployer.run_deploy_from_trusted_launcher(
                        "a" * 40,
                        ["--secret-file", str(secret)],
                    )
        cleanup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
