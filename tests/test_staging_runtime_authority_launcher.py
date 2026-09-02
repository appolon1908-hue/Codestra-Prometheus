from __future__ import annotations

import argparse
import contextlib
import importlib.util
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


class StagingRuntimeAuthorityLauncherTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
