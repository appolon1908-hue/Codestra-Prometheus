#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_repository_security", ROOT / "scripts/validate_repository_security.py"
)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class RepositorySecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sync_source = (ROOT / ".github/workflows/upstream-source-sync.yml").read_text()
        self.sync_document = yaml.safe_load(self.sync_source)

    def test_current_repository_security_contract(self) -> None:
        VALIDATOR.validate_repository()

    def test_mutable_upstream_ref_is_rejected(self) -> None:
        source = json.loads((ROOT / "CODESTRA_UPSTREAM.json").read_text())
        lock = json.loads((ROOT / "CODESTRA_UPSTREAM_LOCK.json").read_text())
        source["upstream_ref"] = "main"
        with self.assertRaisesRegex(ValueError, "upstream_ref_must_be_exact_commit"):
            VALIDATOR.validate_upstream(source, lock)

    def test_sync_cannot_push_a_protected_branch(self) -> None:
        VALIDATOR.validate_sync(self.sync_source, self.sync_document)
        unsafe = self.sync_source.replace(
            'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"',
            "git push origin HEAD:main",
        )
        with self.assertRaisesRegex(ValueError, "protected_branch_sync_forbidden"):
            VALIDATOR.validate_sync(unsafe, self.sync_document)

    def test_required_checks_are_unique_unconditional_and_immutable(self) -> None:
        authority = (ROOT / ".github/workflows/codestra-observability.yml").read_text()
        runtime = (ROOT / ".github/workflows/validate-codestra-corporate-runtime-v1.yml").read_text()
        VALIDATOR.validate_workflows(authority, runtime)
        unsafe = authority.replace("pull_request:\n", "pull_request:\n    paths:\n      - codestra/**\n")
        with self.assertRaisesRegex(ValueError, "pull_request_validation_must_be_unconditional"):
            VALIDATOR.validate_workflows(unsafe, runtime)


if __name__ == "__main__":
    unittest.main(verbosity=2)
