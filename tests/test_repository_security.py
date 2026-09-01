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

    def test_bot_created_sync_pr_dispatches_both_exact_branch_checks(self) -> None:
        self.assertEqual(
            self.sync_document["permissions"],
            {"actions": "write", "contents": "write", "pull-requests": "write"},
        )
        self.assertIn("gh workflow run codestra-observability.yml", self.sync_source)
        self.assertIn("gh workflow run validate-codestra-corporate-runtime-v1.yml", self.sync_source)
        self.assertEqual(self.sync_source.count('--ref "$SYNC_BRANCH"'), 2)
        for name in (
            "codestra-observability.yml",
            "validate-codestra-corporate-runtime-v1.yml",
        ):
            workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
            triggers = workflow.get("on") or workflow.get(True) or {}
            self.assertIn("workflow_dispatch", triggers)

    def test_interrupted_sync_retry_reuses_only_identical_branch_and_pr(self) -> None:
        for token in (
            'UPSTREAM_TIMESTAMP="$(git -C .codestra-upstream-src show -s --format=%cI "$UPSTREAM_SHA")"',
            'export GIT_AUTHOR_DATE="$UPSTREAM_TIMESTAMP"',
            'export GIT_COMMITTER_DATE="$UPSTREAM_TIMESTAMP"',
            '[[ "$REMOTE_SHA" == "$LOCAL_SHA" ]]',
            'gh pr list --repo "$GITHUB_REPOSITORY" --state open',
            "if (( ${#OPEN_PRS[@]} > 1 )); then",
        ):
            self.assertIn(token, self.sync_source)

    def test_vendored_tree_is_bound_to_fresh_exact_upstream_commit(self) -> None:
        authority = (ROOT / ".github/workflows/codestra-observability.yml").read_text()
        self.assertIn('fetch --depth 1 --no-tags origin "$upstream_ref"', authority)
        self.assertIn("rev-parse 'HEAD^{tree}'", authority)
        self.assertIn('git rev-parse "HEAD:${import_path}"', authority)
        self.assertIn('[[ "$vendored_tree" == "$official_tree" ]]', authority)
        self.assertIn('git read-tree --prefix=upstream/ "${UPSTREAM_SHA}^{tree}"', self.sync_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
