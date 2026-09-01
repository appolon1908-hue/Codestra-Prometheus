#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import tempfile
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
        VALIDATOR.validate_repository(
            allow_exact_pin_bootstrap=os.environ.get("PROMETHEUS_PENDING_SYNC") == "1"
        )

    def test_mutable_upstream_ref_is_rejected(self) -> None:
        source = json.loads((ROOT / "CODESTRA_UPSTREAM.json").read_text())
        lock = json.loads((ROOT / "CODESTRA_UPSTREAM_LOCK.json").read_text())
        source["upstream_ref"] = "main"
        with self.assertRaisesRegex(ValueError, "upstream_ref_must_be_exact_commit"):
            VALIDATOR.validate_upstream(source, lock)

    def test_pinned_commit_must_descend_from_trusted_upstream_ref(self) -> None:
        source = json.loads((ROOT / "CODESTRA_UPSTREAM.json").read_text())
        lock = json.loads((ROOT / "CODESTRA_UPSTREAM_LOCK.json").read_text())
        source["trusted_upstream_ref"] = "refs/pull/1/head"
        with self.assertRaisesRegex(ValueError, "prometheus_upstream_drift:trusted_upstream_ref"):
            VALIDATOR.validate_upstream(source, lock)
        for workflow in (
            self.sync_source,
            (ROOT / ".github/workflows/codestra-observability.yml").read_text(),
        ):
            self.assertIn("refs/remotes/origin/codestra-trusted", workflow)
            self.assertIn("merge-base --is-ancestor", workflow)

    def test_exact_pin_only_bootstrap_is_allowed_without_weakening_normal_binding(self) -> None:
        source = json.loads((ROOT / "CODESTRA_UPSTREAM.json").read_text())
        lock = json.loads((ROOT / "CODESTRA_UPSTREAM_LOCK.json").read_text())
        source["upstream_ref"] = "f" * 40
        with self.assertRaisesRegex(ValueError, "upstream_lock_not_bound"):
            VALIDATOR.validate_upstream(source, lock)
        VALIDATOR.validate_upstream(
            source, lock, allow_exact_pin_bootstrap=True
        )
        authority = (ROOT / ".github/workflows/codestra-observability.yml").read_text()
        for token in (
            '[[ "${changed[0]}" == CODESTRA_UPSTREAM.json ]]',
            'validation_ref="$locked_upstream_ref"',
            'validator_args+=(--allow-exact-pin-bootstrap)',
        ):
            self.assertIn(token, authority)

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

    def test_validation_runs_on_every_persistent_branch_push(self) -> None:
        expected = ["main", "development", "test", "staging", "production"]
        paths = (
            ROOT / ".github/workflows/codestra-observability.yml",
            ROOT / ".github/workflows/validate-codestra-corporate-runtime-v1.yml",
        )
        for path in paths:
            document = yaml.safe_load(path.read_text())
            triggers = document.get("on") or document.get(True) or {}
            self.assertEqual((triggers.get("push") or {}).get("branches"), expected)
            self.assertIn("pull_request", triggers)

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

    def test_generated_sync_pr_contains_required_release_notes_block(self) -> None:
        block = "```release-notes\\nNONE\\n```"
        self.assertIn(block, self.sync_source)
        weakened = self.sync_source.replace(block, "NONE")
        with self.assertRaisesRegex(ValueError, "reviewed_sync_boundary_missing"):
            VALIDATOR.validate_sync(weakened, yaml.safe_load(weakened))

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

    def test_sync_branch_distinguishes_completed_runs_but_not_retry_attempts(self) -> None:
        match = re.search(r'^\s*SYNC_BRANCH="([^"]+)"$', self.sync_source, re.MULTILINE)
        self.assertIsNotNone(match)
        template = match.group(1)
        upstream_sha = "a" * 40

        def render(run_id: str) -> str:
            return template.replace("${UPSTREAM_SHA}", upstream_sha).replace(
                "${GITHUB_RUN_ID}", run_id
            )

        self.assertEqual(render("12345"), render("12345"))
        self.assertNotEqual(render("12345"), render("12346"))
        self.assertIn('[[ "$GITHUB_RUN_ID" =~ ^[0-9]+$ ]]', self.sync_source)
        self.assertNotIn("GITHUB_RUN_ATTEMPT", template)

    def test_generated_sync_commit_has_dco_signoff(self) -> None:
        self.assertIn(
            'git commit --signoff -m "vendor: sync official upstream ${UPSTREAM_SHA}"',
            self.sync_source,
        )

    def test_vendored_tree_is_bound_to_fresh_exact_upstream_commit(self) -> None:
        authority = (ROOT / ".github/workflows/codestra-observability.yml").read_text()
        self.assertIn('fetch --filter=blob:none --no-tags origin "${trusted_upstream_ref}:refs/remotes/origin/codestra-trusted"', authority)
        self.assertIn('merge-base --is-ancestor "$upstream_ref" refs/remotes/origin/codestra-trusted', authority)
        self.assertIn("rev-parse 'HEAD^{tree}'", authority)
        self.assertIn('git rev-parse "HEAD:${import_path}"', authority)
        self.assertIn('[[ "$vendored_tree" == "$official_tree" ]]', authority)
        self.assertIn('git read-tree --prefix=upstream/ "${UPSTREAM_SHA}^{tree}"', self.sync_source)

    def test_whitespace_gate_checks_the_committed_base_to_head_range(self) -> None:
        authority = (ROOT / ".github/workflows/codestra-observability.yml").read_text()
        self.assertIn("fetch-depth: 0", authority)
        self.assertIn('base_sha="${{ github.event.pull_request.base.sha }}"', authority)
        self.assertIn(
            'git diff --check "$base_sha" "$GITHUB_SHA" -- . \':(exclude)upstream\'',
            authority,
        )

    def test_secret_scanner_rejects_colon_delimited_client_secrets(self) -> None:
        scanner = ROOT / "scripts/reject_repository_secrets.sh"
        VALIDATOR.validate_secret_scanner(scanner.read_text())
        for content in (
            'client_' + 'secret: actual-sensitive-value\n',
            '"client_' + 'secret": "actual-sensitive-value"\n',
            'client-' + 'secret: actual-sensitive-value\n',
            '"oauth-client-' + 'secret": "actual-sensitive-value"\n',
        ):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as directory:
                (Path(directory) / "config.txt").write_text(content)
                result = subprocess.run(
                    [scanner, directory], check=False, capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn("secret pattern detected", result.stderr)

    def test_secret_scanner_rejects_camel_case_client_secrets(self) -> None:
        scanner = ROOT / "scripts/reject_repository_secrets.sh"
        for content in (
            "".join(('"client', 'Secret": "actual-sensitive-value"\n')),
            "".join(("oauthClient", "Secret=actual-sensitive-value\n")),
            "".join(("client", "secret: actual-sensitive-value\n")),
        ):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as directory:
                (Path(directory) / "config.json").write_text(content)
                result = subprocess.run(
                    [scanner, directory], check=False, capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn("secret pattern detected", result.stderr)

    def test_secret_scanner_rejects_multiline_client_secret_values(self) -> None:
        scanner = ROOT / "scripts/reject_repository_secrets.sh"
        for content in (
            "client_" + "secret:\n  actual-sensitive-value\n",
            '"client_' + 'secret":\n  "actual-sensitive-value"\n',
            "client-" + "secret:\n  actual-sensitive-value\n",
            '"oidc-client-' + 'secret":\n  "actual-sensitive-value"\n',
        ):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as directory:
                (Path(directory) / "config.yml").write_text(content)
                result = subprocess.run(
                    [scanner, directory], check=False, capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn("secret pattern detected", result.stderr)

    def test_secret_scan_errors_fail_even_when_a_secret_also_matches(self) -> None:
        scanner = ROOT / "scripts/reject_repository_secrets.sh"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.symlink(root / "missing", root / "dangling")
            (root / "credential.txt").write_text(
                "Author" + "ization: " + "Bearer " + "abc/def+ghijklmnopqrstuvwxyz==\n"
            )
            result = subprocess.run(
                [scanner, root], check=False, capture_output=True, text=True
            )
            self.assertGreater(result.returncode, 1)
            self.assertIn("symbolic link", result.stderr)

    def test_repository_tests_are_secret_scanned(self) -> None:
        scanner = ROOT / "scripts/reject_repository_secrets.sh"
        source = scanner.read_text()
        self.assertNotIn('-path "$search_root/tests"', source)
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "tests" / "credentials.yml"
            fixture.parent.mkdir()
            fixture.write_text("client_" + "secret: actual-sensitive-value\n")
            result = subprocess.run(
                [scanner, directory], check=False, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("secret pattern detected", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
