#!/usr/bin/env python3
"""Validate protected-source and reviewed sync boundaries for Prometheus."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_PATH = ROOT / "CODESTRA_UPSTREAM.json"
LOCK_PATH = ROOT / "CODESTRA_UPSTREAM_LOCK.json"
SYNC_PATH = ROOT / ".github/workflows/upstream-source-sync.yml"
AUTHORITY_WORKFLOW = ROOT / ".github/workflows/codestra-observability.yml"
RUNTIME_WORKFLOW = ROOT / ".github/workflows/validate-codestra-corporate-runtime-v1.yml"
SECRET_SCANNER = ROOT / "scripts/reject_repository_secrets.sh"


def validate_upstream(source: dict, lock: dict) -> None:
    expected = {
        "upstream_clone_url": "https://github.com/prometheus/prometheus.git",
        "trusted_upstream_ref": "refs/heads/main",
        "import_path": "upstream",
        "deployment_enabled": False,
    }
    for key, value in expected.items():
        if source.get(key) != value or lock.get(key) != value:
            raise ValueError(f"prometheus_upstream_drift:{key}")
    upstream_ref = source.get("upstream_ref")
    if not isinstance(upstream_ref, str) or re.fullmatch(r"[0-9a-f]{40}", upstream_ref) is None:
        raise ValueError("upstream_ref_must_be_exact_commit")
    if lock.get("upstream_ref") != upstream_ref or lock.get("upstream_commit") != upstream_ref:
        raise ValueError("upstream_lock_not_bound_to_exact_ref")


def validate_sync(source: str, document: dict) -> None:
    if (document.get("permissions") or {}) != {
        "actions": "write",
        "contents": "write",
        "pull-requests": "write",
    }:
        raise ValueError("sync_permissions_drift")
    if re.search(r"git\s+push\s+origin\s+(?:HEAD:)?(?:main|staging|production)(?:\s|$)", source):
        raise ValueError("protected_branch_sync_forbidden")
    required = (
        "[[ \"$UPSTREAM_REF\" =~ ^[0-9a-f]{40}$ ]]",
        "[[ \"$UPSTREAM_SHA\" == \"$UPSTREAM_REF\" ]]",
        'SYNC_BRANCH="sync/prometheus-upstream-${UPSTREAM_SHA}"',
        'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"',
        "gh pr create",
        'git fetch --depth 1 --no-tags "$UPSTREAM_URL" "$UPSTREAM_SHA"',
        'GIT_LFS_SKIP_SMUDGE=1 git -C .codestra-upstream-src fetch --filter=blob:none --no-tags origin "${TRUSTED_UPSTREAM_REF}:refs/remotes/origin/codestra-trusted"',
        'git -C .codestra-upstream-src merge-base --is-ancestor "$UPSTREAM_REF" refs/remotes/origin/codestra-trusted',
        "git rm -r --cached --quiet --ignore-unmatch upstream",
        'git read-tree --prefix=upstream/ "${UPSTREAM_SHA}^{tree}"',
        "git ls-remote --heads origin",
        '[[ "$REMOTE_SHA" == "$LOCAL_SHA" ]]',
        "gh pr list",
        "Multiple open synchronization pull requests found.",
        "gh workflow run codestra-observability.yml",
        "gh workflow run validate-codestra-corporate-runtime-v1.yml",
        '--repo "$GITHUB_REPOSITORY" --ref "$SYNC_BRANCH"',
        "--base main",
        "'synchronized_at':os.environ['UPSTREAM_TIMESTAMP']",
        'export GIT_AUTHOR_DATE="$UPSTREAM_TIMESTAMP"',
        'export GIT_COMMITTER_DATE="$UPSTREAM_TIMESTAMP"',
    )
    for token in required:
        if token not in source:
            raise ValueError(f"reviewed_sync_boundary_missing:{token}")


def validate_workflows(authority: str, runtime: str) -> None:
    persistent_branches = ["main", "development", "test", "staging", "production"]
    for name, source in (("authority", authority), ("runtime", runtime)):
        document = yaml.safe_load(source)
        triggers = document.get("on") or document.get(True) or {}
        if "pull_request" not in triggers:
            raise ValueError(f"{name}_pull_request_validation_missing")
        if (triggers.get("push") or {}).get("branches") != persistent_branches:
            raise ValueError(f"{name}_persistent_branch_validation_drift")
    combined = authority + "\n" + runtime
    required = (
        "validate-authority:",
        "name: validate-authority",
        "validate-runtime-v1:",
        "name: validate-runtime-v1",
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
        "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
        "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
        "persist-credentials: false",
        "fetch-depth: 0",
        "python scripts/validate_repository_security.py",
        "workflow_dispatch:",
        "Bind vendored Git tree to the pinned upstream commit",
        'GIT_LFS_SKIP_SMUDGE=1 git -C "$staging/source" fetch --filter=blob:none --no-tags origin "${trusted_upstream_ref}:refs/remotes/origin/codestra-trusted"',
        'git -C "$staging/source" merge-base --is-ancestor "$upstream_ref" refs/remotes/origin/codestra-trusted',
        'official_tree="$(git -C "$staging/source" rev-parse \'HEAD^{tree}\')"',
        'vendored_tree="$(git rev-parse "HEAD:${import_path}")"',
        '[[ "$vendored_tree" == "$official_tree" ]]',
        'git diff --check "$base_sha" "$GITHUB_SHA" -- . \':(exclude)upstream\'',
        "scripts/reject_repository_secrets.sh .",
    )
    for token in required:
        if token not in combined:
            raise ValueError(f"validation_boundary_missing:{token}")
    if re.search(r"uses:\s+actions/(?:checkout|setup-python|setup-go)@v\d+", combined):
        raise ValueError("mutable_action_reference")
    if re.search(r"pull_request:\s*\n\s+paths:", combined):
        raise ValueError("pull_request_validation_must_be_unconditional")
    if re.search(r"^\s*git diff --check\s*$", combined, re.MULTILINE):
        raise ValueError("whitespace_check_must_use_committed_range")


def validate_secret_scanner(source: str) -> None:
    if '-path "$search_root/tests"' in source or "--exclude-dir=tests" in source:
        raise ValueError("repository_tests_must_be_secret_scanned")
    required = (
        "set -Eeuo pipefail",
        "-type f -o -type l",
        'if [[ -L "$path" ]]',
        "grep -aEiqz",
        "client_secret",
        "[[:space:]]*[:=]",
        "PRIVATE KEY",
        "Authorization",
        "Bearer",
        "secret_scan_status=$?",
        "Secret scan failed before completing",
    )
    for token in required:
        if token not in source:
            raise ValueError(f"secret_scanner_boundary_missing:{token}")


def validate_repository() -> None:
    paths = (
        UPSTREAM_PATH,
        LOCK_PATH,
        SYNC_PATH,
        AUTHORITY_WORKFLOW,
        RUNTIME_WORKFLOW,
        SECRET_SCANNER,
    )
    for path in paths:
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"required_regular_file_missing:{path.relative_to(ROOT)}")
    upstream = json.loads(UPSTREAM_PATH.read_text(encoding="utf-8"))
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    sync_source = SYNC_PATH.read_text(encoding="utf-8")
    authority_source = AUTHORITY_WORKFLOW.read_text(encoding="utf-8")
    runtime_source = RUNTIME_WORKFLOW.read_text(encoding="utf-8")
    secret_scanner_source = SECRET_SCANNER.read_text(encoding="utf-8")
    sync_document = yaml.safe_load(sync_source)
    yaml.safe_load(authority_source)
    yaml.safe_load(runtime_source)
    validate_upstream(upstream, lock)
    validate_sync(sync_source, sync_document)
    validate_workflows(authority_source, runtime_source)
    validate_secret_scanner(secret_scanner_source)
    if (ROOT / "upstream/.git").exists():
        raise ValueError("nested_upstream_git_metadata_forbidden")


if __name__ == "__main__":
    try:
        validate_repository()
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as error:
        raise SystemExit(f"PROMETHEUS_SOURCE_SECURITY=FAIL ERROR={error}") from error
    print("PROMETHEUS_SOURCE_SECURITY=PASS")
    print("UPSTREAM_COMMIT_PINNED=YES")
    print("SYNC_THROUGH_REVIEWED_PR=YES")
    print("UNIQUE_UNCONDITIONAL_CHECKS=YES")
