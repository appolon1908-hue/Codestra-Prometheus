#!/usr/bin/env python3
"""Validate an evidence-backed pending-to-active staging PR."""
from __future__ import annotations

import argparse
import copy
import json
import re
import subprocess
from pathlib import Path

import validate_staging_intake_observability as source

REPO = Path(__file__).resolve().parents[2]
TARGET = "codestra/prometheus/targets/staging.json"
CONTRACT = "integration/staging-activation-contract-v1.json"
EVIDENCE = "integration/staging-runtime-evidence-v1.json"
EVIDENCE_SIGNATURE = "integration/staging-runtime-evidence-v1.sig"


def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(REPO), *args], text=True
    ).strip()


def target_state_at(revision: str) -> str:
    document = json.loads(git("show", f"{revision}:{TARGET}"))
    return document[0]["labels"]["activation"]


def validate_activation_diff(base_sha: str) -> None:
    assert re.fullmatch(r"[0-9a-f]{40}", base_sha)
    head_sha = git("rev-parse", "HEAD")
    assert re.fullmatch(r"[0-9a-f]{40}", head_sha)
    changed = [
        line
        for line in git("diff", "--name-only", f"{base_sha}..{head_sha}").splitlines()
        if line
    ]
    assert sorted(changed) == sorted(
        [TARGET, CONTRACT, EVIDENCE, EVIDENCE_SIGNATURE]
    ), changed
    statuses = {
        path: status
        for status, path in (
            line.split("\t", maxsplit=1)
            for line in git(
                "diff", "--name-status", f"{base_sha}..{head_sha}"
            ).splitlines()
        )
    }
    assert statuses == {
        TARGET: "M",
        CONTRACT: "M",
        EVIDENCE: "A",
        EVIDENCE_SIGNATURE: "A",
    }, statuses
    diff = git("diff", "--unified=0", f"{base_sha}..{head_sha}", "--", TARGET)
    removed = [line for line in diff.splitlines() if line.startswith("-") and not line.startswith("---")]
    added = [line for line in diff.splitlines() if line.startswith("+") and not line.startswith("+++")]
    assert len(removed) == 1 and '"activation": "pending"' in removed[0]
    assert len(added) == 1 and '"activation": "active"' in added[0]

    before = json.loads(git("show", f"{base_sha}:{CONTRACT}"))
    after = json.loads(source.CONTRACT_PATH.read_text())
    assert before["staging_evidence"]["artifact_path"] is None
    assert before["staging_evidence"]["checksum"] is None
    assert before["staging_evidence"]["signature_path"] is None
    assert before["staging_evidence"]["collector_source_sha"] is None
    assert before["staging_evidence"]["state"] == "PENDING_RUNTIME_EXECUTION"
    assert before["activation_policy"]["prometheus_target_current_state"] == "pending"
    assert before["activation_policy"]["prometheus_target_allowed_next_state"] == "active"
    assert all(value is False for value in before["runtime_effects"].values())
    assert after["staging_evidence"]["collector_source_sha"] == base_sha

    permitted = copy.deepcopy(before)
    for key in (
        "artifact_path",
        "checksum",
        "signature_path",
        "collector_source_sha",
        "state",
    ):
        permitted["staging_evidence"][key] = after["staging_evidence"][key]
    for key in (
        "prometheus_target_current_state",
        "prometheus_target_allowed_next_state",
    ):
        permitted["activation_policy"][key] = after["activation_policy"][key]
    for key in (
        "deployment_performed",
        "prometheus_target_activated",
        "tokens_provisioned",
        "staging_evidence_collected",
    ):
        permitted["runtime_effects"][key] = after["runtime_effects"][key]
    assert permitted == after


def validate() -> None:
    source.validate("active")
    contract = source.json.loads(source.CONTRACT_PATH.read_text())
    policy = contract["activation_policy"]
    assert policy["prometheus_target_current_state"] == "active"
    assert policy["prometheus_target_allowed_next_state"] is None
    assert policy["only_prometheus_target_may_transition"] is True
    assert policy["blackbox_target_current_state"] == "pending"
    assert policy["blackbox_must_remain_pending"] is True
    assert policy["production_activation_authorized"] is False
    assert contract["runtime_effects"]["prometheus_target_activated"] is True
    assert contract["runtime_effects"]["staging_evidence_collected"] is True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-sha", required=True)
    args = parser.parse_args()
    validate()
    validate_activation_diff(args.base_sha)
    print("PROMETHEUS_ACTIVATION_GATE=PASS")
    print("BLACKBOX_ACTIVATION_GATE=NOT_YET_REQUIRED")
    print("PRODUCTION_ACTIVATION_AUTHORIZED=NO")


if __name__ == "__main__":
    main()
