from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "codestra/scripts"
sys.path.insert(0, str(SCRIPTS))

import validate_staging_intake_observability as source


class StagingIntakeActivationContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.targets = json.loads(
            source.TARGETS_PATH.read_text(encoding="utf-8")
        )
        self.contract = json.loads(
            source.CONTRACT_PATH.read_text(encoding="utf-8")
        )
        self.reference = json.loads(
            source.EVIDENCE_REFERENCE_PATH.read_text(encoding="utf-8")
        )

    def certified_reference(self) -> dict[str, object]:
        reference = copy.deepcopy(self.reference)
        now = datetime.now(UTC)
        reference.update(
            {
                "state": "CERTIFIED_RUNTIME_EVIDENCE",
                "evidence_checksum": "sha256:" + "a" * 64,
                "workflow_run_id": 33700000001,
                "artifact_name": "codestra-staging-intake-evidence-33700000001-1",
                "generated_at": (now - timedelta(minutes=5)).isoformat(),
                "expires_at": (now + timedelta(hours=12)).isoformat(),
                "independent_review_complete": True,
            }
        )
        return reference

    def validate_with_fixtures(
        self,
        *,
        activation_state: str,
        reference: dict[str, object],
        expected_activation: str,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target_path = root / "staging.json"
            contract_path = root / "staging-activation-contract-v1.json"
            reference_path = root / "staging-runtime-evidence-reference-v1.json"
            targets = copy.deepcopy(self.targets)
            targets[0]["labels"]["activation"] = activation_state
            target_path.write_text(json.dumps(targets), encoding="utf-8")
            contract_path.write_text(json.dumps(self.contract), encoding="utf-8")
            reference_path.write_text(json.dumps(reference), encoding="utf-8")
            original_target = source.TARGETS_PATH
            original_contract = source.CONTRACT_PATH
            original_reference = source.EVIDENCE_REFERENCE_PATH
            source.TARGETS_PATH = target_path
            source.CONTRACT_PATH = contract_path
            source.EVIDENCE_REFERENCE_PATH = reference_path
            try:
                source.validate(expected_activation)
            finally:
                source.TARGETS_PATH = original_target
                source.CONTRACT_PATH = original_contract
                source.EVIDENCE_REFERENCE_PATH = original_reference

    def test_pending_source_state_accepts_pending_evidence(self) -> None:
        self.validate_with_fixtures(
            activation_state="pending",
            reference=self.reference,
            expected_activation="pending",
        )

    def test_active_target_rejects_missing_runtime_evidence(self) -> None:
        with self.assertRaises(AssertionError):
            self.validate_with_fixtures(
                activation_state="active",
                reference=self.reference,
                expected_activation="active",
            )

    def test_active_target_accepts_only_certified_runtime_evidence(self) -> None:
        self.validate_with_fixtures(
            activation_state="active",
            reference=self.certified_reference(),
            expected_activation="active",
        )

    def test_pending_target_may_record_reviewed_evidence_before_activation(self) -> None:
        self.validate_with_fixtures(
            activation_state="pending",
            reference=self.certified_reference(),
            expected_activation="pending",
        )

    def test_certified_evidence_must_be_unexpired_and_independently_reviewed(self) -> None:
        expired = self.certified_reference()
        expired["expires_at"] = (
            datetime.now(UTC) - timedelta(minutes=1)
        ).isoformat()
        with self.assertRaises(AssertionError):
            self.validate_with_fixtures(
                activation_state="active",
                reference=expired,
                expected_activation="active",
            )

        unreviewed = self.certified_reference()
        unreviewed["independent_review_complete"] = False
        with self.assertRaises(AssertionError):
            self.validate_with_fixtures(
                activation_state="active",
                reference=unreviewed,
                expected_activation="active",
            )

    def test_staging_loads_every_certified_platform_rule_file(self) -> None:
        config = yaml.safe_load(
            (
                REPO / "codestra/prometheus/prometheus-staging.yml"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(set(config["rule_files"]), source.EXPECTED_STAGING_RULE_FILES)
        compose = yaml.safe_load(
            (REPO / "codestra/deploy/compose.staging.yaml").read_text(
                encoding="utf-8"
            )
        )
        mounts = set(compose["services"]["prometheus-staging"]["volumes"])
        for rule in source.EXPECTED_STAGING_RULE_FILES:
            self.assertTrue(
                any(str(mount).endswith(f":{rule}:ro") for mount in mounts),
                rule,
            )

    def test_primary_discovery_rejects_staging_environment(self) -> None:
        config = yaml.safe_load(
            (REPO / "codestra/prometheus/prometheus.yml").read_text(
                encoding="utf-8"
            )
        )
        jobs = {item["job_name"]: item for item in config["scrape_configs"]}
        relabel = jobs["codestra-targets"]["relabel_configs"]
        self.assertIn(
            {
                "source_labels": ["environment"],
                "regex": "production",
                "action": "keep",
            },
            relabel,
        )

    def test_post_merge_activation_uses_push_before_sha(self) -> None:
        workflow = (
            REPO / ".github/workflows/stage6-intake-observability.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "ACTIVATION_BASE_SHA: ${{ github.event.pull_request.base.sha || github.event.before }}",
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
