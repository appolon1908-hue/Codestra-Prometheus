from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "codestra/scripts"
sys.path.insert(0, str(SCRIPTS))

import validate_staging_intake_observability as source
import validate_staging_intake_observability_activation as activation


class StagingIntakeActivationContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.targets = json.loads(
            source.TARGETS_PATH.read_text(encoding="utf-8")
        )
        self.contract = json.loads(
            source.CONTRACT_PATH.read_text(encoding="utf-8")
        )

    def validate_with_fixtures(
        self,
        *,
        activation_state: str,
        contract: dict[str, object],
        expected_activation: str,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target_path = root / "staging.json"
            contract_path = root / "staging-activation-contract-v1.json"
            targets = copy.deepcopy(self.targets)
            targets[0]["labels"]["activation"] = activation_state
            target_path.write_text(json.dumps(targets), encoding="utf-8")
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            original_target = source.TARGETS_PATH
            original_contract = source.CONTRACT_PATH
            source.TARGETS_PATH = target_path
            source.CONTRACT_PATH = contract_path
            try:
                source.validate(expected_activation)
            finally:
                source.TARGETS_PATH = original_target
                source.CONTRACT_PATH = original_contract

    def test_pending_source_state_accepts_pending_evidence(self) -> None:
        self.validate_with_fixtures(
            activation_state="pending",
            contract=self.contract,
            expected_activation="pending",
        )

    def test_active_target_rejects_missing_runtime_evidence(self) -> None:
        with self.assertRaises(AssertionError):
            self.validate_with_fixtures(
                activation_state="active",
                contract=self.contract,
                expected_activation="active",
            )

    def test_active_target_accepts_only_certified_runtime_evidence(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["staging_evidence"]["checksum"] = "sha256:" + "a" * 64
        contract["staging_evidence"]["state"] = "CERTIFIED_RUNTIME_EVIDENCE"
        self.validate_with_fixtures(
            activation_state="active",
            contract=contract,
            expected_activation="active",
        )

    def test_pending_target_may_record_reviewed_evidence_before_activation(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["staging_evidence"]["checksum"] = "sha256:" + "b" * 64
        contract["staging_evidence"]["state"] = "CERTIFIED_RUNTIME_EVIDENCE"
        self.validate_with_fixtures(
            activation_state="pending",
            contract=contract,
            expected_activation="pending",
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
