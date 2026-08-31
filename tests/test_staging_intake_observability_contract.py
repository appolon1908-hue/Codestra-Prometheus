from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "codestra/scripts"
sys.path.insert(0, str(SCRIPTS))

import validate_staging_intake_observability as source
import validate_staging_intake_observability_activation as activation


class StagingIntakeActivationContractTests(unittest.TestCase):
    def test_source_and_activation_states_are_separate(self) -> None:
        source.validate("pending")
        targets = json.loads(source.TARGETS_PATH.read_text())
        targets[0]["labels"]["activation"] = "active"
        with tempfile.TemporaryDirectory() as directory:
            active_path = Path(directory) / "staging.json"
            active_path.write_text(json.dumps(targets))
            original = source.TARGETS_PATH
            source.TARGETS_PATH = active_path
            try:
                with self.assertRaises(AssertionError):
                    source.validate("pending")
                activation.validate()
            finally:
                source.TARGETS_PATH = original


if __name__ == "__main__":
    unittest.main()
