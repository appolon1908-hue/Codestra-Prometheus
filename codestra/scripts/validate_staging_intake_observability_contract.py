#!/usr/bin/env python3
"""Route CI to the source or activation validator from the target state."""
from __future__ import annotations

import json
import os

import validate_staging_intake_observability as source
import validate_staging_intake_observability_activation as activation


def main() -> None:
    targets = json.loads(source.TARGETS_PATH.read_text())
    state = targets[0]["labels"]["activation"]
    if state == "pending":
        source.main()
        return
    if state == "active":
        base_sha = os.environ.get("ACTIVATION_BASE_SHA", "").strip().lower()
        event_name = os.environ.get("GITHUB_EVENT_NAME", "").strip()
        if event_name == "pull_request" and not base_sha:
            raise SystemExit("ACTIVATION_BASE_SHA is required for an active target")
        activation.validate()
        if base_sha and activation.target_state_at(base_sha) == "pending":
            activation.validate_activation_diff(base_sha)
            print("PROMETHEUS_ACTIVATION_GATE=PASS")
        else:
            if base_sha and activation.target_state_at(base_sha) != "active":
                raise SystemExit("active target has an unsupported base state")
            print("PROMETHEUS_ACTIVE_STEADY_STATE=PASS")
        print("BLACKBOX_ACTIVATION_GATE=NOT_YET_REQUIRED")
        print("PRODUCTION_ACTIVATION_AUTHORIZED=NO")
        return
    raise SystemExit(f"unsupported staging activation state: {state!r}")


if __name__ == "__main__":
    main()
