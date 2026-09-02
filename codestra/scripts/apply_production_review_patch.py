#!/usr/bin/env python3
"""Apply the exact Prometheus production-review remediations idempotently."""

from __future__ import annotations

from pathlib import Path


def replace_once(path: Path, old: str, new: str) -> bool:
    text = path.read_text(encoding="utf-8")
    if new in text:
        return False
    if text.count(old) != 1:
        raise SystemExit(f"expected one replacement in {path}: {text.count(old)}")
    path.write_text(text.replace(old, new), encoding="utf-8")
    return True


def main() -> int:
    changed = False
    collector = Path("codestra/scripts/collect_staging_intake_evidence.py")
    changed |= replace_once(
        collector,
        "    declared_families: set[str] = set()\n    series_by_family: dict[str, int] = {}\n",
        "    declared_families: set[str] = set()\n    sampled_families: set[str] = set()\n    series_by_family: dict[str, int] = {}\n",
    )
    changed |= replace_once(
        collector,
        "        series_by_family[family] = series_by_family.get(family, 0) + 1\n        declared_families.add(family)\n",
        "        series_by_family[family] = series_by_family.get(family, 0) + 1\n        sampled_families.add(family)\n",
    )
    changed |= replace_once(
        collector,
        "    missing = EXPECTED_METRIC_FAMILIES - declared_families\n",
        "    missing = EXPECTED_METRIC_FAMILIES - sampled_families\n",
    )
    changed |= replace_once(
        collector,
        '        "family_count": len(declared_families),\n',
        '        "family_count": len(sampled_families),\n        "declared_family_count": len(declared_families),\n        "sampled_metric_families": sorted(sampled_families),\n',
    )

    prometheus = Path("codestra/prometheus/prometheus.yml")
    changed |= replace_once(
        prometheus,
        '      - files: ["/etc/prometheus/targets/*.json"]\n',
        '      - files: ["/etc/prometheus/targets/production.json"]\n',
    )

    activation = Path(".github/workflows/controlled-intake-staging-activation-gate.yml")
    changed |= replace_once(
        activation,
        '''      staging_evidence_checksum:
        description: "Passing runtime evidence checksum"
        required: true
        type: string
      confirm_prometheus_only:
''',
        '''      staging_evidence_checksum:
        description: "Passing runtime evidence checksum"
        required: true
        type: string
      staging_evidence_run_id:
        description: "Successful collector workflow run ID containing the evidence artifact"
        required: true
        type: string
      staging_evidence_artifact_name:
        description: "Exact unexpired collector artifact name"
        required: true
        type: string
      confirm_prometheus_only:
''',
    )
    changed |= replace_once(
        activation,
        "permissions:\n  contents: read\n",
        "permissions:\n  contents: read\n  actions: read\n",
    )
    changed |= replace_once(
        activation,
        '''      STAGING_EVIDENCE_CHECKSUM: ${{ inputs.staging_evidence_checksum }}
      CONFIRM_PROMETHEUS_ONLY: ${{ inputs.confirm_prometheus_only }}
''',
        '''      STAGING_EVIDENCE_CHECKSUM: ${{ inputs.staging_evidence_checksum }}
      STAGING_EVIDENCE_RUN_ID: ${{ inputs.staging_evidence_run_id }}
      STAGING_EVIDENCE_ARTIFACT_NAME: ${{ inputs.staging_evidence_artifact_name }}
      CONFIRM_PROMETHEUS_ONLY: ${{ inputs.confirm_prometheus_only }}
''',
    )
    changed |= replace_once(
        activation,
        '''      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
      - name: Verify runtime evidence references
''',
        '''      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
      - name: Download exact successful runtime evidence artifact
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          set -Eeuo pipefail
          [[ "$STAGING_EVIDENCE_RUN_ID" =~ ^[1-9][0-9]*$ ]]
          test -n "$STAGING_EVIDENCE_ARTIFACT_NAME"
          run_json="$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$STAGING_EVIDENCE_RUN_ID")"
          test "$(jq -r '.status' <<<"$run_json")" = completed
          test "$(jq -r '.conclusion' <<<"$run_json")" = success
          test "$(jq -r '.head_sha' <<<"$run_json")" = "$EXPECTED_BRANCH_HEAD"
          gh api "repos/$GITHUB_REPOSITORY/actions/runs/$STAGING_EVIDENCE_RUN_ID/artifacts" > /tmp/evidence-artifacts.json
          ARTIFACT_NAME="$STAGING_EVIDENCE_ARTIFACT_NAME" python3 - <<'PY'
          import json
          import os
          from pathlib import Path
          document = json.loads(Path('/tmp/evidence-artifacts.json').read_text())
          matches = [item for item in document.get('artifacts', []) if item.get('name') == os.environ['ARTIFACT_NAME'] and item.get('expired') is False]
          if len(matches) != 1:
              raise SystemExit('exact unexpired evidence artifact was not found')
          PY
          rm -rf staging-evidence-artifact
          mkdir -p staging-evidence-artifact
          gh run download "$STAGING_EVIDENCE_RUN_ID" \
            --repo "$GITHUB_REPOSITORY" \
            --name "$STAGING_EVIDENCE_ARTIFACT_NAME" \
            --dir staging-evidence-artifact
      - name: Verify runtime evidence references and content
''',
    )
    changed |= replace_once(
        activation,
        "          import json\n          import os\n          import re\n          import subprocess\n",
        "          import hashlib\n          import json\n          import os\n          import re\n          import subprocess\n",
    )
    changed |= replace_once(
        activation,
        '''          if evidence in forbidden_evidence:
              raise SystemExit("runtime evidence must differ from every release or image checksum")
          for name in ("CONFIRM_PROMETHEUS_ONLY", "CONFIRM_BLACKBOX_PENDING", "CONFIRM_NO_EXTERNAL_EFFECTS"):
''',
        '''          if evidence in forbidden_evidence:
              raise SystemExit("runtime evidence must differ from every release or image checksum")

          artifact_root = Path("staging-evidence-artifact")
          candidates = []
          for candidate in artifact_root.rglob("*.json"):
              try:
                  document = json.loads(candidate.read_text(encoding="utf-8"))
              except (OSError, json.JSONDecodeError):
                  continue
              if isinstance(document, dict) and document.get("suite_id") == "codestra-controlled-intake-monitoring-v1":
                  candidates.append((candidate, document))
          if len(candidates) != 1:
              raise SystemExit("artifact must contain exactly one controlled-intake evidence document")
          evidence_path, evidence_document = candidates[0]
          evidence_bytes = evidence_path.read_bytes()
          computed = "sha256:" + hashlib.sha256(evidence_bytes).hexdigest()
          if computed != evidence:
              raise SystemExit("runtime evidence checksum does not match downloaded artifact")
          checksum_files = list(artifact_root.rglob("*.sha256"))
          if len(checksum_files) != 1 or checksum_files[0].read_text(encoding="utf-8").strip().lower() != computed:
              raise SystemExit("artifact checksum file does not match the evidence document")
          if evidence_document["schema_version"] != "1.0":
              raise SystemExit("runtime evidence schema is not supported")
          if evidence_document["overall_result"] != "PASS":
              raise SystemExit("runtime evidence did not pass")
          if evidence_document["environment"] != "staging":
              raise SystemExit("runtime evidence is not from staging")
          target = evidence_document["target"]
          if target.get("private_network_only") is not True or target.get("methods_used") != ["GET"] or target.get("business_writes_performed") is not False:
              raise SystemExit("runtime evidence target boundary is unsafe")
          release = evidence_document["middleware_release"]
          if release["source_sha"] != source["source_sha"]:
              raise SystemExit("runtime evidence source SHA does not match the release lock")
          if evidence_document["middleware_release"]["image_digest"] != image:
              raise SystemExit("runtime evidence image digest does not match the release lock")
          checks = evidence_document["checks"]
          if checks.get("unauthenticated_metrics_denied") is not True or checks.get("wrong_token_metrics_denied") is not True:
              raise SystemExit("runtime evidence does not prove fail-closed metrics authentication")
          if checks.get("authenticated_metrics_scrapes") != 2 or checks.get("runtime_safety") != "PASS":
              raise SystemExit("runtime evidence does not contain the required successful scrapes and safety check")
          scrapes = evidence_document["metrics"].get("scrapes")
          if not isinstance(scrapes, list) or len(scrapes) != 2:
              raise SystemExit("runtime evidence must contain exactly two metric scrapes")
          for scrape in scrapes:
              if scrape.get("missing_metric_families") != [] or scrape.get("series_count", 0) <= 0:
                  raise SystemExit("runtime evidence contains an incomplete metric scrape")
              sampled = set(scrape.get("sampled_metric_families", []))
              required = set(scrape.get("required_metric_families", []))
              if not required or not required.issubset(sampled):
                  raise SystemExit("runtime evidence does not prove samples for every required metric family")
          safety = evidence_document["runtime_safety"]
          for key in ("provider_effects_disabled", "all_external_effects_disabled", "staging_safe"):
              if safety.get(key) is not True:
                  raise SystemExit(f"runtime safety evidence is false: {key}")
          expected_activation = {"prometheus_target_state": "pending", "blackbox_target_state": "pending", "production_authorized": False}
          if evidence_document["activation"] != expected_activation:
              raise SystemExit("runtime evidence activation boundary is invalid")

          for name in ("CONFIRM_PROMETHEUS_ONLY", "CONFIRM_BLACKBOX_PENDING", "CONFIRM_NO_EXTERNAL_EFFECTS"):
''',
    )
    changed |= replace_once(
        activation,
        '''              summary.write(f"- Locked Middleware image: `{image}`\n- Runtime evidence: `{evidence}`\n")
''',
        '''              summary.write(f"- Locked Middleware image: `{image}`\n- Runtime evidence: `{evidence}`\n")
              summary.write(f"- Evidence run: `{os.environ['STAGING_EVIDENCE_RUN_ID']}`\n- Evidence artifact: `{os.environ['STAGING_EVIDENCE_ARTIFACT_NAME']}`\n")
''',
    )
    print(f"PROMETHEUS_REVIEW_PATCH_CHANGED={str(changed).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
