# Prometheus production-readiness authority — 2026-09-03

## Candidate

```text
REPOSITORY=appolon1908-hue/Codestra-Prometheus
REPOSITORY_ID=1350767800
SOURCE_BASE=staging@49729f312da4f98ee0dea252e9f9bf26ccdafe3d
TARGET_BRANCH=main
TARGET_SERVER=37.27.128.39
NATIVE_LISTENER=127.0.0.1:9090
RUNTIME_IMAGE=docker.io/prom/prometheus@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996
PRODUCTION_TARGET_ACTIVATION=pending
BLACKBOX_PROBE_ACTIVATION=disabled
PRODUCTION_DEPLOYMENT=disabled
```

This candidate supersedes the obsolete `production` branch and the earlier staging-to-main candidate created before source-provenance PR #48. The current authority is the signed `staging` tree at the SHA above.

## Included production controls

- exact upstream Prometheus source commit and tree retained as non-runtime reference;
- exact digest-pinned Prometheus 3.5.0 runtime used for config, rule and Stage 6 test validation;
- signed deterministic configuration-bundle release authority;
- exact-head, synthetic-merge and protected-commit validation;
- loopback-only host publication, read-only filesystem, non-root runtime, dropped capabilities, no-new-privileges, disabled admin/lifecycle APIs, limits, health check and persistent TSDB storage;
- low-cardinality label contract, tenant/customer identifier prohibitions, recording rules, SLOs, alerts and operations-dashboard telemetry;
- production targets and Blackbox probes retained in a fail-closed pending/disabled state;
- PostgreSQL Exporter owned by `Codestra-Postgres-Exporter`, addressed only as `postgres-exporter:9187` on the private observability network;
- no public exporter hostname, Prometheus-owned exporter container, host port, public route, custom DNS, hosts-file override, resolver-file mount or Compose inheritance;
- stable repository-name authority retained as `PREPARED_NOT_RENAMED`.

## Deliberately not activated

```text
PROMETHEUS_DEPLOYED=NO
PROMETHEUS_RELOADED=NO
PRODUCTION_TARGETS_ACTIVATED=0
BLACKBOX_PROBES_ACTIVATED=0
ALERT_DELIVERY_CHANGED=NO
EXPORTERS_DEPLOYED=0
DNS_CHANGED=NO
SECRETS_WRITTEN=NO
PRODUCTION_TRAFFIC_CHANGED=NO
```

## Remaining production cutover gates

1. Protected merge with qualifying independent approval.
2. Release the signed configuration bundle from the exact accepted commit.
3. Record its checksum, provenance, source identity and the exact Prometheus image digest.
4. Deploy the candidate to isolated staging without changing target activation.
5. Prove `promtool` configuration/rules/tests, TSDB startup, retention, loopback binding, private-network reachability, target discovery, no secret leakage and bounded cardinality.
6. Read back the authoritative runtime and active edge on `37.27.128.39`.
7. Preserve the current runtime/configuration bundle as the rollback candidate and rehearse rollback.
8. Activate targets only through a separate evidence-bound change after each endpoint is privately reachable and ownership is certified.

A repository merge establishes `SOURCE_READY`; it does not establish `PRODUCTION_LIVE` or authorize target activation.
