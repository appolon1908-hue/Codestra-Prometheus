# Codestra Prometheus production readiness

## Current state

```text
REPOSITORY=appolon1908-hue/Codestra-Prometheus
REPOSITORY_ID=1350767800
TARGET_SERVER=37.27.128.39
PUBLIC_HOSTNAME=NONE
PRIVATE_SERVICE_IDENTITY=prometheus:9090
SOURCE_STATE=PRODUCTION_SOURCE_CANDIDATE
RUNTIME_STATE=NOT_CERTIFIED_NOT_DEPLOYED_BY_THIS_CHANGE
```

This package makes the repository source certifiable and fail-closed. It does not claim that Prometheus, Alertmanager, or any exporter has been reloaded or deployed. A source merge never enables alert delivery, remote write, the administrative API, a public listener, or a production restart.

## Canonical network boundary

- Prometheus is private-only and is consumed by approved internal services such as Grafana.
- PostgreSQL Exporter is private-only at `postgres-exporter:9187`.
- PostgreSQL Exporter has no public hostname, host port, Caddy route, Kong route, Ingress, Gateway, LoadBalancer, or NodePort.
- Prometheus must resolve `postgres-exporter` through the approved private observability network, with no `extra_hosts`, custom DNS, resolver-file mount, competing alias, or inherited Compose override.
- Alertmanager remains private unless a separately reviewed authority explicitly changes that decision.

## Source certification

Run on the exact pull-request head and protected merge result:

```bash
python3 codestra/scripts/validate_repository_name_authority.py
python3 -m unittest discover -s codestra/tests -p 'test_*.py'
python3 scripts/validate_production_readiness.py
```

The repository’s existing corporate validation workflow must also run its Prometheus configuration, rule, target, label, Compose, secret, and release checks. A passing repository-alias check does not replace `promtool` validation.

## Immutable release candidate

A deployable candidate exists only when the release packet records:

```text
PROTECTED_SOURCE_SHA=<40-character SHA>
PROMETHEUS_IMAGE=<approved image>@sha256:<digest>
ALERTMANAGER_IMAGE=<approved image>@sha256:<digest>|N/A
EXPORTER_IMAGE_DIGESTS=<service-to-digest map>
PROMETHEUS_CONFIG_SHA256=<digest>
RULES_SHA256=<digest>
TARGETS_SHA256=<digest>
SBOM_OR_UPSTREAM_IMAGE_EVIDENCE=PASS
PROVENANCE_OR_UPSTREAM_IMAGE_EVIDENCE=PASS
SIGNATURE_VERIFICATION=PASS
```

A branch name, floating tag, local image name, pull-request merge ref, or unverified registry tag is not a production identity.

## Staging certification

Apply the exact configuration and immutable images to isolated staging without changing their identities. Required evidence:

- `promtool check config` passes on the rendered configuration;
- `promtool check rules` passes for every loaded rule file;
- the running Prometheus build/version and image digest match the release packet;
- configuration checksum and rule checksum match the release packet;
- all mandatory private targets are healthy;
- any intentionally unavailable target is explicitly classified and approved, not silently ignored;
- `postgres-exporter:9187` resolves to the private exporter and nowhere else;
- no public listener exists for Prometheus, Alertmanager, or PostgreSQL Exporter;
- target labels contain no customer, tenant, account, user, email, phone, token, request, trace, raw URL, SQL statement, or other unbounded sensitive identifiers;
- cardinality and retention limits remain within the approved capacity envelope;
- alert evaluation works without enabling unapproved notification delivery;
- a supported snapshot or backup is captured and restored in staging;
- rollback to the previous configuration and immutable images succeeds;
- the candidate can be reapplied after rollback without drift.

## Production cutover

Before mutation, record the target server, current image digests, configuration and rule checksums, TSDB storage identity, retention settings, private networks, current target health, current alerting state, current snapshot/backup evidence, and rollback identities. Do not capture credentials or secret values.

Production deployment is allowed only after:

1. protected merge and exact merge-result checks pass;
2. every image and configuration identity is immutable and verified;
3. staging certification, restore rehearsal, and rollback rehearsal pass;
4. Server B `37.27.128.39` and the actual Compose/project authority are read back;
5. the `production` GitHub Environment or equivalent approved change authority authorizes the exact release packet;
6. automatic rollback triggers are defined;
7. Grafana compatibility and private scrape reachability are proven.

Deploy only the changed components. Render and validate before replacement, preserve the running service until the candidate is healthy, then switch the intended private consumers. Do not expose a new public route and do not restart unrelated workloads.

## Required post-deployment evidence

```text
TARGET_SERVER=37.27.128.39
PROMETHEUS_RUNNING_IMAGE_DIGEST=<immutable digest>
PROMETHEUS_EXPECTED_IMAGE_DIGEST=<same immutable digest>
IMAGE_DIGEST_MATCH=PASS
PROMETHEUS_CONFIG_SHA256=<digest>
RULES_SHA256=<digest>
TARGETS_SHA256=<digest>
SOURCE_SHA=<protected merge SHA>
PROMETHEUS_HEALTH=PASS
PROMETHEUS_READINESS=PASS
MANDATORY_TARGETS_HEALTHY=PASS
POSTGRES_EXPORTER_PRIVATE_RESOLUTION=PASS
PUBLIC_PROMETHEUS_ROUTE=ABSENT
PUBLIC_ALERTMANAGER_ROUTE=ABSENT
PUBLIC_POSTGRES_EXPORTER_ROUTE=ABSENT
BACKUP_OR_SNAPSHOT=PASS
RESTORE_REHEARSAL=PASS
ROLLBACK_CONFIGURATION=PASS
ROLLBACK_IMAGES_AVAILABLE=PASS
UNRELATED_WORKLOADS_RESTARTED=0
UNAPPROVED_ALERT_DELIVERY_ENABLED=NO
REMOTE_WRITE_UNINTENTIONALLY_ENABLED=NO
PRODUCTION_TRAFFIC_UNINTENTIONALLY_CHANGED=NO
```

Until that evidence exists, the correct result is `SOURCE_READY_RUNTIME_NOT_CERTIFIED`, not `PRODUCTION_LIVE`.
