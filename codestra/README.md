# Codestra Prometheus authority

This directory is the authoritative source for Codestra metrics collection, target discovery, recording rules, and alert evaluation. Service repositories own metric exposure; this repository owns scraping, labels, aggregation, alerts, and the canonical service catalogue. Alertmanager owns routing and notification credentials. Grafana must query recording rules instead of repeatedly evaluating expensive raw PromQL.

## Safety and labels

Metrics stay on the private `codestra-observability` network. Prometheus binds to loopback for reverse-proxy access; exporters and application endpoints are never published to the internet. Every target carries `environment`, `server`, `application`, `service`, and `tenant_scope`. Central metrics use `tenant_scope=aggregate`; raw tenant, customer, account, user, email, phone, token, session, request, trace, message, order, workflow, webhook, idempotency, raw path, URL, and query labels are rejected or stripped.

## Backend contract

Backends expose normalized `codestra_http_requests_total`, `codestra_http_request_duration_seconds`, dependency/database latency histograms, queue depth, worker failures, outbox/inbox count and oldest age, webhook delivery/retry counters, authentication/authorization failures, idempotency conflicts, reconciliation failures, provider failures, `codestra_deployment_info`, and `codestra_capability_state`. Capability modes are `disabled`, `simulation`, `shadow`, or `enabled`; live external-effect capabilities require `approval_state=approved` and production evidence.

## Activation

Targets marked `activation=pending` are catalogued but deliberately not scraped. Flip a target to `active` only after its service-owned PR, private-network attachment, endpoint contract test, and cardinality review pass. MoneyBee remains excluded under the owner's standing no-change directive.

Promotion is `feature/* -> development -> test -> staging -> production -> main`. Merging does not deploy or enable live application behavior.

## Validation and rollout

```bash
python codestra/scripts/validate.py
cd upstream && go build -o ../.bin/promtool ./cmd/promtool
../.bin/promtool check config ../codestra/prometheus/prometheus.yml
../.bin/promtool check rules ../codestra/prometheus/rules/*.yml
```

Deploy exporters first, then built-in service metrics, then application instrumentation. Verify all required targets, send a synthetic Alertmanager alert, remove it, and complete a 24-hour staging soak before production promotion. Never delete backlog rows or enable live delivery to clear an alert.
