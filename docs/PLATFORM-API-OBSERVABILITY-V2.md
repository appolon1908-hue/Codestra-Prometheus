# Codestra Platform API Observability V2

Prometheus is the metrics collection and alert-evaluation authority for the Codestra platform.

## Metric contract

Every backend must expose aggregate, low-cardinality metrics for HTTP traffic, duration, status/error ratio, authentication and authorization failures, idempotency conflicts, database and dependency latency, queue depth and age, worker health, inbox/outbox/dead-letter backlog, webhook retries, provider reconciliation, deployment identity and capability state.

Allowed labels are limited to:

```text
codestra_business
application
service
operation
method
status_class
environment
server
region
deployment
tenant_scope
```

Customer, tenant, user, account, email, phone, lead, message, request, workflow, correlation, trace and span identifiers are prohibited labels. Raw URLs, SQL and exception text are also prohibited.

## Recording and alert rules

Add reusable recording rules for request rate, error ratio, p50/p95/p99 duration, queue/backlog age, worker health, provider failure and reconciliation ratio, availability and multi-window SLO burn.

Add rule tests for authentication failure surge, authorization denials, provider failures, reconciliation backlog, queue backlog, webhook retry growth, dead letters, stale worker heartbeat, database unavailability and unexpected write-capability activation.

## Target policy

Prepare source definitions for Middleware, Marketing, AI, Communication, Social, Odoo, n8n, Kong, Caddy, Keycloak, OpenTelemetry Collector, Node Exporter, cAdvisor, PostgreSQL Exporter, Redis Exporter and Alertmanager. Every new or changed application target remains `pending` until private staging evidence proves identity, network reachability, privacy, cardinality, repeated successful scrapes and rollback.

Blackbox remains pending until separately reviewed GET/HEAD-only probes are proven side-effect-free.

## Safety

```text
PROMETHEUS_NEW_TARGETS=pending
BLACKBOX_TARGET=pending
PRODUCTION_APPLY=false
RUNTIME_RELOAD=false
EXTERNAL_EFFECTS_ENABLED=false
```
