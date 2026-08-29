# Codestra Prometheus Corporate Features

## Mission

Prometheus is the authoritative Codestra metrics collection and alert-evaluation engine. It provides one consistent operational metric model across all managed businesses and shared platform services.

## Required scrape coverage

Prometheus must be prepared to scrape Node Exporter, cAdvisor, PostgreSQL Exporter, Redis Exporter, Blackbox Exporter, Caddy, Kong, Middleware, Keycloak, n8n, Odoo, OpenTelemetry Collector, Alloy and application metrics endpoints.

## Corporate metric contract

Every target uses the low-cardinality labels `codestra_business`, `application`, `service`, `environment`, `server`, `region` and `deployment`. Customer, tenant, request, trace, phone, email, message and order identifiers are not permitted as Prometheus labels.

## Corporate feature set

- service and business health rollups;
- API request/error/latency metrics;
- dependency and database latency;
- queue, inbox/outbox and worker backlog metrics;
- webhook delivery and retry metrics;
- authentication and authorization failure metrics;
- idempotency/reconciliation metrics;
- provider health and circuit-breaker state;
- deployment/version metrics;
- recording rules for common dashboards;
- SLI/SLO and error-budget evaluation;
- cardinality budgets and noisy-series detection;
- target-down and scrape-staleness detection;
- capacity and saturation signals;
- Alertmanager delivery for actionable alerts.

## Business representation

Grafana can aggregate Prometheus metrics by `codestra_business` to show corporate health and then drill down to the individual service or environment. This provides consistent views for MoneyBee, Beyvra, Breero, LARIM-A, Transportation, Booked4Seasons, Social, Klyrow, Telnexa, Kyqra, Restaurant, Provisioning and the core Codestra platform.

## Financial/trading rule

For Beyvra, Prometheus may expose aggregate order-path latency, provider health, reconciliation state, error rates and capability state. It must not store account IDs, order IDs, positions, balances, customer identifiers or credentials as labels.

## Release rule

Prometheus remains private/internal at `prom.codestra.media`. DNS assignment is not permission to publish the Prometheus native UI or API to the Internet. All Codestra configuration stays outside `upstream/`, and merge does not authorize deployment.
