# Repository Profile — `Codestra-Prometheus`

## Identity

- **Repository:** `appolon1908-hue/Codestra-Prometheus`
- **Category:** Observability backend — metrics
- **Visibility:** `public`
- **Default branch:** `main`
- **Canonical hostname:** `prom.codestra.media`
- **Exposure:** Internal/private only; no public native UI or API
- **Authority:** Primary Prometheus scrape, metrics, recording-rule, alert-rule, retention, and relabeling authority

## Purpose

Collects, stores, evaluates, and serves platform metrics for Grafana and Alertmanager using approved private scrape contracts.

## Owns

- Scrape jobs, service discovery, labels, relabeling, retention, storage, recording rules, and alert rules
- Approved targets for services and exporters
- Prometheus configuration validation, rule tests, backups, upgrades, and rollback source

## Does not own

- Exporter runtime configuration or credentials
- Direct notification delivery outside Alertmanager/Middleware policy
- Public access to the native Prometheus listener

## Key integrations

- Node Exporter, cAdvisor, PostgreSQL Exporter, Redis Exporter, and Blackbox Exporter
- Alertmanager
- Grafana
- OpenTelemetry/Alloy approved metrics paths

## Current priorities

1. Align exact scrape contracts with accepted exporter sources
2. Complete recording and alert rules with `promtool` tests
3. Enforce cardinality, tenant/business labels, retention, and storage policy
4. Prove restore, upgrade, downgrade, and rollback behavior

## Governance and safety

- Promotion model: `feature/docs/fix/security/upgrade -> development -> test -> staging -> production -> main`.
- Native port `9090` must remain private and must not be published through a browser-facing route.
- Never commit scrape credentials, client keys, tokens, customer payloads, or secret-bearing configuration.
- Remote write and new targets require separate review and activation.
- Merge does not start Prometheus, activate targets, change firewall rules, reload Caddy, or expose metrics publicly.

## Account-wide catalog

See `appolon1908-hue/documentaions/REPOSITORY_CATALOG.md`.
