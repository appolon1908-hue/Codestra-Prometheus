# Repository profile

- Authority: `appolon1908-hue/Codestra-Prometheus`
- Stable repository ID: `1350767800`
- Component: `prometheus`
- Production server authority: `37.27.128.39`
- Artifact model: verified upstream image plus signed configuration bundle
- Canonical runtime: `codestra/compose.yaml`
- Runtime validation authority: `docker.io/prom/prometheus@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996`
- Vendored upstream source: exact non-runtime reference `e06b2dc5a6149e20ca82fe936fb044a6dfe45958` / tree `9f3cc4b95e5d0ea24656c2c237a13aa26aa62f29`
- Native exposure: loopback only
- External network: approved private `codestra-observability`
- Exporter ownership: separate component repositories and core-host deployments
- PostgreSQL Exporter identity: private `postgres-exporter:9187`; target remains pending until runtime certification
- Repository rename state: `PREPARED_NOT_RENAMED`
- Production target activation from source: pending
- Production deployment from source: disabled

The Prometheus repository owns configuration, rules, SLOs, target declarations and the signed configuration bundle. It does not own exporter containers, public exporter routes, DNS, secrets, server deployment, or target activation. A source merge is not production activation.
