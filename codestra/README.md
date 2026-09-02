# Codestra Prometheus authority

This directory is the authoritative source for Codestra metrics collection, target discovery, recording rules, and alert evaluation. Service repositories own metric exposure; this repository owns scraping, labels, aggregation, alerts, and the canonical service catalogue. Alertmanager owns routing and notification credentials. Grafana must query recording rules instead of repeatedly evaluating expensive raw PromQL.

## Safety and labels

Metrics stay on the private `codestra-observability` network. Prometheus binds to loopback for reverse-proxy access; exporters and application endpoints are never published to the internet. Every target carries `environment`, `server`, `application`, `service`, and `tenant_scope`. Central metrics use `tenant_scope=aggregate`; raw tenant, customer, account, user, email, phone, token, session, request, trace, message, order, workflow, webhook, idempotency, raw path, URL, and query labels are rejected or stripped.

## Backend contract

Backends expose normalized `codestra_http_requests_total`, `codestra_http_request_duration_seconds`, dependency/database latency histograms, queue depth, worker failures, outbox/inbox count and oldest age, webhook delivery/retry counters, authentication/authorization failures, idempotency conflicts, reconciliation failures, provider failures, `codestra_deployment_info`, and `codestra_capability_state`. Capability modes are `disabled`, `simulation`, `shadow`, or `enabled`; live external-effect capabilities require `approval_state=approved` and production evidence.

## Activation

Targets marked `activation=pending` are excluded from the active workload job. The
controlled Middleware target is scraped only by its OAuth2-authenticated readiness
job so Prometheus connectivity can be proven before activation. Flip a target to
`active` only after its service-owned PR, private-network attachment, endpoint
contract test, and cardinality review pass. MoneyBee remains excluded under the
owner's standing no-change directive.

Promotion is `feature/* -> development -> test -> staging -> production -> main`. Merging does not deploy or enable live application behavior.

The dedicated staging runtime authority is
`codestra/deploy/compose.staging.yaml`. It deploys only Prometheus, publishes no
host port, preserves the Docker default seccomp profile, and joins exactly the
shared observability network plus the isolated Middleware staging network. The
Middleware target remains `activation=pending` until the approved read-only
identity and runtime endpoint have both been independently proven. Activation
requires the collector's sanitized evidence document, its exact SHA-256 in the
activation contract, and its Ed25519 signature from the root-protected evidence
key on `37.27.128.39`. The reviewed four-file transition contains only the
target, contract, newly added evidence document, and detached signature. The
trusted public key is locked in the already-reviewed base and cannot change in
an activation PR. Subsequent active-state CI verifies the signature and evidence
without replaying that one-time transition.

The collector binds its base URL to the exact configured Prometheus target,
requires actual samples for every mandatory metric family, performs two
authenticated scrapes at least 300 seconds apart, and accepts a sanitized
Prometheus-only rollback proof from an absolute non-writable file. The committed
evidence contains hashes and allowlisted results only; bearer tokens remain in
mode-`0600` files outside Git and are never printed.
Because monitoring JWTs live for no more than 300 seconds, the token issuer must
atomically renew both token files during the soak. The collector rereads both
files after the delay and rejects unchanged credentials before the second scrape
or runtime-safety readback.

The v2 collector is a non-executable library and refuses direct invocation.
Collection and deployment run only through the separately installed,
root-protected source authority:

```text
/usr/bin/python3 -I /usr/local/libexec/codestra-prometheus-staging-authority.py --mode collect --source-sha <accepted-main-sha> -- <collector-options>
/usr/bin/python3 -I /usr/local/libexec/codestra-prometheus-staging-authority.py --mode deploy --source-sha <accepted-main-sha> -- --secret-file <protected-client-secret>
```

The installed launcher validates its own protected path and exact canonical
bytes before executing repository code. It fetches canonical `main` into a new
root-private bare Git directory with empty templates and system/global
configuration disabled; it never reads the checkout's `.git` directory or
local Git configuration. It then verifies the requested SHA is merged, compares
every file in the relevant execution closure byte-for-byte, and compiles only
those verified bytes under isolated Python. Collector options must follow the
standalone `--` boundary and include `--signing-key-file` and
`--signature-output`. The private key must be
below
`/var/lib/codestra/staging/prometheus-evidence-signing`, root-owned with no
group/other access, and must match
`integration/staging-evidence-signing-public.pem`; it stays outside Git. The
collector writes evidence, checksum, and a mode-`0600` detached signature only
as direct children of `/var/lib/codestra/staging/prometheus-evidence`, whose
complete ancestry must be protected. It refuses an existing or symbolic
signature output. An ordinary evidence checksum is never sufficient for
activation without this signature. OpenSSL runs with a fixed system
configuration/module allowlist, and the signer hashes and signs the same bytes
through a sealed in-memory file descriptor.

While the target label is `pending`, the dedicated
`middleware-intake-staging-readiness` scrape job exercises the same OAuth2
client-secret exchange, private network, limits, and metric relabeling as the
active job. Activation evidence must query the deployed Prometheus target API
and `up` series and prove that this exact readiness target is UP with a
successful HTTP 200 scrape. Evidence requests explicitly ignore inherited proxy
settings so bearer tokens cannot leave the private network boundary.

Unprivileged CI may render with `codestra/scripts/deploy_staging_runtime.py`;
that repository entrypoint does not offer deployment or collection. Privileged
operations use only the installed authority above. It recreates only the
Prometheus service, disables Compose `.env` loading, and rejects missing,
modified, symbolic, writable, or extra files in the deployment closure.

A root operator must prepare the protected source before running any repository
code:

```bash
install -d -o root -g root -m 0755 /opt/codestra-observability
install -d -o root -g root -m 0700 /opt/codestra-observability/prometheus-authority
/usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null /usr/bin/git clone --no-checkout https://github.com/appolon1908-hue/Codestra-Prometheus.git /opt/codestra-observability/prometheus-authority
/usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null /usr/bin/git -C /opt/codestra-observability/prometheus-authority checkout --detach <accepted-main-sha>
chown -R root:root /opt/codestra-observability/prometheus-authority
chmod -R go-w /opt/codestra-observability/prometheus-authority
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0555 /opt/codestra-observability/prometheus-authority/codestra/scripts/staging_runtime_authority_launcher.py /usr/local/libexec/codestra-prometheus-staging-authority.py
```

Do not invoke any repository Python before installing the external launcher.
The initial checkout is created inside the root-only empty directory using a
fixed canonical URL and sanitized Git environment. The launcher's subsequent
source checks use only a fresh private Git database, so committed or untracked
checkout-local configuration, hooks, filters, credential helpers, and URL
rewrites cannot participate. Privileged Git and Docker subprocesses use fixed
root-owned system paths, and Compose receives no inherited `HOME`,
`DOCKER_CONFIG`, `.env`, or executable search path.

Deployment mode requires a root-owned, root-group, mode-`0440`, single-link
client-secret file under fully root-owned non-writable ancestry. Prometheus runs
as `65534:0`, so it can read the group bit through the read-only secret mount
while UID 65534 cannot chmod, overwrite, or replace the validated host file. It
waits up to 120 seconds for the source-defined healthcheck and reports PASS only
after the container is healthy.

## Immutable runtime preflight

The Compose candidate no longer accepts one free-form image string. Each image is assembled as:

```text
IMAGE_REPOSITORY@sha256:IMAGE_DIGEST
```

Repository inputs must contain no tag or digest. Digest inputs must be exactly 64 lowercase hexadecimal characters. Every render, release packet, and deployment procedure must run the preflight against the exact environment file before invoking Compose:

```bash
python codestra/scripts/validate_runtime_images.py --env-file /run/codestra/prometheus.env
docker compose --env-file /run/codestra/prometheus.env -f codestra/compose.yaml config
```

A direct `docker compose up` that bypasses this preflight is not an approved Codestra deployment path. CI negative-tests mutable tags, embedded digests, uppercase hashes, short hashes, and non-digest values.

## Validation and rollout

```bash
python codestra/scripts/validate.py
python codestra/scripts/validate_runtime_images.py --env-file /run/codestra/prometheus.env
cd upstream && go build -o ../.bin/promtool ./cmd/promtool
../.bin/promtool check config ../codestra/prometheus/prometheus.yml
../.bin/promtool check rules ../codestra/prometheus/rules/*.yml
```

Deploy exporters first, then built-in service metrics, then application instrumentation. Verify all required targets, send a synthetic Alertmanager alert, remove it, and complete a 24-hour staging soak before production promotion. Never delete backlog rows or enable live delivery to clear an alert.
