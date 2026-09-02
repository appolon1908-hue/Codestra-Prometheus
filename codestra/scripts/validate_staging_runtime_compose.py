#!/usr/bin/env python3
"""Validate the dedicated staging Prometheus runtime authority."""

from __future__ import annotations

import inspect
import os
import re
import tempfile
from pathlib import Path

import yaml

from deploy_staging_runtime import (
    PreflightError,
    _kernel_security_values,
    validate_deployment_identity,
    validate_isolated_interpreter,
    validate_protected_checkout,
    validate_secret_file,
)


CODESTRA = Path(__file__).resolve().parents[1]
COMPOSE = CODESTRA / "deploy" / "compose.staging.yaml"
PROMETHEUS_CONFIG = CODESTRA / "prometheus" / "prometheus-staging.yml"
SERVICE_CATALOG = CODESTRA / "catalog" / "services.yml"
STAGING_RULES = {
    "/etc/prometheus/rules-staging/intake-recording-rules.yml": (
        CODESTRA / "prometheus" / "rules" / "intake-recording-rules.yml"
    ),
    "/etc/prometheus/rules-staging/intake-alerts.yml": (
        CODESTRA / "prometheus" / "rules" / "intake-alerts.yml"
    ),
}
IMAGE = (
    "prom/prometheus:v3.5.0@sha256:"
    "63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996"
)


def main() -> None:
    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    assert document["name"] == "codestra-prometheus-staging"
    assert set(document["services"]) == {"prometheus-staging"}
    service = document["services"]["prometheus-staging"]
    assert service["image"] == IMAGE
    assert service["container_name"] == "codestra-prometheus-staging"
    assert service["init"] is True
    assert service["user"] == "65534:0"
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service.get("privileged") in {None, False}
    assert "ports" not in service
    assert service["expose"] == ["9090"]
    assert set(service["networks"]) == {
        "codestra_observability",
        "middleware_staging",
    }
    assert service["networks"]["codestra_observability"]["aliases"] == [
        "prometheus-staging"
    ]
    assert service["healthcheck"]["test"] == [
        "CMD",
        "/bin/promtool",
        "check",
        "healthy",
    ]
    prometheus_config = yaml.safe_load(
        PROMETHEUS_CONFIG.read_text(encoding="utf-8")
    )
    assert prometheus_config["rule_files"] == list(STAGING_RULES)
    alertmanagers = prometheus_config["alerting"]["alertmanagers"]
    assert alertmanagers == [
        {
            "scheme": "http",
            "timeout": "10s",
            "static_configs": [{"targets": ["alertmanager:9093"]}],
        }
    ]
    catalog = yaml.safe_load(SERVICE_CATALOG.read_text(encoding="utf-8"))
    assert catalog["authorities"]["alert_routing"] == (
        "appolon1908-hue/Codestra-Alertmanager"
    )
    approved_alertmanagers = [
        item
        for item in catalog["infrastructure_services"]
        if item["repo"] == "appolon1908-hue/Codestra-Alertmanager"
    ]
    assert approved_alertmanagers == [
        {
            "repo": "appolon1908-hue/Codestra-Alertmanager",
            "codestra_business": "platform",
            "application": "observability",
            "service": "alertmanager",
            "endpoint": "alertmanager:9093",
            "path": "/metrics",
            "activation": "active",
        }
    ]
    volumes = set(service["volumes"])
    for mounted, source in STAGING_RULES.items():
        relative = source.relative_to(CODESTRA)
        assert f"../{relative}:{mounted}:ro" in volumes
        rule_text = source.read_text(encoding="utf-8")
        assert "production" not in rule_text.lower()
        assert yaml.safe_load(rule_text)["groups"]
    assert service["secrets"] == [
        {
            "source": "middleware_staging_monitoring_client_secret",
            "target": "middleware-staging-monitoring-client-secret",
            "mode": 0o440,
        }
    ]
    assert not any(
        "seccomp=unconfined" in str(value).lower()
        for value in service["security_opt"]
    )
    assert document["networks"] == {
        "codestra_observability": {
            "external": True,
            "name": "codestra-observability",
        },
        "middleware_staging": {
            "external": True,
            "name": "codestra-intake-observability-staging_private",
        },
    }
    assert service["labels"]["com.codestra.source.sha"] == (
        "${PROMETHEUS_SOURCE_SHA:?exact merged source SHA is required}"
    )
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", IMAGE.rsplit("@", 1)[1])
    text = COMPOSE.read_text(encoding="utf-8").lower()
    assert "seccomp=unconfined" not in text
    assert "privileged: true" not in text
    assert "klyrow" not in text
    assert "postal" not in text
    deployer = (CODESTRA / "scripts" / "deploy_staging_runtime.py").read_text(
        encoding="utf-8"
    )
    authority = (
        CODESTRA / "scripts" / "staging_runtime_authority_launcher.py"
    ).read_text(encoding="utf-8")
    for required in (
        'SHA40 = re.compile(r"^[0-9a-f]{40}$")',
        'git_output("rev-parse", "HEAD") != source_sha',
        'CANONICAL_REPOSITORY = "https://github.com/appolon1908-hue/Codestra-Prometheus.git"',
        'CANONICAL_MAIN_REF = "refs/remotes/codestra-canonical/main"',
        'f"+refs/heads/main:{CANONICAL_MAIN_REF}"',
        '"merge-base",',
        'GIT = "/usr/bin/git"',
        'COMPOSE_BIN = "/usr/libexec/docker/cli-plugins/docker-compose"',
        'DOCKER = "/usr/bin/docker"',
        'CONTAINER_NAME = "codestra-prometheus-staging"',
        "[GIT, *args]",
        '"--env-file",',
        '"/dev/null",',
        '"GIT_CONFIG_NOSYSTEM": "1"',
        '"GIT_CONFIG_GLOBAL": "/dev/null"',
        '"DOCKER_CONFIG": "/nonexistent"',
        "secret != normalized",
        "not 16 <= len(normalized) <= 4096",
        'b"\\x00" in normalized',
        "os.O_NOFOLLOW",
        '"--force-recreate"',
        '"--wait-timeout"',
        '"prometheus-staging"',
        '"NoNewPrivs", "Seccomp", "Seccomp_filters"',
        'seccomp_mode != 2',
        'seccomp_filters < 1',
        '"no-new-privileges:true" not in security_options',
        'set(networks) != EXPECTED_NETWORKS',
        'validate_running_container_security(source_sha, environment)',
        'remove_failed_prometheus(environment)',
        'print("PROMETHEUS_SECCOMP=PASS")',
        'print("PROMETHEUS_STAGING_NETWORK=PASS")',
        'repo / "codestra" / "scripts",',
        '"deployment and collection scripts"',
        'choices=("render",)',
        "run_deploy_from_trusted_launcher",
    ):
        assert required in deployer
    assert "os.environ.copy()" not in deployer
    assert _kernel_security_values(
        "Name:\tprometheus\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n"
    ) == (1, 2, 1)
    try:
        _kernel_security_values("NoNewPrivs:\t1\nSeccomp:\t2\n")
    except PreflightError:
        pass
    else:
        raise AssertionError("incomplete kernel security status was accepted")
    secret_parameters = inspect.signature(validate_secret_file).parameters
    assert secret_parameters["required_file_uid"].default == 0
    assert secret_parameters["required_file_gid"].default == 0
    for required in (
        'INSTALLED_LAUNCHER = Path(',
        '"/usr/local/libexec/codestra-prometheus-staging-authority.py"',
        'CHECKOUT = Path("/opt/codestra-observability/prometheus-authority")',
        'CANONICAL_REPOSITORY = (',
        '"GIT_CONFIG_SYSTEM": "/dev/null"',
        '"GIT_CONFIG_GLOBAL": "/dev/null"',
        '"GIT_CONFIG_NOSYSTEM": "1"',
        'cwd="/"',
        'f"--git-dir={git_directory}"',
        '"empty-git-template"',
        '"merge-base",',
        '"--is-ancestor",',
        "read_protected_source(launcher",
        "actual_prefix_files(checkout)",
        "load_verified_module(",
        "wrapper.collector = base",
        "DEPLOYER_SOURCE, *COLLECTOR_SOURCES",
        "verify_runtime_security",
        "deployer.validate_running_container_security(",
        "deployer.docker_environment()",
        "run_deploy_from_trusted_launcher",
    ):
        assert required in authority, required
    assert "cwd=CHECKOUT" not in authority
    assert 'cwd=REPO' not in authority
    assert "os.environ.copy()" not in authority
    with tempfile.TemporaryDirectory() as temporary:
        protected_root = Path(temporary)
        secret_directory = protected_root / "secrets"
        secret_directory.mkdir()
        secret = secret_directory / "client-secret"
        secret.write_bytes(b"A" * 32)
        secret.chmod(0o440)
        validation_options = {
            "required_file_uid": os.geteuid(),
            "required_file_gid": os.getegid(),
            "required_ancestry_uid": os.geteuid(),
            "ancestry_root": protected_root,
        }
        validate_secret_file(secret, **validation_options)
        secret.chmod(0o640)
        try:
            validate_secret_file(secret, **validation_options)
        except PreflightError:
            pass
        else:
            raise AssertionError("writable client-secret leaf was accepted")
        secret.chmod(0o440)
        symbolic_directory = protected_root / "symbolic-secrets"
        symbolic_directory.symlink_to(secret_directory)
        try:
            validate_secret_file(
                symbolic_directory / secret.name,
                **validation_options,
            )
        except PreflightError:
            pass
        else:
            raise AssertionError("symbolic client-secret ancestry was accepted")
    with tempfile.TemporaryDirectory() as temporary:
        protected = Path(temporary) / "authority"
        (protected / ".git").mkdir(parents=True)
        (protected / "codestra" / "scripts").mkdir(parents=True)
        (protected / "codestra" / "scripts" / "deploy_staging_runtime.py").write_text(
            "# test\n"
        )
        deploy_source = protected / "codestra" / "deploy"
        deploy_source.mkdir()
        (deploy_source / "compose.staging.yaml").write_text("services: {}\n")
        prometheus_source = protected / "codestra" / "prometheus"
        prometheus_source.mkdir()
        (prometheus_source / "prometheus-staging.yml").write_text("global: {}\n")
        validate_protected_checkout(
            protected,
            required_uid=os.geteuid(),
            ancestry_root=Path(temporary),
        )
        (protected / "codestra" / "scripts").chmod(0o777)
        try:
            validate_protected_checkout(
                protected,
                required_uid=os.geteuid(),
                ancestry_root=Path(temporary),
            )
        except PreflightError:
            pass
        else:
            raise AssertionError("writable entrypoint parent was accepted")
        (protected / "codestra" / "scripts").chmod(0o755)
        (deploy_source / "compose.staging.yaml").chmod(0o666)
        try:
            validate_protected_checkout(
                protected,
                required_uid=os.geteuid(),
                ancestry_root=Path(temporary),
            )
        except PreflightError:
            pass
        else:
            raise AssertionError("writable deployment source was accepted")
        (deploy_source / "compose.staging.yaml").chmod(0o644)
        (prometheus_source / "escape").symlink_to("/tmp")
        try:
            validate_protected_checkout(
                protected,
                required_uid=os.geteuid(),
                ancestry_root=Path(temporary),
            )
        except PreflightError:
            pass
        else:
            raise AssertionError("symlinked deployment source was accepted")
    if os.geteuid() != 0:
        try:
            validate_deployment_identity()
        except PreflightError:
            pass
        else:
            raise AssertionError("non-root deployment authority was accepted")
    if not __import__("sys").flags.isolated:
        try:
            validate_isolated_interpreter()
        except PreflightError:
            pass
        else:
            raise AssertionError("non-isolated deployment interpreter was accepted")
    print("PROMETHEUS_STAGING_RUNTIME_SOURCE=PASS")
    print("SECCOMP_UNCONFINED_CONFIGURED=NO")


if __name__ == "__main__":
    main()
