#!/usr/bin/env python3
"""Render or deploy only the exact merged staging Prometheus authority."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
COMPOSE = REPO / "codestra" / "deploy" / "compose.staging.yaml"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
CANONICAL_REPOSITORY = "https://github.com/appolon1908-hue/Codestra-Prometheus.git"
CANONICAL_MAIN_REF = "refs/remotes/codestra-canonical/main"
GIT = "/usr/bin/git"
COMPOSE_BIN = "/usr/libexec/docker/cli-plugins/docker-compose"
DOCKER = "/usr/bin/docker"
CONTAINER_NAME = "codestra-prometheus-staging"
EXPECTED_NETWORKS = {
    "codestra-observability",
    "codestra-intake-observability-staging_private",
}
EXPECTED_IMAGE = (
    "prom/prometheus:v3.5.0@sha256:"
    "63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996"
)
EXPECTED_COMMAND = [
    "--config.file=/etc/prometheus/prometheus.yml",
    "--storage.tsdb.path=/prometheus",
    "--storage.tsdb.retention.time=30d",
    "--storage.tsdb.retention.size=40GB",
    "--web.listen-address=0.0.0.0:9090",
    "--web.enable-admin-api=false",
    "--web.enable-lifecycle=false",
    "--query.max-concurrency=20",
    "--query.timeout=2m",
]
EXPECTED_ENTRYPOINT = ["/bin/prometheus"]
FORBIDDEN_ROUTING_ENVIRONMENT_KEYS = {
    "ALL_PROXY",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "all_proxy",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "HOSTALIASES",
    "LOCALDOMAIN",
    "RES_OPTIONS",
}
EXPECTED_READONLY_BIND_MOUNTS = {
    "/etc/prometheus/prometheus.yml": REPO
    / "codestra/prometheus/prometheus-staging.yml",
    "/etc/prometheus/targets": REPO / "codestra/prometheus/targets",
    "/etc/prometheus/rules-staging/intake-recording-rules.yml": REPO
    / "codestra/prometheus/rules/intake-recording-rules.yml",
    "/etc/prometheus/rules-staging/intake-alerts.yml": REPO
    / "codestra/prometheus/rules/intake-alerts.yml",
}
RUNTIME_CONFIGURATION_PATHS = (
    COMPOSE,
    *EXPECTED_READONLY_BIND_MOUNTS.values(),
)
GIT_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/nonexistent",
    "XDG_CONFIG_HOME": "/nonexistent",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
    "LC_ALL": "C",
}


class PreflightError(RuntimeError):
    pass


def validate_deployment_identity() -> None:
    if os.geteuid() != 0:
        raise PreflightError(
            "staging Prometheus deployment must run as root so the root-owned "
            "credential can be validated without weakening its ownership"
        )


def validate_isolated_interpreter() -> None:
    """Require a startup mode that cannot import from the checkout."""

    if not sys.flags.isolated:
        raise PreflightError(
            "deployment must invoke /usr/bin/python3 with -I so imports cannot "
            "be resolved from the checkout before source protection is validated"
        )


def _validate_protected_path(path: Path, label: str, required_uid: int) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise PreflightError(f"{label} could not be inspected") from exc
    if stat.S_ISLNK(info.st_mode):
        raise PreflightError(f"{label} must not be a symbolic link")
    if info.st_uid != required_uid:
        raise PreflightError(f"{label} has the wrong owner")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise PreflightError(f"{label} must not be group- or other-writable")


def _validate_protected_tree(path: Path, label: str, required_uid: int) -> None:
    _validate_protected_path(path, label, required_uid)
    for directory, names, files in os.walk(path, followlinks=False):
        directory_path = Path(directory)
        _validate_protected_path(directory_path, label, required_uid)
        for name in (*names, *files):
            _validate_protected_path(directory_path / name, label, required_uid)


def validate_protected_checkout(
    repo: Path = REPO,
    *,
    required_uid: int = 0,
    ancestry_root: Path = Path("/"),
) -> None:
    """Reject deployment from source another host account can replace."""

    if not repo.is_absolute() or repo.is_symlink():
        raise PreflightError("deployment checkout must be an absolute non-symlink path")
    if not ancestry_root.is_absolute() or repo != ancestry_root:
        try:
            repo.relative_to(ancestry_root)
        except ValueError as exc:
            raise PreflightError("deployment checkout is outside protected ancestry") from exc
    current = repo
    while True:
        _validate_protected_path(
            current, "deployment checkout ancestry", required_uid
        )
        if current == ancestry_root:
            break
        if current == current.parent:
            raise PreflightError("protected ancestry root was not reached")
        current = current.parent

    git_directory = repo / ".git"
    if not git_directory.is_dir() or git_directory.is_symlink():
        raise PreflightError(
            "deployment checkout must be a standalone protected Git checkout"
        )
    _validate_protected_tree(
        git_directory, "deployment Git metadata", required_uid
    )
    _validate_protected_path(
        repo / "codestra",
        "deployment source parent",
        required_uid,
    )
    _validate_protected_tree(
        repo / "codestra" / "scripts",
        "deployment and collection scripts",
        required_uid,
    )
    _validate_protected_tree(
        repo / "codestra" / "deploy",
        "deployment Compose source",
        required_uid,
    )
    _validate_protected_tree(
        repo / "codestra" / "prometheus",
        "deployment Prometheus source",
        required_uid,
    )


def git_output(*args: str) -> str:
    result = subprocess.run(
        [GIT, *args],
        cwd=REPO,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
        env=GIT_ENVIRONMENT,
    )
    if result.returncode != 0:
        raise PreflightError("Git source identity could not be verified")
    return result.stdout.strip()


def validate_source(source_sha: str, *, require_merged: bool) -> None:
    if not SHA40.fullmatch(source_sha):
        raise PreflightError("source SHA must be exactly 40 lowercase hexadecimal characters")
    if git_output("rev-parse", "HEAD") != source_sha:
        raise PreflightError("source SHA does not match the checked-out exact head")
    if git_output("status", "--porcelain"):
        raise PreflightError("deployment checkout is not clean")
    if require_merged:
        refreshed = subprocess.run(
            [
                GIT,
                "fetch",
                "--quiet",
                "--no-tags",
                CANONICAL_REPOSITORY,
                f"+refs/heads/main:{CANONICAL_MAIN_REF}",
            ],
            cwd=REPO,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            env=GIT_ENVIRONMENT,
        )
        if refreshed.returncode != 0:
            raise PreflightError("canonical main branch could not be refreshed")
        merged = subprocess.run(
            [
                GIT,
                "merge-base",
                "--is-ancestor",
                source_sha,
                CANONICAL_MAIN_REF,
            ],
            cwd=REPO,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            env=GIT_ENVIRONMENT,
        )
        if merged.returncode != 0:
            raise PreflightError("source SHA is not merged into canonical main")


def validate_secret_ancestry(
    directory: Path,
    *,
    required_uid: int = 0,
    ancestry_root: Path = Path("/"),
) -> None:
    if not directory.is_absolute() or not ancestry_root.is_absolute():
        raise PreflightError("metrics client secret ancestry must be absolute")
    try:
        directory.relative_to(ancestry_root)
    except ValueError as exc:
        raise PreflightError(
            "metrics client secret is outside protected ancestry"
        ) from exc
    current = directory
    while True:
        _validate_protected_path(
            current,
            "metrics client secret ancestry",
            required_uid,
        )
        if not current.is_dir():
            raise PreflightError(
                "metrics client secret ancestry must contain only directories"
            )
        if current == ancestry_root:
            break
        if current == current.parent:
            raise PreflightError(
                "metrics client secret protected ancestry root was not reached"
            )
        current = current.parent


def validate_secret_file(
    path: Path,
    *,
    required_file_uid: int = 0,
    required_file_gid: int = 0,
    required_ancestry_uid: int = 0,
    ancestry_root: Path = Path("/"),
) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise PreflightError("metrics client secret must be an absolute non-symlink file")
    absolute = Path(os.path.abspath(path))
    resolved = path.resolve(strict=True)
    if absolute != resolved:
        raise PreflightError(
            "metrics client secret ancestry must not contain symbolic links"
        )
    validate_secret_ancestry(
        resolved.parent,
        required_uid=required_ancestry_uid,
        ancestry_root=ancestry_root,
    )
    info = resolved.stat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size < 16
        or info.st_size > 4096
    ):
        raise PreflightError("metrics client secret file is missing or malformed")
    if (info.st_uid, info.st_gid) != (required_file_uid, required_file_gid):
        raise PreflightError("metrics client secret has the wrong owner or group")
    if stat.S_IMODE(info.st_mode) != 0o440:
        raise PreflightError("metrics client secret mode must be 0440")
    descriptor = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise PreflightError("metrics client secret changed during validation")
        secret = stream.read(4097)
    normalized = secret.strip()
    if (
        secret != normalized
        or not 16 <= len(normalized) <= 4096
        or b"\x00" in normalized
    ):
        raise PreflightError("metrics client secret content is missing or malformed")
    return resolved


def compose_environment(source_sha: str, secret_file: Path) -> dict[str, str]:
    return {
        **docker_environment(),
        "PROMETHEUS_SOURCE_SHA": source_sha,
        "MIDDLEWARE_METRICS_CLIENT_SECRET_FILE": str(secret_file),
    }


def docker_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "DOCKER_CONFIG": "/nonexistent",
        "LC_ALL": "C",
    }


def _docker_inspect(environment: dict[str, str]) -> dict[str, object]:
    result = subprocess.run(
        [DOCKER, "inspect", "--type", "container", CONTAINER_NAME],
        cwd="/",
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=15,
    )
    if result.returncode != 0:
        raise PreflightError("deployed Prometheus container could not be inspected")
    try:
        documents = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PreflightError("deployed Prometheus inspection was malformed") from exc
    if not isinstance(documents, list) or len(documents) != 1:
        raise PreflightError("deployed Prometheus inspection was not singular")
    document = documents[0]
    if not isinstance(document, dict):
        raise PreflightError("deployed Prometheus inspection was malformed")
    return document


def _kernel_security_values(status: str) -> tuple[int, int, int]:
    parsed: dict[str, int] = {}
    for line in status.splitlines():
        key, separator, value = line.partition(":")
        if separator and key in {"NoNewPrivs", "Seccomp", "Seccomp_filters"}:
            if key in parsed:
                raise PreflightError("container kernel security status was malformed")
            try:
                parsed[key] = int(value.strip())
            except ValueError as exc:
                raise PreflightError("container kernel security status was malformed") from exc
    if set(parsed) != {"NoNewPrivs", "Seccomp", "Seccomp_filters"}:
        raise PreflightError("container kernel security status was incomplete")
    return parsed["NoNewPrivs"], parsed["Seccomp"], parsed["Seccomp_filters"]


def _read_process_status(pid: int) -> str:
    if pid <= 0:
        raise PreflightError("deployed Prometheus process ID was invalid")
    status_path = Path(f"/proc/{pid}/status")
    descriptor = os.open(status_path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        encoded = stream.read(65537)
    if not encoded or len(encoded) > 65536:
        raise PreflightError("container kernel security status was malformed")
    try:
        return encoded.decode("ascii")
    except UnicodeDecodeError as exc:
        raise PreflightError("container kernel security status was malformed") from exc


def _runtime_configuration_sha256() -> str:
    files: list[Path] = []
    for configured in RUNTIME_CONFIGURATION_PATHS:
        if configured.is_dir():
            files.extend(sorted(item for item in configured.rglob("*") if item.is_file()))
        else:
            files.append(configured)
    digest = hashlib.sha256()
    for path in sorted(set(files)):
        if path.is_symlink() or not path.is_file():
            raise PreflightError("Prometheus runtime configuration source is invalid")
        try:
            relative = path.relative_to(REPO).as_posix()
        except ValueError as exc:
            raise PreflightError(
                "Prometheus runtime configuration escaped the protected checkout"
            ) from exc
        encoded = path.read_bytes()
        if len(encoded) > 8 * 1024 * 1024:
            raise PreflightError("Prometheus runtime configuration source is oversized")
        if relative == "codestra/prometheus/targets/staging.json":
            try:
                normalized = json.loads(encoded)
                normalized[0]["labels"]["activation"] = "normalized-for-runtime-hash"
                encoded = json.dumps(
                    normalized,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            except (UnicodeDecodeError, json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
                raise PreflightError(
                    "Prometheus staging target configuration was malformed"
                ) from exc
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(encoded).digest())
    return "sha256:" + digest.hexdigest()


def _validate_runtime_mounts(document: dict[str, object]) -> str:
    mounts = document.get("Mounts")
    if not isinstance(mounts, list) or not all(isinstance(item, dict) for item in mounts):
        raise PreflightError("deployed Prometheus mounts were malformed")
    by_destination = {item.get("Destination"): item for item in mounts}
    expected_destinations = {
        *EXPECTED_READONLY_BIND_MOUNTS,
        "/prometheus",
        "/run/secrets/middleware-staging-monitoring-client-secret",
    }
    if len(by_destination) != len(mounts) or set(by_destination) != expected_destinations:
        raise PreflightError("deployed Prometheus mount destinations were not exact")
    for destination, source in EXPECTED_READONLY_BIND_MOUNTS.items():
        mount = by_destination[destination]
        if (
            mount.get("Type") != "bind"
            or mount.get("RW") is not False
            or mount.get("Source") != str(source.resolve(strict=True))
        ):
            raise PreflightError("deployed Prometheus configuration mount was not exact")
    data = by_destination["/prometheus"]
    if (
        data.get("Type") != "volume"
        or data.get("Name") != "codestra-prometheus-staging_prometheus_staging_data"
        or data.get("RW") is not True
    ):
        raise PreflightError("deployed Prometheus data mount was not exact")
    secret = by_destination[
        "/run/secrets/middleware-staging-monitoring-client-secret"
    ]
    secret_source = secret.get("Source")
    if (
        secret.get("Type") != "bind"
        or secret.get("RW") is not False
        or not isinstance(secret_source, str)
        or not Path(secret_source).is_absolute()
    ):
        raise PreflightError("deployed Prometheus secret mount was not protected")
    return _runtime_configuration_sha256()


def _validate_runtime_routing_controls(
    host_config: dict[str, object],
    config: dict[str, object],
) -> None:
    """Reject container-local target-routing overrides before evidence is signed."""

    for key in ("ExtraHosts", "Dns", "DnsOptions", "DnsSearch", "Links"):
        value = host_config.get(key)
        if value not in (None, [], {}):
            raise PreflightError(
                "deployed Prometheus contains host or DNS routing overrides"
            )
    environment = config.get("Env")
    if environment is None:
        return
    if not isinstance(environment, list) or not all(
        isinstance(item, str) for item in environment
    ):
        raise PreflightError("deployed Prometheus environment was malformed")
    names = {item.partition("=")[0] for item in environment}
    if names & FORBIDDEN_ROUTING_ENVIRONMENT_KEYS:
        raise PreflightError(
            "deployed Prometheus contains proxy or name-resolution overrides"
        )


def validate_running_container_security(
    source_sha: str,
    environment: dict[str, str],
) -> dict[str, object]:
    before = _docker_inspect(environment)
    container_id = before.get("Id")
    state = before.get("State")
    host_config = before.get("HostConfig")
    network_settings = before.get("NetworkSettings")
    config = before.get("Config")
    if (
        not isinstance(container_id, str)
        or not re.fullmatch(r"[0-9a-f]{64}", container_id)
        or not isinstance(state, dict)
        or state.get("Running") is not True
        or type(state.get("Pid")) is not int
        or not isinstance(state.get("StartedAt"), str)
        or not state.get("StartedAt")
        or not isinstance(host_config, dict)
        or not isinstance(network_settings, dict)
        or not isinstance(config, dict)
    ):
        raise PreflightError("deployed Prometheus identity or state was invalid")
    labels = config.get("Labels")
    if (
        not isinstance(labels, dict)
        or labels.get("com.codestra.source.sha") != source_sha
        or labels.get("com.codestra.source.repository")
        != "appolon1908-hue/Codestra-Prometheus"
        or labels.get("com.codestra.environment") != "staging"
        or labels.get("com.codestra.service") != "prometheus"
        or labels.get("com.docker.compose.project")
        != "codestra-prometheus-staging"
        or labels.get("com.docker.compose.service") != "prometheus-staging"
        or labels.get("com.docker.compose.oneoff") != "False"
    ):
        raise PreflightError("deployed Prometheus source label did not match")
    if config.get("Image") != EXPECTED_IMAGE:
        raise PreflightError("deployed Prometheus image did not match")
    if (
        config.get("User") != "65534:0"
        or config.get("Entrypoint") != EXPECTED_ENTRYPOINT
        or config.get("Cmd") != EXPECTED_COMMAND
        or config.get("ExposedPorts") != {"9090/tcp": {}}
        or not isinstance(config.get("Healthcheck"), dict)
        or config["Healthcheck"].get("Test")
        != ["CMD", "/bin/promtool", "check", "healthy"]
        or host_config.get("ReadonlyRootfs") is not True
        or host_config.get("CapDrop") != ["ALL"]
        or host_config.get("Privileged") is not False
        or host_config.get("PidsLimit") != 256
        or host_config.get("Init") is not True
        or host_config.get("PublishAllPorts") is not False
        or (host_config.get("PortBindings") or {}) != {}
    ):
        raise PreflightError("deployed Prometheus runtime configuration was not exact")
    _validate_runtime_routing_controls(host_config, config)
    security_options = host_config.get("SecurityOpt")
    if (
        not isinstance(security_options, list)
        or "no-new-privileges:true" not in security_options
        or any("seccomp=unconfined" in str(item).lower() for item in security_options)
    ):
        raise PreflightError("deployed Prometheus security options were unsafe")
    networks = network_settings.get("Networks")
    if not isinstance(networks, dict) or set(networks) != EXPECTED_NETWORKS:
        raise PreflightError("deployed Prometheus network attachment was not exact")
    published_ports = network_settings.get("Ports")
    if (
        not isinstance(published_ports, dict)
        or any(value is not None for value in published_ports.values())
    ):
        raise PreflightError("deployed Prometheus publishes a host port")
    network_addresses: dict[str, str] = {}
    for name in sorted(EXPECTED_NETWORKS):
        detail = networks[name]
        address = detail.get("IPAddress") if isinstance(detail, dict) else None
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError as exc:
            raise PreflightError("deployed Prometheus network address was invalid") from exc
        if (
            parsed_address.version != 4
            or not parsed_address.is_private
            or parsed_address.is_loopback
            or parsed_address.is_link_local
        ):
            raise PreflightError("deployed Prometheus network address was not private")
        network_addresses[name] = str(parsed_address)
    configuration_sha256 = _validate_runtime_mounts(before)

    pid = state["Pid"]
    started_at = state["StartedAt"]
    no_new_privileges, seccomp_mode, seccomp_filters = _kernel_security_values(
        _read_process_status(pid)
    )
    if no_new_privileges != 1 or seccomp_mode != 2 or seccomp_filters < 1:
        raise PreflightError(
            "deployed Prometheus process does not have no-new-privileges and "
            "filter-mode seccomp enforced"
        )

    after = _docker_inspect(environment)
    after_state = after.get("State")
    after_network_settings = after.get("NetworkSettings")
    after_networks = (
        after_network_settings.get("Networks")
        if isinstance(after_network_settings, dict)
        else None
    )
    if (
        after.get("Id") != container_id
        or not isinstance(after_state, dict)
        or after_state.get("Running") is not True
        or after_state.get("Pid") != pid
        or after_state.get("StartedAt") != started_at
        or not isinstance(after_networks, dict)
        or set(after_networks) != EXPECTED_NETWORKS
    ):
        raise PreflightError("deployed Prometheus changed during security verification")
    for name, address in network_addresses.items():
        after_detail = after_networks[name]
        if not isinstance(after_detail, dict) or after_detail.get("IPAddress") != address:
            raise PreflightError("deployed Prometheus address changed during verification")
    if _validate_runtime_mounts(after) != configuration_sha256:
        raise PreflightError("deployed Prometheus mounts changed during verification")
    return {
        "schema_version": "1.0",
        "container_identity_sha256": "sha256:"
        + hashlib.sha256(container_id.encode("ascii")).hexdigest(),
        "process_identity_sha256": "sha256:"
        + hashlib.sha256(
            f"{container_id}\0{pid}\0{started_at}".encode("utf-8")
        ).hexdigest(),
        "source_sha": source_sha,
        "image_digest": EXPECTED_IMAGE.rsplit("@", 1)[1],
        "runtime_configuration_sha256": configuration_sha256,
        "no_new_privileges": True,
        "seccomp_mode": "filter",
        "seccomp_filters": seccomp_filters,
        "networks": sorted(EXPECTED_NETWORKS),
        "network_addresses": network_addresses,
    }


def remove_failed_prometheus(environment: dict[str, str]) -> bool:
    result = subprocess.run(
        [
            COMPOSE_BIN,
            "--env-file",
            "/dev/null",
            "-f",
            str(COMPOSE),
            "rm",
            "--stop",
            "--force",
            "prometheus-staging",
        ],
        cwd=REPO,
        env=environment,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=60,
    )
    return result.returncode == 0


def render(source_sha: str, secret_file: Path) -> None:
    result = subprocess.run(
        [
            COMPOSE_BIN,
            "--env-file",
            "/dev/null",
            "-f",
            str(COMPOSE),
            "config",
            "--quiet",
        ],
        cwd=REPO,
        env=compose_environment(source_sha, secret_file),
        check=False,
        timeout=180,
    )
    if result.returncode != 0:
        raise PreflightError("staging Prometheus render failed")


def run_deploy_from_trusted_launcher(source_sha: str, argv: list[str]) -> int:
    """Deploy after the external authority verified these exact module bytes."""

    validate_isolated_interpreter()
    validate_deployment_identity()
    if not SHA40.fullmatch(source_sha):
        raise PreflightError(
            "source SHA must be exactly 40 lowercase hexadecimal characters"
        )
    parser = argparse.ArgumentParser()
    parser.add_argument("--secret-file", type=Path, required=True)
    args = parser.parse_args(argv)
    secret_file = validate_secret_file(args.secret_file)
    environment = compose_environment(source_sha, secret_file)
    result = subprocess.run(
        [
            COMPOSE_BIN,
            "--env-file",
            "/dev/null",
            "-f",
            str(COMPOSE),
            "up",
            "-d",
            "--no-deps",
            "--force-recreate",
            "--wait",
            "--wait-timeout",
            "120",
            "prometheus-staging",
        ],
        cwd=REPO,
        env=environment,
        check=False,
        timeout=180,
    )
    if result.returncode != 0:
        if not remove_failed_prometheus(environment):
            raise PreflightError(
                "staging Prometheus deploy failed and isolated service cleanup failed"
            )
        raise PreflightError("staging Prometheus deploy failed")
    try:
        validate_running_container_security(source_sha, environment)
    except (OSError, subprocess.TimeoutExpired, PreflightError) as exc:
        if not remove_failed_prometheus(environment):
            raise PreflightError(
                "Prometheus runtime security verification failed and isolated "
                "service cleanup also failed"
            ) from exc
        raise
    print("PROMETHEUS_SECCOMP=PASS")
    print("SECCOMP_DISABLED=NO")
    print("PROMETHEUS_STAGING_NETWORK=PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("render",), required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--secret-file", type=Path, required=True)
    args = parser.parse_args()
    validate_source(args.source_sha, require_merged=False)
    render(args.source_sha, args.secret_file)
    print("PROMETHEUS_STAGING_RENDER=PASS")
    print(f"PROMETHEUS_SOURCE_SHA={args.source_sha}")
    print("SECCOMP_RUNTIME_CHECK=NOT_RUN")
    print("SECCOMP_UNCONFINED_CONFIGURED=NO")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.TimeoutExpired, PreflightError) as exc:
        print(f"PROMETHEUS_STAGING_PREFLIGHT=FAIL: {exc}")
        raise SystemExit(1)
