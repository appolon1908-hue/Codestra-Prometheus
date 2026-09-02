#!/usr/bin/env python3
"""Render or deploy only the exact merged staging Prometheus authority."""

from __future__ import annotations

import argparse
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
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "DOCKER_CONFIG": "/nonexistent",
        "LC_ALL": "C",
        "PROMETHEUS_SOURCE_SHA": source_sha,
        "MIDDLEWARE_METRICS_CLIENT_SECRET_FILE": str(secret_file),
    }


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
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "DOCKER_CONFIG": "/nonexistent",
        "LC_ALL": "C",
        "PROMETHEUS_SOURCE_SHA": source_sha,
        "MIDDLEWARE_METRICS_CLIENT_SECRET_FILE": str(secret_file),
    }
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
        raise PreflightError("staging Prometheus deploy failed")
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
    print("SECCOMP_DISABLED=NO")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.TimeoutExpired, PreflightError) as exc:
        print(f"PROMETHEUS_STAGING_PREFLIGHT=FAIL: {exc}")
        raise SystemExit(1)
