#!/usr/bin/env python3
"""Externally installed source authority for privileged staging operations.

This file is installed at a fixed root-protected path before use. It never
executes repository code or reads checkout-local Git metadata. Instead it
fetches canonical main into a fresh private bare repository, verifies the
requested merged commit and exact execution-closure bytes, then compiles those
already-verified bytes under isolated Python.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import sys
import tempfile
import types
from pathlib import Path
from typing import Any


INSTALLED_LAUNCHER = Path(
    "/usr/local/libexec/codestra-prometheus-staging-authority.py"
)
CHECKOUT = Path("/opt/codestra-observability/prometheus-authority")
CANONICAL_REPOSITORY = (
    "https://github.com/appolon1908-hue/Codestra-Prometheus.git"
)
CANONICAL_MAIN_REF = "refs/codestra/canonical-main"
GIT = "/usr/bin/git"
PYTHON = "/usr/bin/python3"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
MAX_SOURCE_FILE_BYTES = 8 * 1024 * 1024
LAUNCHER_SOURCE = "codestra/scripts/staging_runtime_authority_launcher.py"
DEPLOYER_SOURCE = "codestra/scripts/deploy_staging_runtime.py"
COLLECTOR_SOURCES = (
    "codestra/scripts/collect_staging_intake_evidence.py",
    "codestra/scripts/collect_staging_intake_evidence_v2.py",
    "codestra/prometheus/targets/staging.json",
    "integration/staging-activation-contract-v1.json",
)
DEPLOYMENT_SOURCE_PREFIXES = (
    "codestra/deploy",
    "codestra/prometheus",
)
GIT_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/nonexistent",
    "XDG_CONFIG_HOME": "/nonexistent",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
    "LC_ALL": "C",
}


class AuthorityError(RuntimeError):
    pass


def _protected_metadata(
    path: Path,
    label: str,
    *,
    directory: bool | None = None,
) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AuthorityError(f"{label} could not be inspected") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise AuthorityError(f"{label} must not be symbolic")
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise AuthorityError(f"{label} must be root-owned and non-writable")
    if directory is True and not stat.S_ISDIR(metadata.st_mode):
        raise AuthorityError(f"{label} must be a directory")
    if directory is False and not stat.S_ISREG(metadata.st_mode):
        raise AuthorityError(f"{label} must be a regular file")
    return metadata


def validate_protected_ancestry(path: Path, label: str) -> None:
    if not path.is_absolute():
        raise AuthorityError(f"{label} must be absolute")
    current = path
    while True:
        _protected_metadata(current, f"{label} ancestry", directory=True)
        if current == current.parent:
            break
        current = current.parent


def validate_launcher_identity(
    launcher: Path = INSTALLED_LAUNCHER,
    checkout: Path = CHECKOUT,
) -> None:
    invoked = Path(os.path.abspath(__file__))
    if launcher == INSTALLED_LAUNCHER and invoked != launcher:
        raise AuthorityError("invoke the separately installed staging source authority")
    if invoked != invoked.resolve(strict=True):
        raise AuthorityError("installed staging source authority must not be symbolic")
    if os.geteuid() != 0:
        raise AuthorityError("staging source authority must run as root")
    if not sys.flags.isolated:
        raise AuthorityError("staging source authority requires /usr/bin/python3 -I")
    validate_protected_ancestry(launcher.parent, "installed launcher")
    launcher_metadata = _protected_metadata(
        launcher,
        "installed launcher",
        directory=False,
    )
    if launcher_metadata.st_nlink != 1:
        raise AuthorityError("installed launcher must have exactly one link")
    if checkout != CHECKOUT:
        raise AuthorityError("staging checkout must use the fixed authority path")
    validate_protected_ancestry(checkout, "staging checkout")


def trusted_git(
    git_directory: Path,
    *arguments: str,
    input_bytes: bytes | None = None,
    timeout: int = 30,
) -> bytes:
    result = subprocess.run(
        [GIT, f"--git-dir={git_directory}", *arguments],
        cwd="/",
        env=GIT_ENVIRONMENT,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise AuthorityError("canonical Git source verification failed")
    return result.stdout


def initialize_canonical_authority(root: Path, source_sha: str) -> Path:
    if not SHA40.fullmatch(source_sha):
        raise AuthorityError(
            "source SHA must be exactly 40 lowercase hexadecimal characters"
        )
    template = root / "empty-git-template"
    git_directory = root / "canonical.git"
    template.mkdir(mode=0o700)
    initialized = subprocess.run(
        [GIT, "init", "--bare", "--quiet", f"--template={template}", git_directory],
        cwd="/",
        env=GIT_ENVIRONMENT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=15,
    )
    if initialized.returncode != 0:
        raise AuthorityError("private canonical Git authority could not be initialized")
    trusted_git(
        git_directory,
        "fetch",
        "--quiet",
        "--no-tags",
        CANONICAL_REPOSITORY,
        f"+refs/heads/main:{CANONICAL_MAIN_REF}",
        timeout=60,
    )
    canonical_head = trusted_git(
        git_directory,
        "rev-parse",
        "--verify",
        CANONICAL_MAIN_REF,
    ).decode("ascii").strip()
    if not SHA40.fullmatch(canonical_head):
        raise AuthorityError("canonical main did not resolve to an exact commit")
    trusted_git(
        git_directory,
        "rev-parse",
        "--verify",
        f"{source_sha}^{{commit}}",
    )
    trusted_git(
        git_directory,
        "merge-base",
        "--is-ancestor",
        source_sha,
        CANONICAL_MAIN_REF,
    )
    return git_directory


def canonical_paths(git_directory: Path, source_sha: str, mode: str) -> tuple[str, ...]:
    if mode == "collect":
        return tuple(sorted({LAUNCHER_SOURCE, *COLLECTOR_SOURCES}))
    if mode != "deploy":
        raise AuthorityError("unsupported privileged staging mode")
    encoded = trusted_git(
        git_directory,
        "ls-tree",
        "-r",
        "-z",
        "--name-only",
        source_sha,
        "--",
        *DEPLOYMENT_SOURCE_PREFIXES,
    )
    try:
        discovered = {
            item.decode("utf-8") for item in encoded.split(b"\0") if item
        }
    except UnicodeDecodeError as exc:
        raise AuthorityError("canonical source contains a non-UTF-8 path") from exc
    paths = discovered | {LAUNCHER_SOURCE, DEPLOYER_SOURCE}
    for relative in paths:
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise AuthorityError("canonical source contains an unsafe path")
    if not discovered:
        raise AuthorityError("canonical deployment source closure is empty")
    return tuple(sorted(paths))


def canonical_blob(git_directory: Path, source_sha: str, relative: str) -> bytes:
    encoded = trusted_git(
        git_directory,
        "cat-file",
        "blob",
        f"{source_sha}:{relative}",
    )
    if len(encoded) > MAX_SOURCE_FILE_BYTES:
        raise AuthorityError("canonical source file exceeds the size limit")
    return encoded


def read_protected_source(path: Path, label: str) -> bytes:
    validate_protected_ancestry(path.parent, label)
    before = _protected_metadata(path, label, directory=False)
    if before.st_nlink != 1 or before.st_size > MAX_SOURCE_FILE_BYTES:
        raise AuthorityError(f"{label} has an invalid link count or size")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise AuthorityError(f"{label} changed during validation")
        encoded = stream.read(MAX_SOURCE_FILE_BYTES + 1)
    if len(encoded) > MAX_SOURCE_FILE_BYTES:
        raise AuthorityError(f"{label} exceeds the size limit")
    return encoded


def actual_prefix_files(checkout: Path) -> set[str]:
    files: set[str] = set()
    for prefix in DEPLOYMENT_SOURCE_PREFIXES:
        root = checkout / prefix
        _protected_metadata(root, "deployment source directory", directory=True)
        for directory, names, filenames in os.walk(root, followlinks=False):
            directory_path = Path(directory)
            _protected_metadata(
                directory_path,
                "deployment source directory",
                directory=True,
            )
            for name in names:
                _protected_metadata(
                    directory_path / name,
                    "deployment source directory",
                    directory=True,
                )
            for name in filenames:
                source = directory_path / name
                _protected_metadata(source, "deployment source file", directory=False)
                files.add(source.relative_to(checkout).as_posix())
    return files


def verify_execution_closure(
    git_directory: Path,
    source_sha: str,
    mode: str,
    checkout: Path = CHECKOUT,
    launcher: Path = INSTALLED_LAUNCHER,
) -> dict[str, bytes]:
    paths = canonical_paths(git_directory, source_sha, mode)
    expected = {
        relative: canonical_blob(git_directory, source_sha, relative)
        for relative in paths
    }
    if read_protected_source(launcher, "installed launcher") != expected[LAUNCHER_SOURCE]:
        raise AuthorityError("installed launcher does not match canonical source")
    if mode == "deploy":
        expected_runtime_files = {
            relative
            for relative in paths
            if relative.startswith(DEPLOYMENT_SOURCE_PREFIXES)
        }
        if actual_prefix_files(checkout) != expected_runtime_files:
            raise AuthorityError("deployment source tree differs from canonical authority")
    verified: dict[str, bytes] = {}
    for relative, canonical in expected.items():
        if relative == LAUNCHER_SOURCE:
            continue
        actual = read_protected_source(
            checkout / relative,
            f"staging source {relative}",
        )
        if actual != canonical:
            raise AuthorityError(f"staging source differs from canonical authority: {relative}")
        verified[relative] = actual
    return verified


def load_verified_module(name: str, path: Path, encoded: bytes) -> Any:
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    exec(compile(encoded, str(path), "exec"), module.__dict__)
    return module


def dispatch(
    mode: str,
    source_sha: str,
    operation_args: list[str],
    verified: dict[str, bytes],
    checkout: Path = CHECKOUT,
) -> int:
    if mode == "deploy":
        deployer = load_verified_module(
            "codestra_verified_prometheus_deployer",
            checkout / DEPLOYER_SOURCE,
            verified[DEPLOYER_SOURCE],
        )
        try:
            return deployer.run_deploy_from_trusted_launcher(
                source_sha,
                operation_args,
            )
        except (
            deployer.PreflightError,
            OSError,
            subprocess.TimeoutExpired,
        ) as exc:
            print(f"PROMETHEUS_STAGING_DEPLOY=FAIL: {exc}", file=sys.stderr)
            return 1
    base_path = checkout / COLLECTOR_SOURCES[0]
    wrapper_path = checkout / COLLECTOR_SOURCES[1]
    base = load_verified_module(
        "codestra_verified_staging_evidence_collector",
        base_path,
        verified[COLLECTOR_SOURCES[0]],
    )
    wrapper = load_verified_module(
        "codestra_verified_staging_evidence_wrapper",
        wrapper_path,
        verified[COLLECTOR_SOURCES[1]],
    )
    wrapper.collector = base
    return wrapper.run_from_trusted_launcher(operation_args)


def parse_args(argv: list[str]) -> tuple[argparse.Namespace, list[str]]:
    if "--" not in argv:
        raise AuthorityError("privileged operation arguments require a standalone --")
    separator = argv.index("--")
    authority_args = argv[:separator]
    operation_args = argv[separator + 1 :]
    if not operation_args:
        raise AuthorityError("privileged operation arguments are missing")
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("deploy", "collect"), required=True)
    parser.add_argument("--source-sha", required=True)
    return parser.parse_args(authority_args), operation_args


def main() -> int:
    validate_launcher_identity()
    args, operation_args = parse_args(sys.argv[1:])
    with tempfile.TemporaryDirectory(
        prefix="codestra-prometheus-source-authority-",
        dir="/run",
    ) as temporary:
        authority_root = Path(temporary)
        os.chmod(authority_root, 0o700)
        git_directory = initialize_canonical_authority(
            authority_root,
            args.source_sha,
        )
        verified = verify_execution_closure(
            git_directory,
            args.source_sha,
            args.mode,
        )
        result = dispatch(
            args.mode,
            args.source_sha,
            operation_args,
            verified,
        )
    if result != 0:
        raise AuthorityError(f"staging {args.mode} operation failed")
    print(f"PROMETHEUS_STAGING_{args.mode.upper()}=PASS")
    print(f"PROMETHEUS_SOURCE_SHA={args.source_sha}")
    print("SECCOMP_DISABLED=NO")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"PROMETHEUS_STAGING_AUTHORITY=FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
