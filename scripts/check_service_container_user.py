#!/usr/bin/env python3
"""Gate: first-party service images declare a non-root USER in the runtime stage.

Why this exists
---------------
Sixteen ``services/*/Dockerfile`` files shipped with no ``USER`` directive, so
every published service container started as uid 0. A Dockerfile that never
names a user is not an accident waiting for compose to fix it — it is the
runtime default.

What it checks
--------------
Every ``services/*/Dockerfile`` is parsed stage by stage. The **last** ``FROM``
is the runtime image; the effective user is the last ``USER`` in that stage, or
root when there is none. Any ``USER`` whose uid is ``0`` or ``root`` (including
``USER root:nogroup``) is treated as root.

Optional ``--probe SERVICE`` builds the image compose would build for one
service and runs ``id -u`` inside it. That is the observation half: a
Dockerfile can declare ``USER`` and still be overridden at run time, which this
does not check; it does catch a declaration that never made it into the built
image.

Usage
-----
::

    python3 scripts/check_service_container_user.py
    python3 scripts/check_service_container_user.py --probe api
    python3 scripts/check_service_container_user.py --self-test

Exit codes: 0 clean, 1 findings, 2 the scan could not run.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import refuses_an_empty_tree, repo_root, scratch_tree

_SERVICES_GLOB = "services/*/Dockerfile"


@dataclass(frozen=True)
class StageUser:
    dockerfile: str
    stage: str
    user: str | None


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


def _runs_as_root(user_spec: str | None) -> bool:
    if not user_spec:
        return True
    uid_part = user_spec.split(":", 1)[0].strip().lower()
    return uid_part in {"root", "0"}


def effective_runtime_user(text: str) -> StageUser:
    """Return the user the last stage runs as; ``None`` means root."""
    lines = text.splitlines()
    stage_indices = [i for i, line in enumerate(lines) if _strip_comment(line).upper().startswith("FROM ")]
    if not stage_indices:
        return StageUser("", "missing FROM", None)
    start = stage_indices[-1]
    stage = _strip_comment(lines[start])
    declared: str | None = None
    for line in lines[start + 1 :]:
        stripped = _strip_comment(line)
        if not stripped:
            continue
        if stripped.upper().startswith("FROM "):
            break
        if stripped.upper().startswith("USER "):
            declared = stripped[4:].strip()
    if _runs_as_root(declared):
        return StageUser("", stage, None)
    return StageUser("", stage, declared)


def scan(root: Path) -> list[tuple[str, StageUser]]:
    dockerfiles = sorted(root.glob(_SERVICES_GLOB))
    if not dockerfiles:
        raise RuntimeError(f"no {_SERVICES_GLOB} under {root}")
    findings: list[tuple[str, StageUser]] = []
    for path in dockerfiles:
        rel = path.relative_to(root).as_posix()
        info = effective_runtime_user(path.read_text(encoding="utf-8"))
        info = StageUser(rel, info.stage, info.user)
        if info.user is None:
            findings.append((rel, info))
    return findings


def probe_service(root: Path, service: str, *, timeout: int = 600) -> tuple[int, str]:
    """Build and run ``id -u`` for one compose service; return (uid, detail)."""
    if shutil.which("docker") is None:
        raise RuntimeError("docker is not on PATH")
    compose = root / "docker-compose.yml"
    if not compose.is_file():
        raise RuntimeError(f"no {compose}")
    build = subprocess.run(  # noqa: S603
        ["docker", "compose", "-f", str(compose), "build", service],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=root,
    )
    if build.returncode != 0:
        raise RuntimeError(f"docker compose build {service} failed:\n{build.stderr[-4000:]}")
    run = subprocess.run(  # noqa: S603
        [
            "docker",
            "compose",
            "-f",
            str(compose),
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "id",
            service,
            "-u",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=root,
    )
    if run.returncode != 0:
        raise RuntimeError(f"docker compose run id failed:\n{run.stderr[-2000:]}")
    uid = run.stdout.strip()
    if not uid.isdigit():
        raise RuntimeError(f"unexpected id output: {run.stdout!r}")
    return int(uid), run.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument(
        "--probe",
        metavar="SERVICE",
        help="after the static scan passes, build one compose service and run id -u inside it",
    )
    args = parser.parse_args(argv)
    root = (args.repo_root or repo_root()).resolve()

    try:
        findings = scan(root)
    except RuntimeError as exc:
        print(f"check_service_container_user: FAILED to run: {exc}", file=sys.stderr)
        return 2

    if findings:
        print(f"SERVICE-CONTAINER-USER GATE FAILED — {len(findings)} Dockerfile(s) run as root:", file=sys.stderr)
        for rel, info in findings:
            print(
                f"  [{rel}] runtime stage {info.stage!r} has no non-root USER "
                f"(add USER before CMD, following services/mcp or services/escalations)",
                file=sys.stderr,
            )
        return 1

    print(f"OK — all {len(list(root.glob(_SERVICES_GLOB)))} service Dockerfiles declare a non-root runtime USER.")

    if args.probe:
        try:
            uid, detail = probe_service(root, args.probe)
        except RuntimeError as exc:
            print(f"check_service_container_user: probe failed: {exc}", file=sys.stderr)
            return 2
        if uid == 0:
            print(f"PROBE FAILED — {args.probe} runs as uid 0 (id output: {detail})", file=sys.stderr)
            return 1
        print(f"PROBE OK — {args.probe} runs as uid {uid}")

    return 0


def self_test() -> int:
    print("check_service_container_user self-test")

    def record(label: str, passed: bool, detail: str = "") -> None:
        checks.append((label, passed))
        print(f"  {'PASS' if passed else 'FAIL'}  {label}")
        if detail:
            print(f"        {detail}")

    checks: list[tuple[str, bool]] = []

    missing = effective_runtime_user("FROM python:3.11-slim\nCMD []\n")
    record("no USER in the runtime stage is root", missing.user is None)

    root_user = effective_runtime_user("FROM alpine:3.19\nUSER root\nCMD []\n")
    record("USER root is treated as root", root_user.user is None)

    uid_zero_group = effective_runtime_user("FROM alpine:3.19\nUSER 0:65534\nCMD []\n")
    record("USER with uid 0 is treated as root", uid_zero_group.user is None)

    ok = effective_runtime_user("FROM python:3.11-slim\nUSER nobody\nCMD []\n")
    record("USER nobody is accepted", ok.user == "nobody")

    multi = effective_runtime_user("FROM golang:1.26 AS builder\nRUN go build\nFROM alpine:3.19\nUSER aisoc\nCMD []\n")
    record("the last stage's USER wins across stages", multi.user == "aisoc")

    last = effective_runtime_user("FROM python:3.11-slim\nUSER nobody\nUSER aisoc\nCMD []\n")
    record("the last USER in a stage wins", last.user == "aisoc")

    with scratch_tree() as tree:
        svc = tree / "services" / "demo"
        svc.mkdir(parents=True)
        (svc / "Dockerfile").write_text("FROM python:3.11-slim\nCMD []\n", encoding="utf-8")
        bad = scan(tree)
        record("scan finds a service Dockerfile without USER", len(bad) == 1 and bad[0][0] == "services/demo/Dockerfile")

        (svc / "Dockerfile").write_text("FROM python:3.11-slim\nUSER nobody\nCMD []\n", encoding="utf-8")
        good = scan(tree)
        record("scan is clean when USER is set", not good)

    refused, detail = refuses_an_empty_tree(Path(__file__).name, [])
    record("refuses a tree with no content rather than reporting it clean", refused, detail.replace("\n", " | "))

    print()
    if not all(passed for _, passed in checks):
        print("check_service_container_user.py: self-test FAILED")
        return 1
    print(f"check_service_container_user.py: self-test OK ({len(checks)} assertions)")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(self_test())
    raise SystemExit(main())
