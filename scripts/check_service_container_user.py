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
quoted forms and ``USER root:nogroup``) is treated as root. A ``USER`` value
containing ``$`` is a finding because the gate cannot verify the runtime uid.

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
import re
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


_HEREDOC_REDIRECT = re.compile(
    r"(?:^|\s)<<-?"
    r"(?:"
    r"'(?P<dq>[^']+)'"
    r"|\"(?P<sq>[^\"]+)\""
    r"|(?P<uq>[A-Za-z_][A-Za-z0-9_]*)"
    r")",
)
_USER_DIRECTIVE = re.compile(r"^USER\s+(.+)$", re.IGNORECASE)
_COPY_OR_RUN = re.compile(r"^(COPY|RUN)\s+", re.IGNORECASE)


def _heredoc_delimiter(instruction: str) -> str | None:
    """Return the heredoc delimiter when ``instruction`` is COPY/RUN with ``<<``."""
    if not _COPY_OR_RUN.match(instruction):
        return None
    match = _HEREDOC_REDIRECT.search(instruction)
    if not match:
        return None
    return match.group("dq") or match.group("sq") or match.group("uq")


def _logical_instruction_lines(text: str) -> list[str]:
    """Dockerfile lines merged for ``\\`` continuations; heredoc bodies omitted."""
    logical: list[str] = []
    pending = ""
    in_heredoc = False
    heredoc_delim = ""
    for raw in text.splitlines():
        stripped = _strip_comment(raw)
        if in_heredoc:
            if stripped == heredoc_delim:
                in_heredoc = False
            continue
        if pending:
            stripped = pending + stripped
            pending = ""
        while stripped.endswith("\\"):
            pending = stripped[:-1].rstrip() + " "
            stripped = ""
            break
        if not stripped:
            continue
        delim = _heredoc_delimiter(stripped)
        if delim is not None:
            in_heredoc = True
            heredoc_delim = delim
        logical.append(stripped)
    return logical


def _uid_part(user_spec: str) -> str:
    spec = user_spec.strip()
    if len(spec) >= 2 and spec[0] == spec[-1] and spec[0] in "\"'":
        spec = spec[1:-1].strip()
    return spec.split(":", 1)[0].strip()


def _runs_as_root(user_spec: str | None) -> bool:
    if not user_spec:
        return True
    uid_part = _uid_part(user_spec)
    if uid_part.lower() == "root":
        return True
    try:
        return int(uid_part, 10) == 0
    except ValueError:
        return False


def _effective_user_spec(user_spec: str | None) -> str | None:
    """Return the declared user when it is a static non-root spec; else ``None`` (finding)."""
    if user_spec is None:
        return None
    if "$" in user_spec:
        return None
    if _runs_as_root(user_spec):
        return None
    return user_spec


def _parse_user_directive(line: str) -> str | None:
    match = _USER_DIRECTIVE.match(line)
    if not match:
        return None
    return match.group(1).strip()


def effective_runtime_user(text: str) -> StageUser:
    """Return the user the last stage runs as; ``None`` means root."""
    logical = _logical_instruction_lines(text)
    stage_indices = [i for i, line in enumerate(logical) if line.upper().startswith("FROM ")]
    if not stage_indices:
        return StageUser("", "missing FROM", None)
    start = stage_indices[-1]
    stage = logical[start]
    declared: str | None = None
    for line in logical[start + 1 :]:
        if line.upper().startswith("FROM "):
            break
        parsed = _parse_user_directive(line)
        if parsed is not None:
            declared = parsed
    user = _effective_user_spec(declared)
    return StageUser("", stage, user)


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

    uid_00 = effective_runtime_user("FROM alpine:3.19\nUSER 00\nCMD []\n")
    record("USER 00 is treated as root", uid_00.user is None)

    quoted_zero = effective_runtime_user('FROM alpine:3.19\nUSER "0"\nCMD []\n')
    record('USER "0" is treated as root', quoted_zero.user is None)

    single_quoted = effective_runtime_user("FROM alpine:3.19\nUSER '0'\nCMD []\n")
    record("USER '0' is treated as root", single_quoted.user is None)

    quoted_root = effective_runtime_user('FROM alpine:3.19\nUSER "root"\nCMD []\n')
    record('USER "root" is treated as root', quoted_root.user is None)

    quoted_root_group = effective_runtime_user('FROM alpine:3.19\nUSER "root:root"\nCMD []\n')
    record('USER "root:root" is treated as root', quoted_root_group.user is None)

    quoted_zero_group = effective_runtime_user('FROM alpine:3.19\nUSER "0:0"\nCMD []\n')
    record('USER "0:0" is treated as root', quoted_zero_group.user is None)

    sq_zero_group = effective_runtime_user("FROM alpine:3.19\nUSER '0:0'\nCMD []\n")
    record("USER '0:0' is treated as root", sq_zero_group.user is None)

    tab_user = effective_runtime_user("FROM alpine:3.19\nUSER nobody\nUSER\t0\nCMD []\n")
    record("USER with tab before uid 0 is treated as root", tab_user.user is None)

    arg_expand = effective_runtime_user("FROM alpine:3.19\nARG U=0\nUSER ${U}\nCMD []\n")
    record("USER with variable expansion is a finding", arg_expand.user is None)

    env_expand = effective_runtime_user("FROM alpine:3.19\nENV U=root\nUSER $U\nCMD []\n")
    record("USER with env substitution is a finding", env_expand.user is None)

    run_not_user = effective_runtime_user("FROM alpine:3.19\nRUN echo start \\\nUSER nobody\nCMD []\n")
    record("USER in a continued RUN is not a USER instruction", run_not_user.user is None)

    shell_shift = effective_runtime_user("FROM alpine:3.19\nUSER nobody\nRUN echo $((1<<4))\nUSER 0\nCMD []\n")
    record("shell << shift does not swallow a later USER 0", shell_shift.user is None)

    heredoc = effective_runtime_user("FROM alpine:3.19\nCOPY <<EOF /etc/motd\nUSER nobody\nEOF\nCMD []\n")
    record("USER inside an unquoted heredoc body is not a USER instruction", heredoc.user is None)

    quoted_heredoc = effective_runtime_user("FROM alpine:3.19\nRUN cat <<'EOF'\nUSER nobody\nEOF\nCMD []\n")
    record("USER inside a quoted heredoc body is not a USER instruction", quoted_heredoc.user is None)

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
