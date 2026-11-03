#!/usr/bin/env python3
"""Fail when the root pnpm lockfile resolves known-vulnerable minimatch or deepmerge.

The root ``pnpm-lock.yaml`` is what ``apps/web``, ``apps/docs``, and the rest of
the workspace install from. ``security_audit.py`` audits every pnpm install root
and only fails on high/critical findings, so moderate ``minimatch`` and low
``deepmerge`` advisories on the root lockfile can sit as warnings forever while
Dependabot and ``pnpm audit`` still name them on every push.

This gate is narrower and stricter: it reads the resolved versions in the root
lockfile and refuses any copy outside the fixed ranges recorded for
GHSA-g3hv-75wg-m249 (minimatch before 11.0.1) and GHSA-gcqx-w48m-w2h4
(deepmerge 4.2.0 through 4.3.1). ``apps/mobile`` keeps its own lockfile and is
out of scope here on purpose — the workspace file is what the console and docs
builds use.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main

_PNPM_PKG = re.compile(
    r"^ {2}/(?P<name>@[^/@\s]+/[^@\s]+|[^@/\s][^@\s]*)@(?P<version>\d[^(:\s]*)",
    re.MULTILINE,
)

_MINIMATCH_FLOOR = (11, 0, 1)
_DEEPMERGE_VULN_LOW = (4, 2, 0)
_DEEPMERGE_VULN_HIGH = (4, 3, 1)


def _parse_version(raw: str) -> tuple[int, ...]:
    parts: list[int] = []
    for piece in raw.split("."):
        if not piece.isdigit():
            break
        parts.append(int(piece))
    return tuple(parts or (0,))


def _lt(left: tuple[int, ...], right: tuple[int, ...]) -> bool:
    width = max(len(left), len(right))
    left_padded = left + (0,) * (width - len(left))
    right_padded = right + (0,) * (width - len(right))
    return left_padded < right_padded


def _between(version: tuple[int, ...], low: tuple[int, ...], high: tuple[int, ...]) -> bool:
    return not _lt(version, low) and not _lt(high, version)


def parse_pnpm_lock_versions(text: str) -> dict[str, list[str]]:
    resolved: dict[str, list[str]] = {}
    for match in _PNPM_PKG.finditer(text):
        resolved.setdefault(match.group("name"), []).append(match.group("version"))
    return resolved


def findings_for_lockfile(text: str) -> list[str]:
    problems: list[str] = []
    resolved = parse_pnpm_lock_versions(text)
    if not resolved:
        return ["pnpm-lock.yaml contains no resolved package entries — nothing was scanned"]

    for version in sorted(set(resolved.get("minimatch", []))):
        parsed = _parse_version(version)
        if _lt(parsed, _MINIMATCH_FLOOR):
            problems.append(
                f"minimatch@{version} is below 11.0.1 (GHSA-g3hv-75wg-m249); "
                "raise it with a pnpm override and refresh the lockfile"
            )

    for version in sorted(set(resolved.get("deepmerge", []))):
        parsed = _parse_version(version)
        if _between(parsed, _DEEPMERGE_VULN_LOW, _DEEPMERGE_VULN_HIGH):
            problems.append(
                f"deepmerge@{version} is inside the GHSA-gcqx-w48m-w2h4 range "
                "(4.2.0 through 4.3.1); pin below 4.2.0 or refresh when upstream ships a fix"
            )

    return problems


def check_root_lockfile(root: Path) -> list[str]:
    lockfile = root / "pnpm-lock.yaml"
    if not lockfile.is_file():
        return [f"missing {lockfile.relative_to(root)} — the web workspace lockfile was not scanned"]
    return findings_for_lockfile(lockfile.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="repository root (default: git rev-parse)",
    )
    args = parser.parse_args(argv)

    root = (args.root or repo_root()).resolve()

    problems = check_root_lockfile(root)
    if problems:
        for line in problems:
            print(f"check_pnpm_web_lockfile: {line}", file=sys.stderr)
        return 1

    print("check_pnpm_web_lockfile: OK — root pnpm-lock.yaml has no known-vulnerable minimatch/deepmerge")
    return 0


def _self_test_cases() -> list[tuple[str, bool]]:
    bad = "\n".join(
        [
            "lockfileVersion: '9.0'",
            "packages:",
            "  /minimatch@3.1.5:",
            "    resolution: {integrity: x}",
            "  /deepmerge@4.3.1:",
            "    resolution: {integrity: y}",
        ]
    )
    good = bad.replace("3.1.5", "11.0.4").replace("4.3.1", "4.1.2")
    return [
        ("flags known-vulnerable minimatch and deepmerge", len(findings_for_lockfile(bad)) >= 2),
        ("accepts fixed minimatch/deepmerge versions", not findings_for_lockfile(good)),
    ]


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test_main(Path(__file__).name, [], extra=_self_test_cases()))
    sys.exit(main())
