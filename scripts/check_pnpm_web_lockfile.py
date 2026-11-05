#!/usr/bin/env python3
"""Fail when the root pnpm lockfile resolves known-vulnerable minimatch or deepmerge.

The root ``pnpm-lock.yaml`` is what ``apps/web``, ``apps/docs``, and the rest of
the workspace install from. Sibling ``security_audit.py`` only fails on
high/critical findings, so moderate ``minimatch`` and low ``deepmerge``
advisories can remain green there.

Constraints this gate encodes:

* **minimatch** — refuse GHSA-g3hv-75wg-m249 on every resolved copy below
  11.0.1. Registry ``minimatch@11`` is not a callable CommonJS
  ``require('minimatch')`` for glob@7, serve-handler, and eslint-plugin-react;
  the workspace facade ``packages/minimatch-cjs-compat`` (via
  ``pnpm.overrides.minimatch``) wraps ``minimatch@11.0.4`` for those callers.
* **deepmerge** — refuse versions below 4.2.0 (no ``__proto__`` merge guard).
  Do not pin 4.1.2 for GHSA-gcqx-w48m-w2h4: that release drops the 4.2.0+
  guard. Keep 4.3.1 (or newer when upstream ships). npm lists patched versions
  as ``<0.0.0``; ``pnpm audit`` exits 1 on that low finding until a patched
  release exists. No audit ignore for it.

Package keys using registry tarballs or quoted paths are parsed the same as
``/pkg@version:`` entries. ``apps/mobile`` is out of scope.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main

_PNPM_PKG = re.compile(
    r"^ {2}(?:'/|/)(?P<name>@[^/@\s'\"]+/[^@\s'\"]+|[^@/\s'\"][^@\s'\"]*)@(?P<version>\d[\d.]*)(?:':|:)",
    re.MULTILINE,
)
_PNPM_TARBALL = re.compile(
    r"^ {2}['\"]?@[^'\"]+/(?P<name>[^/'\"]+)/-/[^/'\"]+-(?P<version>\d[\d.]*)\.tgz['\"]?:",
    re.MULTILINE,
)

_MINIMATCH_FLOOR = (11, 0, 1)
_DEEPMERGE_GUARD_FLOOR = (4, 2, 0)


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


def parse_pnpm_lock_versions(text: str) -> dict[str, list[str]]:
    resolved: dict[str, list[str]] = {}
    for match in _PNPM_PKG.finditer(text):
        resolved.setdefault(match.group("name"), []).append(match.group("version"))
    for match in _PNPM_TARBALL.finditer(text):
        resolved.setdefault(match.group("name"), []).append(match.group("version"))
    return resolved


def _minimatch_problems(versions: set[str]) -> list[str]:
    problems: list[str] = []
    for version in sorted(versions):
        parsed = _parse_version(version)
        if _lt(parsed, _MINIMATCH_FLOOR):
            problems.append(
                f"minimatch@{version} is below 11.0.1 (GHSA-g3hv-75wg-m249); "
                "use the minimatch CJS compat workspace package and refresh the lockfile"
            )
    return problems


def findings_for_lockfile(text: str) -> list[str]:
    problems: list[str] = []
    resolved = parse_pnpm_lock_versions(text)
    if not resolved:
        return ["pnpm-lock.yaml contains no resolved package entries; nothing was scanned"]

    for line in _minimatch_problems(set(resolved.get("minimatch", []))):
        problems.append(line)

    for version in sorted(set(resolved.get("deepmerge", []))):
        parsed = _parse_version(version)
        if _lt(parsed, _DEEPMERGE_GUARD_FLOOR):
            problems.append(
                f"deepmerge@{version} is below 4.2.0 and lacks the __proto__ merge guard; "
                "do not pin 4.1.2 to silence GHSA-gcqx-w48m-w2h4; keep 4.2.0+ instead"
            )

    return problems


def check_root_lockfile(root: Path) -> list[str]:
    lockfile = root / "pnpm-lock.yaml"
    if not lockfile.is_file():
        return [f"missing {lockfile.relative_to(root)}; the web workspace lockfile was not scanned"]
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

    print("check_pnpm_web_lockfile: OK; root pnpm-lock.yaml has no known-vulnerable minimatch/deepmerge")
    return 0


def _self_test_cases() -> list[tuple[str, bool]]:
    bad_minimatch = "\n".join(
        [
            "lockfileVersion: '9.0'",
            "packages:",
            "  /minimatch@3.1.5:",
            "    resolution: {integrity: x}",
            "  /deepmerge@4.3.1:",
            "    resolution: {integrity: y}",
        ]
    )
    bad_deepmerge = bad_minimatch.replace("4.3.1", "4.1.2").replace("3.1.5", "11.0.4")
    good = bad_minimatch.replace("3.1.5", "11.0.4")
    quoted = bad_minimatch.replace("/minimatch@3.1.5:", "'/minimatch@3.1.5':")
    tarball = bad_minimatch.replace(
        "  /minimatch@3.1.5:",
        "  '@registry.npmjs.org/minimatch/-/minimatch-3.1.5.tgz':",
    )
    return [
        ("flags legacy minimatch below 11.0.1", bool(findings_for_lockfile(bad_minimatch))),
        ("flags deepmerge below 4.2.0", bool(findings_for_lockfile(bad_deepmerge))),
        ("accepts fixed minimatch/deepmerge versions", not findings_for_lockfile(good)),
        ("flags quoted pnpm package keys", bool(findings_for_lockfile(quoted))),
        ("flags registry tarball package keys", bool(findings_for_lockfile(tarball))),
    ]


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test_main(Path(__file__).name, [], extra=_self_test_cases()))
    sys.exit(main())
