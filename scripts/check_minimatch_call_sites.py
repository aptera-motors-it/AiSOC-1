#!/usr/bin/env python3
"""Run live minimatch consumer checks (glob.sync, rimraf, serve-handler, eslint-react)."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main

_SCRIPT = Path(__file__).resolve().parent / "check_minimatch_call_sites.js"
_GLOB_MODULES = "node_modules/.pnpm/glob@7.2.3/node_modules"


def run_check(root: Path, modules_dir: Path | None = None) -> tuple[int, str]:
    cmd = ["node", str(_SCRIPT)]
    if modules_dir is not None:
        cmd.extend(["--modules-dir", str(modules_dir)])
    proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, check=False)
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=None)
    parser.add_argument("--modules-dir", type=Path, default=None)
    args = parser.parse_args(argv)
    root = (args.root or repo_root()).resolve()
    modules = args.modules_dir
    if modules is None:
        modules = root / _GLOB_MODULES
    if not modules.is_dir():
        print(f"check_minimatch_call_sites: missing {modules}", file=sys.stderr)
        return 1
    code, output = run_check(root, modules)
    if output.strip():
        print(output.rstrip())
    return code


def _self_test_cases() -> list[tuple[str, bool]]:
    root = repo_root()
    modules = root / _GLOB_MODULES
    if not modules.is_dir():
        return [("glob@7 fixture present", False)]
    code, _ = run_check(root, modules)
    return [("glob.sync and related call sites pass at repo head", code == 0)]


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test_main(Path(__file__).name, [], extra=_self_test_cases()))
    sys.exit(main())
