"""Regression tests for minimatch@11 overrides vs legacy v3 call sites."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECK_SCRIPT = REPO_ROOT / "scripts" / "check_minimatch_call_sites.py"
NODE_SCRIPT = REPO_ROOT / "scripts" / "check_minimatch_call_sites.js"
GLOB_MODULES = REPO_ROOT / "node_modules" / ".pnpm" / "glob@7.2.3" / "node_modules"
SERVE_MODULES = REPO_ROOT / "node_modules" / ".pnpm" / "serve-handler@6.1.7" / "node_modules"
ESLINT_REACT_GLOB = list((REPO_ROOT / "node_modules" / ".pnpm").glob("eslint-plugin-react@*/node_modules"))


def _node_modules_dir(*candidates: Path) -> Path:
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    pytest.skip(f"missing node_modules fixture: {candidates[0]}")


def _run_call_site_check(modules_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["node", str(NODE_SCRIPT), "--modules-dir", str(modules_dir)],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_call_sites_at_head_lockfile() -> None:
    glob_dir = _node_modules_dir(GLOB_MODULES)
    proc = _run_call_site_check(glob_dir)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_serve_handler_modules_at_head() -> None:
    serve_dir = _node_modules_dir(SERVE_MODULES)
    proc = _run_call_site_check(serve_dir)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_eslint_react_modules_at_head() -> None:
    if not ESLINT_REACT_GLOB:
        pytest.skip("eslint-plugin-react not installed")
    proc = _run_call_site_check(ESLINT_REACT_GLOB[0])
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_legacy_minimatch_three_call_sites_in_isolated_tree(tmp_path: Path) -> None:
    if shutil.which("npm") is None:
        pytest.skip("npm not available")
    subprocess.run(
        [
            "npm",
            "install",
            "--no-save",
            "--no-package-lock",
            "minimatch@3.1.5",
            "glob@7.2.3",
            "rimraf@3.0.2",
            "serve-handler@6.1.7",
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )
    proc = _run_call_site_check(tmp_path / "node_modules")
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_check_script_self_test() -> None:
    proc = subprocess.run(
        [sys.executable, str(CHECK_SCRIPT), "--self-test"],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
