from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
NODE_SCRIPT = REPO_ROOT / "scripts" / "check_minimatch_call_sites.js"
PY_SCRIPT = REPO_ROOT / "scripts" / "check_minimatch_call_sites.py"


def _run_call_site_check(extra_args: list[str] | None = None) -> subprocess.CompletedProcess[str]:
    cmd = ["node", str(NODE_SCRIPT), *(extra_args or [])]
    return subprocess.run(cmd, cwd=REPO_ROOT, check=False, capture_output=True, text=True)


def test_minimatch_facade_exports_make_re() -> None:
    script = """
const mm = require('./packages/minimatch-cjs-compat');
if (typeof mm.makeRe !== 'function') {
  throw new Error('minimatch.makeRe missing');
}
const re = mm.makeRe('packages/**/internal/**');
if (!re.test('packages/foo/internal/bar')) {
  throw new Error('makeRe test() failed');
}
"""
    proc = subprocess.run(
        ["node", "-e", script],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_call_sites_at_head_lockfile() -> None:
    proc = _run_call_site_check()
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
            "eslint@9.39.5",
            "eslint-plugin-import@2.32.0",
            "eslint-plugin-react@7.37.5",
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )
    proc = _run_call_site_check(["--modules-dir", str(tmp_path / "node_modules")])
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_modules_dir_does_not_require_repo_pnpm_eslint(tmp_path: Path) -> None:
    """--modules-dir must work without scanning the caller's repo .pnpm store."""
    if shutil.which("npm") is None:
        pytest.skip("npm not available")
    modules_root = Path("/tmp/qp/mm-isolated/node_modules")
    if not modules_root.is_dir():
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
                "eslint@9.39.5",
                "eslint-plugin-import@2.32.0",
                "eslint-plugin-react@7.37.5",
            ],
            cwd=tmp_path,
            check=True,
            capture_output=True,
            text=True,
        )
        modules_root = tmp_path / "node_modules"

    bare = Path(tempfile.mkdtemp(prefix="aisoc-callsite-bare-"))
    try:
        (bare / "scripts").mkdir()
        (bare / "node_modules" / ".pnpm").mkdir(parents=True)
        shutil.copy(NODE_SCRIPT, bare / "scripts" / "check_minimatch_call_sites.js")
        proc = subprocess.run(
            [
                "node",
                str(bare / "scripts" / "check_minimatch_call_sites.js"),
                "--modules-dir",
                str(modules_root),
            ],
            cwd=bare,
            check=False,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
    finally:
        shutil.rmtree(bare, ignore_errors=True)


def test_check_script_self_test() -> None:
    proc = subprocess.run(
        [sys.executable, str(PY_SCRIPT), "--self-test"],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
