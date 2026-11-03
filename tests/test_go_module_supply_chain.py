"""F68: first-party Go modules must not ship a vulnerable stdlib toolchain or x/net.

The four modules under ``services/`` are what compose and CI build. ``go 1.26.0``
without a ``toolchain`` line selects the runner's patch level; on the default
1.26.0 toolchain ``govulncheck`` reports dozens of code-reachable stdlib issues.
Pinning ``toolchain go1.26.10`` (and current ``golang.org/x/net`` on ingest) is
the supply-chain fix this gate locks in.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

P25_GO_MODULES = (
    "services/ingest",
    "services/enrichment",
    "services/demo-producer",
    "services/osquery-extensions",
)

_AFFECTED_RE = re.compile(
    r"Your code is affected by (\d+) vulnerabilities",
    re.MULTILINE,
)


def _require_tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        pytest.fail(f"{name} must be on PATH — this test runs the real scanner, not a stub")
    assert path is not None
    return path


@pytest.mark.parametrize("module_dir", P25_GO_MODULES)
def test_govulncheck_reports_no_code_reachable_vulnerabilities(module_dir: str) -> None:
    _require_tool("govulncheck")
    cwd = REPO_ROOT / module_dir
    proc = subprocess.run(
        ["govulncheck", "./..."],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    combined = proc.stdout + proc.stderr
    if proc.returncode not in (0, 3):
        pytest.fail(f"govulncheck could not scan {module_dir} (exit {proc.returncode}):\n{combined[:2000]}")
    match = _AFFECTED_RE.search(combined)
    if match is None:
        if "No vulnerabilities found" in combined:
            return
        pytest.fail(f"govulncheck output missing vulnerability summary for {module_dir}:\n{combined[:2000]}")
    assert match is not None
    count = int(match.group(1))
    assert count == 0, f"{module_dir}: {count} code-reachable vulnerabilities (pin patched toolchain/x/net)"


@pytest.mark.parametrize("module_dir", P25_GO_MODULES)
def test_osv_scanner_reports_no_known_vulnerabilities(module_dir: str) -> None:
    osv = _require_tool("osv-scanner")
    go_mod = REPO_ROOT / module_dir / "go.mod"
    proc = subprocess.run(
        [osv, "scan", "source", "-L", str(go_mod), "--all-vulns"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    combined = proc.stdout + proc.stderr
    assert proc.returncode == 0, f"osv-scanner failed for {module_dir}:\n{combined}"
    assert "Uncalled vulnerabilities" not in combined, (
        f"osv-scanner --all-vulns reported uncalled vulnerabilities for {module_dir}:\n{combined}"
    )
    assert "No issues found" in combined, (
        f"osv-scanner --all-vulns must report a clean lockfile for {module_dir}:\n{combined}"
    )


def test_ingest_pins_patched_golang_org_x_net() -> None:
    text = (REPO_ROOT / "services/ingest" / "go.mod").read_text(encoding="utf-8")
    match = re.search(r"golang\.org/x/net v(\d+\.\d+\.\d+)", text)
    assert match, "ingest go.mod must declare golang.org/x/net"
    major, minor, patch = (int(x) for x in match.group(1).split("."))
    assert (major, minor, patch) >= (0, 62, 0), f"ingest golang.org/x/net must be at least v0.62.0 (found v{match.group(1)})"


@pytest.mark.parametrize("module_dir", P25_GO_MODULES)
def test_go_mod_pins_patched_toolchain(module_dir: str) -> None:
    text = (REPO_ROOT / module_dir / "go.mod").read_text(encoding="utf-8")
    match = re.search(r"^toolchain go(\d+\.\d+\.\d+)$", text, re.MULTILINE)
    assert match, f"{module_dir}/go.mod must pin toolchain go1.26.10 or newer"
    major, minor, patch = (int(x) for x in match.group(1).split("."))
    assert (major, minor, patch) >= (1, 26, 10), f"{module_dir} toolchain go{match.group(1)} is below patched go1.26.10"
