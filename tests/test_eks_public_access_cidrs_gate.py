"""F76: the EKS API must not default to a world-reachable public endpoint.

The IaC workflow runs tfsec 1.28.13 and checkov over ``infra/terraform``.
This gate mirrors those paths so CKV_AWS_38 and AVD-AWS-0041 cannot regress.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TERRAFORM_ROOT = REPO / "infra" / "terraform"
EKS_MODULE = TERRAFORM_ROOT / "modules" / "eks"
TFSEC_VERSION = "1.28.13"
TFSEC_RULE = "AVD-AWS-0041"
CHECKOV_CHECK = "CKV_AWS_38"


def _tfsec_bin() -> Path:
    dest = Path("/tmp") / f"tfsec-{TFSEC_VERSION}"
    if dest.exists():
        return dest
    url = f"https://github.com/aquasecurity/tfsec/releases/download/v{TFSEC_VERSION}/tfsec-linux-amd64"
    subprocess.run(
        ["curl", "-sSL", "--fail", "--retry", "3", url, "-o", str(dest)],
        check=True,
    )
    dest.chmod(0o755)
    return dest


def _checkov_bin() -> str | None:
    return shutil.which("checkov")


def _tfsec_report(target: Path) -> list[dict]:
    report = Path("/tmp") / f"tfsec-{target.name}.json"
    if report.exists():
        report.unlink()
    completed = subprocess.run(
        [
            str(_tfsec_bin()),
            str(target),
            "--format",
            "json",
            "--out",
            str(report),
            "--soft-fail",
        ],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    payload = json.loads(report.read_text())
    return payload.get("results") or []


def test_tfsec_iac_workflow_scans_infra_terraform_tree():
    hits = [row for row in _tfsec_report(TERRAFORM_ROOT) if row.get("rule_id") == TFSEC_RULE]
    assert not hits, [row.get("description") for row in hits]


def test_checkov_iac_workflow_passes_eks_public_endpoint_cidr_check():
    checkov = _checkov_bin()
    if checkov is None:
        pytest.skip("checkov is not on PATH (the IaC workflow installs it; this Python job does not)")
    completed = subprocess.run(
        [
            checkov,
            "-d",
            str(TERRAFORM_ROOT),
            "--check",
            CHECKOV_CHECK,
            "--quiet",
            "--compact",
        ],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Failed checks: 0" in completed.stdout


def test_eks_module_wires_public_access_cidrs_and_rejects_open_internet():
    main_tf = (EKS_MODULE / "main.tf").read_text()
    variables_tf = (EKS_MODULE / "variables.tf").read_text()
    assert "public_access_cidrs" in main_tf
    assert "public_access_cidrs" in variables_tf
    assert "0.0.0.0/0" in variables_tf
    assert "tonumber(element(split" in variables_tf
    assert ">= 16" in variables_tf
    assert "precondition" in main_tf
    assert "endpoint_public_access" in variables_tf
    assert 'default     = false' in variables_tf
