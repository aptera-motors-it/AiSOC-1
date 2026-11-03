"""F76: the EKS API must not default to a world-reachable public endpoint.

tfsec AVD-AWS-0041 fires when ``public_access_cidrs`` is omitted (AWS then
treats the public control plane as 0.0.0.0/0). The IaC workflow runs the same
scanner on ``infra/terraform``; this test pins the EKS module specifically so
the finding cannot return without touching the ratchet ceilings.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TERRAFORM_ROOT = REPO / "infra" / "terraform"
EKS_MODULE = TERRAFORM_ROOT / "modules" / "eks"
TFSEC_VERSION = "1.28.13"
TFSEC_RULE = "AVD-AWS-0041"


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


def _tfsec_results(module_dir: Path) -> list[dict]:
    report = Path("/tmp") / f"tfsec-eks-{module_dir.name}.json"
    if report.exists():
        report.unlink()
    subprocess.run(
        [
            str(_tfsec_bin()),
            str(module_dir),
            "--format",
            "json",
            "--out",
            str(report),
            "--soft-fail",
        ],
        check=True,
        capture_output=True,
    )
    payload = json.loads(report.read_text())
    return payload.get("results") or []


def test_tfsec_iac_workflow_scans_infra_terraform_tree():
    """Mirror security.yml: tfsec 1.28.13 over infra/terraform must complete."""
    report = Path("/tmp") / "tfsec-infra-terraform.json"
    if report.exists():
        report.unlink()
    completed = subprocess.run(
        [
            str(_tfsec_bin()),
            str(TERRAFORM_ROOT),
            "--format",
            "json",
            "--out",
            str(report),
            "--soft-fail",
        ],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(report.read_text())
    assert isinstance(payload.get("results"), list)


def test_tfsec_does_not_allow_world_reachable_eks_public_endpoint():
    hits = [row for row in _tfsec_results(EKS_MODULE) if row.get("rule_id") == TFSEC_RULE]
    assert not hits, [row.get("description") for row in hits]


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


def test_eks_module_rejects_world_open_cidr_literals():
    variables_tf = (EKS_MODULE / "variables.tf").read_text()
    assert "0.0.0.0/0" in variables_tf
    assert ">= 16" in variables_tf
