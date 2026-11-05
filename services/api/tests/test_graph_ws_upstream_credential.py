"""The internal graph dial presents an ingest credential.

The browser's session token stops at this proxy. The hop from here to the
ingest broadcaster used to carry only ``tenant_id`` in the query string, and
the broadcaster subscribed to whatever that said. The dial has to present
the service credential ingest already requires everywhere else, and the
tenant header that credential must declare.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
GRAPH_WS = REPO_ROOT / "services" / "api" / "app" / "api" / "v1" / "endpoints" / "graph_ws.py"


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def test_internal_dial_presents_the_ingest_service_credential() -> None:
    source = GRAPH_WS.read_text(encoding="utf-8")
    tree = ast.parse(source)
    headers_fn: ast.FunctionDef | None = None
    dial_keywords: set[str | None] = set()
    dial_found = False
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_upstream_headers":
            headers_fn = node
        if isinstance(node, ast.Call) and _call_name(node) == "aconnect_ws":
            dial_found = True
            dial_keywords = {kw.arg for kw in node.keywords}
    assert headers_fn is not None, "the ingest dial has no credential to present; a query-string tenant is not one"
    body = ast.get_source_segment(source, headers_fn) or ""
    assert "X-Tenant-ID" in body
    # The secret is read in the helper the headers call, or inline. Either
    # way it has to be the service token, not a tenant id from the query.
    credential = next(
        (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "_upstream_credential"),
        None,
    )
    credential_src = ast.get_source_segment(source, credential) if credential is not None else ""
    assert "AISOC_SERVICE_TOKEN" in body or ("_upstream_credential" in body and "AISOC_SERVICE_TOKEN" in (credential_src or ""))
    assert dial_found, "aconnect_ws is no longer how the proxy dials ingest"
    assert "headers" in dial_keywords, "the credential must travel on the upgrade, not in the URL"
