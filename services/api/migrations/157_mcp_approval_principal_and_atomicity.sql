-- An MCP approval separates the requesting person from the deciding person.
-- A key prefix identifies the credential in audit views, but a person can
-- own multiple keys, so it cannot enforce separation of duties.

ALTER TABLE aisoc_mcp_tool_approvals
    ADD COLUMN IF NOT EXISTS requested_by_user_id UUID;

CREATE INDEX IF NOT EXISTS aisoc_mcp_tool_approvals_requester_idx
    ON aisoc_mcp_tool_approvals (tenant_id, requested_by_user_id);

COMMENT ON COLUMN aisoc_mcp_tool_approvals.requested_by_user_id IS
    'Authenticated principal that requested the call; key prefixes remain in requested_by for display.';
