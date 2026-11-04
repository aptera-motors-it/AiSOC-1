-- A signed ChatOps reply may arrive at any actions replica. The unique
-- action id makes recording the reply an atomic, durable single-use claim.
CREATE TABLE IF NOT EXISTS aisoc_chatops_callback_replies (
    action_id UUID PRIMARY KEY,
    responded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
