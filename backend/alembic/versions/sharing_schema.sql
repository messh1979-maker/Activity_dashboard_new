-- ============================================================
-- Module: sharing (M6) - Sharing & Collaboration
-- Architecture Reference: Sections 4.6, 8.2, 11.1
-- ============================================================

-- Shares table (ACL)
CREATE TABLE sharing.shares (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type VARCHAR(32) NOT NULL, -- goal | task | group | document
    entity_id UUID NOT NULL,
    recipient_id UUID NOT NULL REFERENCES auth.users(id),
    granted_by UUID REFERENCES auth.users(id),
    permission_level VARCHAR(16) NOT NULL, -- read | write | manage
    allow_comment BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    revoked_reason VARCHAR(100)
);

-- Indexes for shares
CREATE INDEX ix_shares_entity ON sharing.shares(entity_type, entity_id);
CREATE INDEX ix_shares_recipient ON sharing.shares(recipient_id);
CREATE INDEX ix_shares_granted_by ON sharing.shares(granted_by);
CREATE INDEX ix_shares_expires ON sharing.shares(expires_at) WHERE expires_at IS NOT NULL;

-- ACL View (effective permissions)
CREATE OR REPLACE VIEW sharing.effective_permissions AS
SELECT 
    s.entity_type,
    s.entity_id,
    s.recipient_id,
    s.permission_level,
    s.allow_comment,
    CASE 
        WHEN s.revoked_at IS NOT NULL THEN 'denied'
        WHEN s.expires_at IS NOT NULL AND s.expires_at < now() THEN 'expired'
        ELSE 'granted'
    END as status
FROM sharing.shares s
WHERE s.revoked_at IS NULL;

-- Share Requests (Inbox items related to sharing)
CREATE TABLE sharing.share_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_id UUID NOT NULL REFERENCES auth.users(id),
    recipient_id UUID NOT NULL REFERENCES auth.users(id),
    entity_type VARCHAR(32) NOT NULL,
    entity_id UUID NOT NULL,
    title VARCHAR(200) NOT NULL,
    message TEXT,
    priority VARCHAR(16) NOT NULL DEFAULT 'normal',
    status VARCHAR(16) NOT NULL DEFAULT 'pending', -- pending | accepted | rejected | expired
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    acted_at TIMESTAMPTZ,
    response_note TEXT
);

-- Indexes for share requests
CREATE INDEX ix_share_requests_recipient ON sharing.share_requests(recipient_id, status);
CREATE INDEX ix_share_requests_sender ON sharing.share_requests(sender_id);