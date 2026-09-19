-- ============================================================
-- Module: inbox (M8) - Inbox/Outbox
-- Architecture Reference: Sections 9.1, 9.2
-- ============================================================

-- Inbox Items types enum
CREATE TYPE inbox.item_action AS ENUM ('pending', 'accepted', 'rejected', 'deferred', 'expired');
CREATE TYPE inbox.receipt_state AS ENUM ('sent', 'seen', 'acted');

-- Inbox Items table
CREATE TABLE inbox.items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_id UUID NOT NULL REFERENCES auth.users(id),
    recipient_id UUID NOT NULL REFERENCES auth.users(id),
    item_type VARCHAR(40) NOT NULL, -- meeting_invite | share_request | task_assignment | chat_invoice | approval
    entity_type VARCHAR(32), -- NULL | goal | task | meeting
    entity_id UUID,
    title VARCHAR(200) NOT NULL,
    message TEXT,
    priority VARCHAR(16) NOT NULL DEFAULT 'normal',
    action_state inbox.item_action NOT NULL DEFAULT 'pending',
    receipt_state inbox.receipt_state NOT NULL DEFAULT 'sent',
    seen_at TIMESTAMPTZ,
    acted_at TIMESTAMPTZ,
    defer_until TIMESTAMPTZ, -- For "deferred" action
    response_note TEXT,
    due_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for inbox queries
CREATE INDEX ix_inbox_recipient ON inbox.items(recipient_id, action_state, created_at DESC);
CREATE INDEX ix_inbox_sender ON inbox.items(sender_id, created_at DESC);
CREATE INDEX ix_inbox_deferred ON inbox.items(defer_until) WHERE action_state = 'deferred';
CREATE INDEX ix_inbox_item_type ON inbox.items(item_type, recipient_id);

-- Receipts table (tracking read/acted state)
CREATE TABLE inbox.receipts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    item_id UUID NOT NULL REFERENCES inbox.items(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id), -- The viewer
    state inbox.receipt_state NOT NULL DEFAULT 'sent',
    seen_at TIMESTAMPTZ,
    acted_at TIMESTAMPTZ,
    note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    CONSTRAINT uq_item_user_receipt UNIQUE (item_id, user_id)
);

-- Indexes for receipts
CREATE INDEX ix_receipts_item ON inbox.receipts(item_id);
CREATE INDEX ix_receipts_user ON inbox.receipts(user_id);

-- Outbox Items table (sent items with read receipts)
CREATE TABLE inbox.outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_id UUID NOT NULL REFERENCES auth.users(id),
    recipient_id UUID NOT NULL REFERENCES auth.users(id),
    item_type VARCHAR(40) NOT NULL,
    entity_type VARCHAR(32),
    entity_id UUID,
    title VARCHAR(200) NOT NULL,
    message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    read_receipt BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Read receipt tracking
    recipient_acknowledged_at TIMESTAMPTZ,
    recipient_acknowledged_note TEXT
);

-- Indexes for outbox
CREATE INDEX ix_outbox_sender ON inbox.outbox(sender_id, created_at DESC);
CREATE INDEX ix_outbox_recipient ON inbox.outbox(recipient_id, created_at DESC);
CREATE INDEX ix_outbox_read ON inbox.outbox(read_receipt) WHERE read_receipt = TRUE;