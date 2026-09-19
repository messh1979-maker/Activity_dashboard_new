-- ============================================================
-- Module: notification (M10) - Notification & Alerts
-- Architecture Reference: Sections 11.3, 11.4
-- ============================================================

-- Notifications table
CREATE TABLE notification.notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id),
    type VARCHAR(32) NOT NULL, -- system | mention | share | goal_update | task_due | mention
    title VARCHAR(200) NOT NULL,
    message TEXT,
    data JSONB, -- Additional data (goal_id, task_id, etc.)
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    action_url VARCHAR(512), -- URL to navigate on click
    action_text VARCHAR(100), -- Button text on click
    related_entity_type VARCHAR(32), -- goal | task | group | etc.
    related_entity_id UUID,
    priority VARCHAR(16) NOT NULL DEFAULT 'normal', -- normal | high | urgent
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    read_at TIMESTAMPTZ
);

-- Indexes for notifications
CREATE INDEX ix_notifications_user ON notification.notifications(user_id, is_read);
CREATE INDEX ix_notifications_created ON notification.notifications(created_at DESC);
CREATE INDEX ix_notifications_unread ON notification.notifications(user_id) WHERE is_read = FALSE;

-- Notification Preferences per user
CREATE TABLE notification.preferences (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id),
    email_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    push_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    inbox_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    types JSONB NOT NULL DEFAULT '{}', -- {goal_update: true, mention: false, ...}
    quiet_hours_start TIME,
    quiet_hours_end TIME,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for preferences
CREATE INDEX ix_preferences_user ON notification.preferences(user_id);

-- Notification Log (for audit)
CREATE TABLE notification.log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id),
    action VARCHAR(100) NOT NULL, -- sent | read | dismissed
    notification_id UUID REFERENCES notification.notifications(id),
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for notification log
CREATE INDEX ix_log_user ON notification.log(user_id);