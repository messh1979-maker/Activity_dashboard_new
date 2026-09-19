-- ============================================================
-- Module: reporting (M9) - Reporting & Dashboards
-- Architecture Reference: Sections 10.1, 10.2, 10.3
-- ============================================================

-- Dashboard Layouts table
CREATE TABLE reporting.dashboard_layouts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id),
    name VARCHAR(64) NOT NULL,
    view_mode VARCHAR(16) NOT NULL DEFAULT 'daily', -- daily | weekly | monthly
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    schema_version SMALLINT NOT NULL DEFAULT 1, -- For migration compatibility
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX uq_layout_default
    ON reporting.dashboard_layouts(user_id, view_mode) WHERE is_default = TRUE;

-- User Dashboard Settings (per-block configuration)
CREATE TABLE reporting.user_dashboard_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id),
    layout_id UUID NOT NULL REFERENCES reporting.dashboard_layouts(id) ON DELETE CASCADE,
    block_key VARCHAR(48) NOT NULL,
    is_visible BOOLEAN NOT NULL DEFAULT TRUE,
    position_x SMALLINT NOT NULL DEFAULT 0 CHECK (position_x BETWEEN 0 AND 11),
    position_y SMALLINT NOT NULL DEFAULT 0,
    width SMALLINT NOT NULL DEFAULT 4 CHECK (width BETWEEN 1 AND 12),
    height SMALLINT NOT NULL DEFAULT 4 CHECK (height BETWEEN 1 AND 20),
    is_collapsed BOOLEAN NOT NULL DEFAULT FALSE,
    config JSONB NOT NULL DEFAULT '{}', -- Widget-specific configuration
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Ensure within grid (position_x + width <= 12)
    CONSTRAINT ck_within_grid CHECK (position_x + width <= 12),
    
    -- Unique constraint: one setting per block per layout
    CONSTRAINT uq_layout_block UNIQUE (layout_id, block_key)
);

-- User Widget Settings (floating widgets like clock)
CREATE TABLE reporting.user_widget_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id),
    widget_key VARCHAR(48) NOT NULL, -- clock | quick_add | mini_calendar
    platform VARCHAR(16) NOT NULL DEFAULT 'all', -- desktop | web | all
    is_visible BOOLEAN NOT NULL DEFAULT TRUE,
    position_x INTEGER NOT NULL DEFAULT 20, -- Absolute coordinates
    position_y INTEGER NOT NULL DEFAULT 20,
    width INTEGER NOT NULL DEFAULT 260 CHECK (width BETWEEN 160 AND 640),
    height INTEGER NOT NULL DEFAULT 120 CHECK (height BETWEEN 80 AND 400),
    z_index SMALLINT NOT NULL DEFAULT 10,
    style JSONB NOT NULL DEFAULT '{}', -- {bg, fg, font_family, font_size, opacity}
    config JSONB NOT NULL DEFAULT '{}', -- {show_jalali, time_format, ...}
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Unique constraint per user-widget-platform
    CONSTRAINT uq_widget_user_platform UNIQUE (user_id, widget_key, platform)
);

-- Indexes for reporting queries
CREATE INDEX ix_dashboard_layouts_user ON reporting.dashboard_layouts(user_id);
CREATE INDEX ix_dashboard_settings_layout ON reporting.user_dashboard_settings(layout_id);
CREATE INDEX ix_dashboard_settings_block ON reporting.user_dashboard_settings(block_key);
CREATE INDEX ix_user_widgets_user ON reporting.user_widget_settings(user_id);
CREATE INDEX ix_user_widgets_key ON reporting.user_widget_settings(widget_key, platform);

-- Section Types for dashboard (default blocks)
CREATE TYPE reporting.section_type AS ENUM (
    'goals',
    'calendar', 
    'quick_actions',
    'recent_activity',
    'tags',
    'clock'
);

-- Default section configuration
CREATE TABLE reporting.default_sections (
    key VARCHAR(32) PRIMARY KEY,
    label VARCHAR(64) NOT NULL,
    description TEXT,
    default_blocks TEXT[] -- JSON array of block keys
);

-- Insert default section configurations
INSERT INTO reporting.default_sections (key, label, description, default_blocks) VALUES
('default', 'داشبورد پیش‌فرض', 'چیدمان پیش‌فرض برای کاربران جدید', ARRAY['clock', 'goals', 'quick-actions', 'recent-activity']),
('goals', 'اهداف', 'نمایش پیشرفت اهداف', ARRAY['goals']),
('calendar', 'تقویم', 'تقویم و Dates', ARRAY['calendar']),
('widgets', 'ویجت‌ها', 'ویجت‌های شناور', ARRAY['clock']),
('admin', 'ادمین', 'پنل مدیر', ARRAY['reports', 'users']);