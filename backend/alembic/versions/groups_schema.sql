-- ============================================================
-- Module: groups (M3) - Groups & Privacy
-- Architecture Reference: Sections 4.4, 7.2, 7.3, 11.2
-- ============================================================

-- Privacy levels enum
CREATE TYPE groups.privacy_level AS ENUM (
    'fully_private',      -- Only owner can see
    'team_only',          -- Team members can see aggregate stats
    'selected',           -- Only specified exceptions can see
    'fully_transparent'   -- Everyone can see everything
);

-- Groups table with hierarchical structure (LTREE)
CREATE TABLE groups.groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id UUID REFERENCES groups.groups(id) ON DELETE RESTRICT,
    path LTREE, -- Hierarchical path for efficient queries
    name VARCHAR(128) NOT NULL,
    description TEXT,
    ldap_group_dn VARCHAR(512),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

-- Index for hierarchical queries
CREATE INDEX ix_groups_path ON groups.groups USING GIST(path);
CREATE INDEX ix_groups_parent ON groups.groups(parent_id) WHERE is_active = TRUE;
CREATE INDEX ix_groups_owner ON groups.groups(created_by);

-- Group Members table
CREATE TABLE groups.group_members (
    group_id UUID NOT NULL REFERENCES groups.groups(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    is_manager BOOLEAN NOT NULL DEFAULT FALSE,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    added_by UUID,
    
    CONSTRAINT uq_group_member UNIQUE (group_id, user_id)
);

-- Indexes for group members
CREATE INDEX ix_group_members_user ON groups.group_members(user_id);
CREATE INDEX ix_group_members_group ON groups.group_members(group_id);

-- Privacy Settings per user (can be overridden per entity type)
CREATE TABLE groups.privacy_settings (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    default_level groups.privacy_level NOT NULL DEFAULT 'team_only',
    
    -- Per-entity-type overrides
    goals_level groups.privacy_level,
    tasks_level groups.privacy_level,
    meetings_level groups.privacy_level,
    progress_level groups.privacy_level,
    
    -- Manager comment & notification settings
    allow_manager_comment BOOLEAN NOT NULL DEFAULT TRUE,
    notify_on_manager_view BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Privacy Exceptions (for 'selected' level)
CREATE TABLE groups.privacy_exceptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL,
    viewer_id UUID NOT NULL,
    entity_type VARCHAR(32), -- NULL = all types, otherwise: goal | task | meeting
    can_comment BOOLEAN NOT NULL DEFAULT FALSE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    
    -- Ensure uniqueness per owner-viewer-entity combination
    CONSTRAINT uq_privacy_exception UNIQUE (owner_id, viewer_id, entity_type)
);

-- Indexes for privacy queries
CREATE INDEX ix_privacy_owner ON groups.privacy_exceptions(owner_id);
CREATE INDEX ix_privacy_viewer ON groups.privacy_exceptions(viewer_id);

-- NOTE: groups.effective_privacy view removed 2026-09-19: it referenced
-- columns (owner_id, privacy_level, can_comment) that exist in no table in
-- scope. Reintroduce it once a proper privacy-source table is designed.