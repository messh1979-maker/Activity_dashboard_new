-- ============================================================
-- Module: planning (M4) - Goals & Planning
-- Architecture Reference: Sections 4.5, 9.10, 12.12
-- ============================================================

-- Goals table
CREATE TABLE planning.goals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    owner_id UUID NOT NULL REFERENCES auth.users(id),
    privacy_level groups.privacy_level NOT NULL DEFAULT 'team_only',
    progress_pct SMALLINT NOT NULL DEFAULT 0 CHECK (progress_pct >= 0 AND progress_pct <= 100),
    start_date DATE,
    due_date DATE,
    status VARCHAR(16) NOT NULL DEFAULT 'active', -- active | completed | archived
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

-- Tasks table (linked to goals)
CREATE TABLE planning.tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    goal_id UUID REFERENCES planning.goals(id) ON DELETE SET NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    assignee_id UUID REFERENCES auth.users(id), -- Optional assignment
    owner_id UUID NOT NULL REFERENCES auth.users(id), -- Who created it
    privacy_level groups.privacy_level NOT NULL DEFAULT 'team_only',
    status VARCHAR(16) NOT NULL DEFAULT 'pending', -- pending | in_progress | completed | deferred
    priority VARCHAR(16) NOT NULL DEFAULT 'normal', -- normal | high | low
    due_date DATE,
    progress_pct SMALLINT NOT NULL DEFAULT 0 CHECK (progress_pct >= 0 AND progress_pct <= 100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

-- Tags table (many-to-many with goals)
CREATE TABLE planning.tags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(64) NOT NULL UNIQUE,
    color VARCHAR(7) NOT NULL DEFAULT '#3B82F6', -- Hex color code
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Goals-Tags junction table
CREATE TABLE planning.goal_tags (
    goal_id UUID NOT NULL REFERENCES planning.goals(id) ON DELETE CASCADE,
    tag_id UUID NOT NULL REFERENCES planning.tags(id) ON DELETE CASCADE,
    PRIMARY KEY (goal_id, tag_id)
);

-- Indexes for planning module
CREATE INDEX ix_goals_owner ON planning.goals(owner_id);
CREATE INDEX ix_goals_status ON planning.goals(status);
CREATE INDEX ix_goals_privacy ON planning.goals(privacy_level);
CREATE INDEX ix_tasks_goal ON planning.tasks(goal_id);
CREATE INDEX ix_tasks_assignee ON planning.tasks(assignee_id);
CREATE INDEX ix_tasks_status ON planning.tasks(status);
CREATE INDEX ix_tags_name ON planning.tags(name);
CREATE INDEX ix_goal_tags_goal ON planning.goal_tags(goal_id);
CREATE INDEX ix_goal_tags_tag ON planning.goal_tags(tag_id);