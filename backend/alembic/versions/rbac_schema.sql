-- ============================================================
-- Module: rbac (M2) - Role-Based Access Control
-- Architecture Reference: Sections 7.1, 7.3, 7.4, 11.1
-- ============================================================

-- Permissions table
CREATE TABLE rbac.permissions (
    id SERIAL PRIMARY KEY,
    code VARCHAR(100) NOT NULL UNIQUE, -- Format: module.action
    module VARCHAR(40) NOT NULL,
    action VARCHAR(40) NOT NULL,
    title_fa VARCHAR(120) NOT NULL,
    is_dangerous BOOLEAN NOT NULL DEFAULT FALSE, -- Requires secondary confirmation
    description TEXT
);

-- Roles table
CREATE TABLE rbac.roles (
    id SMALLSERIAL PRIMARY KEY,
    code VARCHAR(32) NOT NULL UNIQUE, -- super_admin | admin | manager | user | viewer
    title_fa VARCHAR(64) NOT NULL,
    level SMALLINT NOT NULL, -- For privilege escalation prevention (1-10)
    is_system BOOLEAN NOT NULL DEFAULT TRUE,
    description TEXT
);

-- Role-Permission junction
CREATE TABLE rbac.role_permissions (
    role_id SMALLINT NOT NULL REFERENCES rbac.roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES rbac.permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- User-Roles junction with scoping
CREATE TABLE rbac.user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL, -- Logical reference to auth.users
    role_id SMALLINT NOT NULL REFERENCES rbac.roles(id) ON DELETE CASCADE,
    scope_type VARCHAR(16) NOT NULL DEFAULT 'global', -- global | group
    scope_id UUID, -- group_id for group-scoped roles (NULL = global scope)
    granted_by UUID,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    source VARCHAR(16) NOT NULL DEFAULT 'manual' -- manual | ldap_group
);

-- Unique role assignment per scope (NULL scope_id = global; NULLs are
-- distinct in plain UNIQUE, hence two partial indexes)
CREATE UNIQUE INDEX uq_user_role_noscope
    ON rbac.user_roles(user_id, role_id, scope_type)
    WHERE scope_id IS NULL;
CREATE UNIQUE INDEX uq_user_role_scoped
    ON rbac.user_roles(user_id, role_id, scope_type, scope_id)
    WHERE scope_id IS NOT NULL;
CREATE INDEX idx_user_roles_user ON rbac.user_roles(user_id);
CREATE INDEX idx_user_roles_scope ON rbac.user_roles(scope_type, scope_id);

-- Privilege Escalation Prevention View
CREATE VIEW rbac.max_user_role_level AS
SELECT user_id, MAX(rbac.roles.level) as max_level
FROM rbac.user_roles
JOIN rbac.roles ON rbac.user_roles.role_id = rbac.roles.id
GROUP BY user_id;