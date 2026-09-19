-- ============================================================
-- Module: auth (M1) - Authentication & Users
-- Architecture Reference: Sections 4.2, 6.5, 7.1, 11.2
-- ============================================================

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "ltree";

-- Types
CREATE TYPE auth.auth_mode AS ENUM ('local', 'sso', 'both');
CREATE TYPE auth.mfa_method AS ENUM ('totp', 'email', 'sms', 'recovery', 'none');
CREATE DOMAIN auth.risk_score_range AS SMALLINT CHECK (VALUE BETWEEN 0 AND 100);
CREATE TYPE auth.login_method AS ENUM ('local', 'sso', 'ldap', 'kerberos', 'recovery');
CREATE TYPE auth.session_type AS ENUM ('access', 'refresh');

-- Users table
CREATE TABLE auth.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Identity (national ID encrypted)
    username VARCHAR(64) NOT NULL,
    national_id_enc BYTEA NOT NULL, -- AES-256-GCM encrypted
    national_id_nonce BYTEA NOT NULL, -- Unique nonce per encryption
    national_id_hash CHAR(64) NOT NULL, -- HMAC-SHA256(national_id, PEPPER) for searchable lookup
    national_id_last4 CHAR(4) NOT NULL, -- Masked display: ******1234
    display_name VARCHAR(128) NOT NULL,
    employee_code VARCHAR(32),
    
    -- Authentication
    auth_mode auth.auth_mode NOT NULL DEFAULT 'local',
    sso_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ldap_dn TEXT,
    ldap_object_guid UUID,
    ldap_sam_account VARCHAR(256),
    ldap_synced_at TIMESTAMPTZ,
    
    -- Password (Argon2id hash)
    password_hash TEXT, -- NULL if SSO only
    password_changed_at TIMESTAMPTZ,
    password_expires_at TIMESTAMPTZ, -- 90-day policy
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    token_version INTEGER NOT NULL DEFAULT 1,
    
    -- MFA
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_method VARCHAR(16),
    mfa_secret_enc BYTEA, -- Encrypted TOTP secret (never in API response)
    mfa_secret_nonce BYTEA,
    mfa_enrolled_at TIMESTAMPTZ,
    mfa_recovery_codes_used SMALLINT NOT NULL DEFAULT 0,
    
    -- Status & Security
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    failed_login_count SMALLINT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    lockout_level SMALLINT NOT NULL DEFAULT 0, -- Exponential backoff
    last_login_at TIMESTAMPTZ,
    allowed_ip_ranges CIDR[], -- User IP whitelist
    require_trusted_device BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Preferences
    theme VARCHAR(10) NOT NULL DEFAULT 'system',
    locale VARCHAR(10) NOT NULL DEFAULT 'fa-IR',
    timezone VARCHAR(64) NOT NULL DEFAULT 'Asia/Tehran',
    privacy_level VARCHAR(20) NOT NULL DEFAULT 'team_only',
    
    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    
    -- Constraints
    CONSTRAINT ck_auth_method CHECK (password_hash IS NOT NULL OR sso_enabled = TRUE)
);

CREATE UNIQUE INDEX uq_users_national_hash
    ON auth.users(national_id_hash) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_users_username
    ON auth.users(LOWER(username)) WHERE deleted_at IS NULL;

-- User Devices table
CREATE TABLE auth.user_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    device_fingerprint VARCHAR(255) NOT NULL, -- SHA256 hash
    mac_address VARCHAR(17), -- NULL for web clients
    mac_source VARCHAR(16), -- psutil | uuid_getnode | unavailable
    platform VARCHAR(16) NOT NULL, -- desktop | web | mobile_web
    device_label VARCHAR(128), -- User-assigned name
    os_info VARCHAR(128),
    user_agent TEXT,
    hmac_key_enc BYTEA, -- Encrypted HMAC key for device binding
    is_trusted BOOLEAN NOT NULL DEFAULT FALSE,
    trusted_at TIMESTAMPTZ,
    trusted_by_mfa BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_ip INET,
    is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
    blocked_reason VARCHAR(255),
    
    CONSTRAINT uq_device_user_fingerprint UNIQUE (user_id, device_fingerprint)
);

CREATE INDEX idx_device_mac ON auth.user_devices(mac_address) WHERE mac_address IS NOT NULL;

-- Sessions table
CREATE TABLE auth.sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    device_id UUID REFERENCES auth.user_devices(id) ON DELETE SET NULL,
    refresh_hash CHAR(64) NOT NULL UNIQUE, -- For refresh token rotation
    family_id UUID NOT NULL, -- For detecting token reuse
    auth_method auth.login_method NOT NULL, -- local | ldap | kerberos
    mfa_satisfied BOOLEAN NOT NULL DEFAULT FALSE,
    ip_address INET,
    geo_location JSONB,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_reason VARCHAR(64)
);

CREATE INDEX idx_sessions_active ON auth.sessions(user_id) WHERE revoked_at IS NULL;

-- MFA Recovery Codes
CREATE TABLE auth.mfa_recovery_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    code_hash CHAR(64) NOT NULL, -- Hashed recovery code
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_recovery_code UNIQUE (code_hash)
);

-- IP Access Rules
CREATE TABLE auth.ip_access_rules (
    id SERIAL PRIMARY KEY,
    scope VARCHAR(16) NOT NULL, -- global | user
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    cidr CIDR NOT NULL,
    rule_type VARCHAR(10) NOT NULL, -- allow | deny
    reason VARCHAR(255),
    expires_at TIMESTAMPTZ,
    created_by UUID REFERENCES auth.users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- LDAP Settings (Singleton)
CREATE TABLE auth.ldap_settings (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    server_host VARCHAR(255) NOT NULL,
    server_port INTEGER NOT NULL DEFAULT 636,
    use_ssl BOOLEAN NOT NULL DEFAULT TRUE,
    use_start_tls BOOLEAN NOT NULL DEFAULT FALSE,
    validate_certificate BOOLEAN NOT NULL DEFAULT TRUE,
    ca_certificate TEXT,
    base_dn VARCHAR(512) NOT NULL,
    user_search_base VARCHAR(512),
    group_search_base VARCHAR(512),
    user_filter VARCHAR(512) NOT NULL DEFAULT '(&(objectClass=user)(sAMAccountName={username}))',
    attr_national_id VARCHAR(64) DEFAULT 'employeeID', -- AD attribute mapping
    bind_dn VARCHAR(512) NOT NULL,
    bind_password_enc BYTEA NOT NULL, -- Encrypted
    bind_password_nonce BYTEA NOT NULL,
    auto_provision BOOLEAN NOT NULL DEFAULT TRUE,
    default_role_id SMALLINT,
    kerberos_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    kerberos_spn VARCHAR(255),
    kerberos_keytab_path VARCHAR(512),
    last_test_at TIMESTAMPTZ,
    last_test_result JSONB,
    updated_by UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for auth module
CREATE INDEX idx_users_active ON auth.users(is_active) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_deleted ON auth.users(deleted_at) WHERE deleted_at IS NOT NULL;
CREATE INDEX idx_sessions_user ON auth.sessions(user_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_devices_user ON auth.user_devices(user_id);
CREATE INDEX idx_users_ldap_guid ON auth.users(ldap_object_guid) WHERE ldap_object_guid IS NOT NULL;