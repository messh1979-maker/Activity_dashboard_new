-- ============================================================
-- Module: ssoldap (M12) - SSO & LDAP Integration
-- Architecture Reference: Sections 1.4, 5.2, 11.2
-- ============================================================

-- LDAP Settings (Singleton - only one row)
CREATE TABLE ssoldap.ldap_settings (
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
    attr_national_id VARCHAR(64) DEFAULT 'employeeID', -- AD attribute for national ID
    attr_username VARCHAR(64) DEFAULT 'sAMAccountName',
    attr_email VARCHAR(256) DEFAULT 'mail',
    attr_display_name VARCHAR(128) DEFAULT 'displayName',
    attr_groups VARCHAR(512) DEFAULT 'memberOf', -- Group DN list
    bind_dn VARCHAR(512) NOT NULL,
    bind_password_enc BYTEA NOT NULL, -- Encrypted
    bind_password_nonce BYTEA NOT NULL,
    auto_provision BOOLEAN NOT NULL DEFAULT TRUE, -- Auto-create users on first login
    default_role_id SMALLINT, -- Default role for auto-provisioned users
    kerberos_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    kerberos_spn VARCHAR(255), -- Service Principal Name
    kerberos_keytab_path VARCHAR(512), -- Path to keytab file
    last_test_at TIMESTAMPTZ,
    last_test_result JSONB, -- {success: boolean, message: string}
    updated_by UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Kerberos Tickets Cache (for tracking)
CREATE TABLE ssoldap.kerberos_tickets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id),
    ticket_name VARCHAR(256) NOT NULL, -- Ticket name
    spn VARCHAR(255), -- Service Principal Name
    issue_date TIMESTAMPTZ,
    expiration TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes
CREATE INDEX idx_ssoldap_tickets_user ON ssoldap.kerberos_tickets(user_id);

-- Login Attempts tracking with SSO
CREATE TABLE ssoldap.login_attempts (
    id SERIAL PRIMARY KEY,
    username VARCHAR(128) NOT NULL,
    auth_method VARCHAR(32) NOT NULL, -- sso | kerberos | ldap
    success BOOLEAN NOT NULL,
    ip_address INET,
    mac_address VARCHAR(17),
    user_agent TEXT,
    risk_score SMALLINT, -- 0-100
    failure_reason VARCHAR(100),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes
CREATE INDEX idx_ssoleep_logins_user ON ssoldap.login_attempts(username);
CREATE INDEX idx_ssoleep_logins_timestamp ON ssoldap.login_attempts(timestamp DESC);