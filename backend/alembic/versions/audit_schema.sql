-- ============================================================
-- Module: audit (M11) - Audit & Logging
-- Architecture Reference: Sections 4.8, 11.5, 11.6
-- ============================================================

-- Audit Logs table (Append-only + Hash Chain)
CREATE TABLE audit.audit_logs (
    id BIGSERIAL,
    user_id UUID,
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50),
    entity_id UUID,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Identity & Device
    ip_address INET,
    mac_address VARCHAR(17), -- Desktop; NULL/Web
    mac_verified BOOLEAN NOT NULL DEFAULT FALSE, -- Was HMAC verified?
    device_fingerprint VARCHAR(255),
    device_id UUID, -- FK to auth.user_devices
    user_agent TEXT,
    session_id UUID,

    -- Result
    result VARCHAR(20) NOT NULL, -- success | failure | denied
    details JSONB,
    old_value JSONB,
    new_value JSONB,
    geo_location JSONB,
    request_id UUID,
    correlation_id UUID,

    -- Hash Chain (Integrity)
    prev_hash CHAR(64), -- Chain link to previous record
    row_hash CHAR(64) NOT NULL, -- Computed hash of this record
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Partitioned tables must include the partition key in the PK
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Partition strategy (monthly for performance)
CREATE TABLE audit.audit_logs_2026_09 PARTITION OF audit.audit_logs
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');

CREATE TABLE audit.audit_logs_2026_10 PARTITION OF audit.audit_logs
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');

-- Safety net: without a DEFAULT partition every INSERT after the last dated
-- partition fails and login/audit writes (same transaction as the business
-- operation) would take the whole request down. The audit_archive worker
-- creates the next monthly partitions ahead of time (architecture 3.1).
CREATE TABLE audit.audit_logs_default PARTITION OF audit.audit_logs DEFAULT;

-- Indexes for audit queries
CREATE INDEX idx_audit_user_time ON audit.audit_logs(user_id, timestamp DESC);
CREATE INDEX idx_audit_mac ON audit.audit_logs(mac_address) WHERE mac_address IS NOT NULL;
CREATE INDEX idx_audit_ip ON audit.audit_logs(ip_address);
CREATE INDEX idx_audit_action ON audit.audit_logs(action, timestamp DESC);
CREATE INDEX idx_audit_fingerprint ON audit.audit_logs(device_fingerprint);
CREATE INDEX idx_audit_entity ON audit.audit_logs(entity_type, entity_id, timestamp DESC);

-- Login Audit Logs (specific to authentication)
CREATE TABLE audit.login_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID,
    username VARCHAR(100), -- Even for non-existent users
    national_id_hash CHAR(64), -- Never raw national ID
    auth_method VARCHAR(20) NOT NULL, -- local | sso | ldap | kerberos | recovery
    mfa_used VARCHAR(16), -- totp | email | sms | recovery | none
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip_address INET,
    mac_address VARCHAR(17),
    mac_verified BOOLEAN NOT NULL DEFAULT FALSE,
    device_fingerprint VARCHAR(255),
    device_is_trusted BOOLEAN,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(255), -- Internal code, not user-facing message
    session_id UUID,
    geo_location JSONB,
    risk_score SMALLINT, -- 0-100, for anomaly detection
    prev_hash CHAR(64),
    row_hash CHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for login audit
CREATE INDEX idx_login_audit_user ON audit.login_audit_logs(user_id, timestamp DESC);
CREATE INDEX idx_login_audit_mac ON audit.login_audit_logs(mac_address);
CREATE INDEX idx_login_audit_ip ON audit.login_audit_logs(ip_address, timestamp DESC);
CREATE INDEX idx_login_failed ON audit.login_audit_logs(username, timestamp DESC) WHERE success = FALSE;

-- ------------------------------------------------------------
-- Hash chain: computed by the application (AuditService) inside the same
-- transaction as the business operation, under an advisory lock, exactly as
-- architecture 4.8 / 12.3 specify. (A DB trigger that recomputes row_hash
-- would overwrite the app's value with a different formula and break
-- verification, so none is installed.)
-- ------------------------------------------------------------

-- Append-only enforcement (ADR-10): UPDATE / DELETE / TRUNCATE are rejected
-- for every role, including the table owner. Retention is done by
-- DETACH PARTITION, which is DDL and unaffected.
CREATE OR REPLACE FUNCTION audit.forbid_mutation() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit tables are append-only (% on %.% rejected)',
        TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_logs_append_only
BEFORE UPDATE OR DELETE ON audit.audit_logs
FOR EACH ROW EXECUTE FUNCTION audit.forbid_mutation();

CREATE TRIGGER trg_audit_logs_no_truncate
BEFORE TRUNCATE ON audit.audit_logs
FOR EACH STATEMENT EXECUTE FUNCTION audit.forbid_mutation();

CREATE TRIGGER trg_login_audit_append_only
BEFORE UPDATE OR DELETE ON audit.login_audit_logs
FOR EACH ROW EXECUTE FUNCTION audit.forbid_mutation();

CREATE TRIGGER trg_login_audit_no_truncate
BEFORE TRUNCATE ON audit.login_audit_logs
FOR EACH STATEMENT EXECUTE FUNCTION audit.forbid_mutation();

-- Least privilege for the application role (only when that role exists;
-- an unconditional REVOKE/GRANT aborts the whole migration on a fresh DB).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
        REVOKE UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA audit FROM app_user;
        GRANT USAGE ON SCHEMA audit TO app_user;
        GRANT INSERT, SELECT ON ALL TABLES IN SCHEMA audit TO app_user;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA audit TO app_user;
    END IF;
END
$$;
