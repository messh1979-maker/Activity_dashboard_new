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
    failure_reason VARCHAR(100), -- Internal code, not user-facing message
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

-- Hash Chain Function (Trigger)
CREATE OR REPLACE FUNCTION audit.compute_row_hash() RETURNS TRIGGER AS $$
DECLARE
    material TEXT;
BEGIN
    material := '|' || 
        COALESCE(NEW.prev_hash, 'GENESIS') || '|' ||
        COALESCE(NEW.user_id::text, '') || '|' ||
        COALESCE(NEW.action, '') || '|' ||
        TO_CHAR(NEW.timestamp, 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') || '|' ||
        COALESCE(NEW.ip_address::text, '') || '|' ||
        COALESCE(NEW.mac_address, '') || '|' ||
        COALESCE(NEW.result, '') || '|' ||
        COALESCE(NEW.details::text, '') ||
        '|' || COALESCE(NEW.old_value::text, '') || '|' || COALESCE(NEW.new_value::text, '');
    
    NEW.row_hash := ENCODE(DIGEST(material, 'sha256'), 'hex');
    NEW.prev_hash := COALESCE((SELECT row_hash FROM audit.audit_logs ORDER BY id DESC LIMIT 1), 'GENESIS');
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger to audit_logs
CREATE TRIGGER trg_audit_row_hash
BEFORE INSERT ON audit.audit_logs
FOR EACH ROW EXECUTE FUNCTION audit.compute_row_hash();

-- Same trigger for login_audit_logs
CREATE TRIGGER trg_login_audit_row_hash
BEFORE INSERT ON audit.login_audit_logs
FOR EACH ROW EXECUTE FUNCTION audit.compute_row_hash();

-- Integrity Check Function (Daily job)
CREATE OR REPLACE FUNCTION audit.check_integrity() RETURNS VOID AS $$
DECLARE
    rec RECORD;
    expected_hash CHAR(64);
BEGIN
    FOR rec IN SELECT id, prev_hash, row_hash FROM audit.audit_logs ORDER BY id LOOP
        -- Verify chain link
        IF rec.prev_hash != (
            SELECT row_hash FROM audit.audit_logs WHERE id = rec.id - 1
        ) THEN
            -- Chain broken - raise notice
            RAISE NOTICE 'Audit chain broken at log ID %', rec.id;
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Policy: Restrict app_user to only INSERT/SELECT
REVOKE ALL ON ALL TABLES IN SCHEMA audit FROM app_user;
GRANT INSERT, SELECT ON ALL TABLES IN SCHEMA audit TO app_user;
GRANT EXECUTE ON FUNCTION audit.compute_row_hash TO app_user;