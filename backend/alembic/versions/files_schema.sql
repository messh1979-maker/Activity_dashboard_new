-- ============================================================
-- Module: files (M13) - File Storage & Upload
-- Architecture Reference: Sections 8.2, 11.1
-- ============================================================

-- Uploads table (already defined in chat module, but standalone too)
-- This is the standalone definition for modules that don't use chat's files table

-- File Uploads table is created by chat_schema.sql (identical definition);
-- only the extra composite index is added here.
CREATE INDEX IF NOT EXISTS ix_uploads_scan_status ON files.uploads(scan_status, created_at);

-- Virus Scan Queue (for Celery/background processing)
CREATE TABLE files.scan_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    upload_id UUID NOT NULL REFERENCES files.uploads(id) ON DELETE CASCADE,
    status VARCHAR(16) NOT NULL DEFAULT 'pending', -- pending | scanning | completed
    clamav_message TEXT,
    scanned_at TIMESTAMPTZ,
    retry_count SMALLINT NOT NULL DEFAULT 0,
    max_retries SMALLINT NOT NULL DEFAULT 3,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at TIMESTAMPTZ
);

-- Indexes for scan queue
CREATE INDEX ix_scan_queue_status ON files.scan_queue(status);
CREATE INDEX ix_scan_queue_upload ON files.scan_queue(upload_id);

-- File Access Logs
CREATE TABLE files.access_logs (
    id BIGSERIAL PRIMARY KEY,
    upload_id UUID NOT NULL REFERENCES files.uploads(id),
    ip_address INET,
    user_id UUID REFERENCES auth.users(id),
    accessed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    action VARCHAR(32) NOT NULL, -- download | view | share
    
    CONSTRAINT fk_access_upload FOREIGN KEY (upload_id) REFERENCES files.uploads(id) ON DELETE CASCADE
);

-- Index for access logs
CREATE INDEX ix_access_logs_upload ON files.access_logs(upload_id);
CREATE INDEX ix_access_logs_user ON files.access_logs(user_id);