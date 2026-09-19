-- ============================================================
-- Module: chat (M7) - Chat & Real-time Communication
-- Architecture Reference: Sections 8.1, 8.2, 8.3
-- ============================================================

-- Rooms table
CREATE TABLE chat.rooms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(160) NOT NULL,
    linked_type VARCHAR(32), -- task | meeting | goal | NULL (free room)
    linked_id UUID,
    owner_id UUID NOT NULL REFERENCES auth.users(id),
    is_archived BOOLEAN NOT NULL DEFAULT FALSE,
    archived_at TIMESTAMPTZ,
    archive_object_key VARCHAR(512), -- S3 path for archived content
    retention_days SMALLINT NOT NULL DEFAULT 365,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

-- Indexes for rooms
CREATE INDEX ix_rooms_linked ON chat.rooms(linked_type, linked_id);
CREATE INDEX ix_rooms_owner ON chat.rooms(owner_id);
CREATE INDEX ix_rooms_archived ON chat.rooms(is_archived) WHERE is_archived = TRUE;

-- Room Members table
CREATE TABLE chat.room_members (
    room_id UUID NOT NULL REFERENCES chat.rooms(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    role VARCHAR(16) NOT NULL DEFAULT 'member', -- owner | moderator | member | readonly
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_read_message_id UUID,
    muted_until TIMESTAMPTZ,
    left_at TIMESTAMPTZ,
    
    CONSTRAINT uq_room_member UNIQUE (room_id, user_id)
);

-- Indexes for room members
CREATE INDEX ix_room_members_room ON chat.room_members(room_id);
CREATE INDEX ix_room_members_user ON chat.room_members(user_id);

-- Messages table
CREATE TABLE chat.messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    room_id UUID NOT NULL REFERENCES chat.rooms(id) ON DELETE CASCADE,
    sender_id UUID NOT NULL REFERENCES auth.users(id),
    reply_to_id UUID REFERENCES chat.messages(id) ON DELETE SET NULL,
    body TEXT CHECK (char_length(body) <= 4000),
    body_html TEXT, -- Sanitized output
    file_id UUID, -- Reference to files.uploads
    message_type VARCHAR(16) NOT NULL DEFAULT 'text', -- text | file | system
    is_edited BOOLEAN NOT NULL DEFAULT FALSE,
    edited_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    
    -- Search vector for full-text search
    search_vector TSVECTOR
);

-- Indexes for messages
CREATE INDEX ix_messages_room ON chat.messages(room_id, created_at DESC) WHERE deleted_at IS NULL;
CREATE INDEX ix_messages_sender ON chat.messages(sender_id);
CREATE INDEX ix_messages_search ON chat.messages USING GIN(search_vector);
CREATE INDEX ix_messages_deleted ON chat.messages(deleted_at) WHERE deleted_at IS NOT NULL;

-- Files uploads (shared across modules)
CREATE TABLE files.uploads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    uploader_id UUID NOT NULL REFERENCES auth.users(id),
    context_type VARCHAR(32) NOT NULL, -- chat | task_attachment | avatar
    context_id UUID,
    original_name VARCHAR(255) NOT NULL, -- For display only, not stored path
    object_key VARCHAR(512) NOT NULL UNIQUE, -- UUID-based, outside web root
    mime_declared VARCHAR(128),
    mime_detected VARCHAR(128), -- From magic number analysis
    size_bytes BIGINT NOT NULL CHECK (size_bytes <= 52428800), -- Max 50MB
    sha256 CHAR(64) NOT NULL, -- File hash
    scan_status VARCHAR(16) NOT NULL DEFAULT 'pending', -- pending | clean | infected | error
    scan_engine VARCHAR(32),
    scanned_at TIMESTAMPTZ,
    is_available BOOLEAN NOT NULL DEFAULT FALSE, -- False until AV scan completes
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ
);

-- Indexes for files
CREATE INDEX ix_uploads_scan ON files.uploads(scan_status) WHERE scan_status = 'pending';
CREATE INDEX ix_uploads_uploader ON files.uploads(uploader_id);
CREATE INDEX ix_uploads_available ON files.uploads(is_available) WHERE is_available = TRUE;