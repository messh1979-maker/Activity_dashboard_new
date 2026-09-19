-- ============================================================
-- Module: calendar (M5) - Calendar & Scheduling
-- Architecture Reference: Sections 9.3, 10.4
-- ============================================================

-- Calendar Events table
CREATE TABLE calendar.events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    owner_id UUID NOT NULL REFERENCES auth.users(id),
    privacy_level groups.privacy_level NOT NULL DEFAULT 'team_only',
    
    -- Timing
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ NOT NULL,
    all_day BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Recurrence
    recurrence_rule VARCHAR(100), -- iCalendar RRULE format
    recurrence_exceptions DATE[], -- Exceptions to recurrence
    
    -- Status
    status VARCHAR(16) NOT NULL DEFAULT 'active', -- active | cancelled | rescheduled
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

-- Calendar Event Attendees
CREATE TABLE calendar.attendees (
    event_id UUID NOT NULL REFERENCES calendar.events(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id),
    response_status VARCHAR(16) NOT NULL DEFAULT 'pending', -- pending | accepted | declined | tentative
    notified_at TIMESTAMPTZ,
    rsvp BOOLEAN NOT NULL DEFAULT FALSE,
    
    CONSTRAINT uq_event_attendee UNIQUE (event_id, user_id)
);

-- Indexes
CREATE INDEX ix_calendar_events_owner ON calendar.events(owner_id);
CREATE INDEX ix_calendar_events_privacy ON calendar.events(privacy_level);
CREATE INDEX ix_calendar_events_start ON calendar.events(start_time);
CREATE INDEX ix_calendar_attendees_event ON calendar.attendees(event_id);
CREATE INDEX ix_calendar_attendees_user ON calendar.attendees(user_id);

-- Meeting Notes (linked to events)
CREATE TABLE calendar.notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL REFERENCES calendar.events(id) ON DELETE CASCADE,
    author_id UUID REFERENCES auth.users(id),
    content TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for notes
CREATE INDEX ix_notes_event ON calendar.notes(event_id);