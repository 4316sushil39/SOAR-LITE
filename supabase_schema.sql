-- ==============================================================================
-- SOAR Lite - Resilient Supabase PostgreSQL Database Schema
-- Run this entire script in the Supabase SQL Editor.
-- ==============================================================================

-- 1. Create Actions Table First
CREATE TABLE IF NOT EXISTS public.soar_actions (
    action_id TEXT PRIMARY KEY,
    playbook TEXT NOT NULL,
    target TEXT NOT NULL,
    rationale TEXT,
    requested_by TEXT NOT NULL DEFAULT 'lab-analyst',
    status TEXT NOT NULL,
    impact_simulation JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decision_by TEXT,
    decision_reason TEXT,
    rollback_simulation JSONB,
    execution_result JSONB,
    mode TEXT NOT NULL DEFAULT 'simulation'
);

-- 2. Create Audit Events Table (Independent Primary Table)
CREATE TABLE IF NOT EXISTS public.soar_audit_events (
    event_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- 3. Create Network Blocks Table
CREATE TABLE IF NOT EXISTS public.soar_network_blocks (
    block_id TEXT PRIMARY KEY,
    action_id TEXT,
    target TEXT NOT NULL,
    block_type TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active BOOLEAN NOT NULL DEFAULT true,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- 4. Safely Add Foreign Key Constraints (Only if not already present)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_soar_audit_action'
    ) THEN
        ALTER TABLE public.soar_audit_events 
        ADD CONSTRAINT fk_soar_audit_action 
        FOREIGN KEY (action_id) 
        REFERENCES public.soar_actions(action_id) 
        ON DELETE CASCADE;
    END IF;
EXCEPTION
    WHEN OTHERS THEN
        -- If foreign key cannot be added immediately, audit logging continues safely
        RAISE NOTICE 'Foreign key fk_soar_audit_action skipped: %', SQLERRM;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_soar_blocks_action'
    ) THEN
        ALTER TABLE public.soar_network_blocks 
        ADD CONSTRAINT fk_soar_blocks_action 
        FOREIGN KEY (action_id) 
        REFERENCES public.soar_actions(action_id) 
        ON DELETE SET NULL;
    END IF;
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE 'Foreign key fk_soar_blocks_action skipped: %', SQLERRM;
END $$;

-- 5. Create Performance Indexes
CREATE INDEX IF NOT EXISTS idx_soar_actions_status ON public.soar_actions(status);
CREATE INDEX IF NOT EXISTS idx_soar_actions_created_at ON public.soar_actions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_soar_audit_action_id ON public.soar_audit_events(action_id);
CREATE INDEX IF NOT EXISTS idx_soar_audit_timestamp ON public.soar_audit_events(timestamp ASC);
CREATE INDEX IF NOT EXISTS idx_soar_blocks_active ON public.soar_network_blocks(is_active);

-- 6. Enable Row Level Security (RLS) on each table
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'soar_actions') THEN
        ALTER TABLE public.soar_actions ENABLE ROW LEVEL SECURITY;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'soar_audit_events') THEN
        ALTER TABLE public.soar_audit_events ENABLE ROW LEVEL SECURITY;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'soar_network_blocks') THEN
        ALTER TABLE public.soar_network_blocks ENABLE ROW LEVEL SECURITY;
    END IF;
END $$;

-- 7. Create Permissive Access Policies (for anon and authenticated keys)
DO $$
BEGIN
    -- Policy for soar_actions
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'soar_actions' AND policyname = 'Allow all access to soar_actions'
    ) THEN
        CREATE POLICY "Allow all access to soar_actions"
        ON public.soar_actions
        FOR ALL
        TO anon, authenticated
        USING (true)
        WITH CHECK (true);
    END IF;

    -- Policy for soar_audit_events
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'soar_audit_events' AND policyname = 'Allow all access to soar_audit_events'
    ) THEN
        CREATE POLICY "Allow all access to soar_audit_events"
        ON public.soar_audit_events
        FOR ALL
        TO anon, authenticated
        USING (true)
        WITH CHECK (true);
    END IF;

    -- Policy for soar_network_blocks
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'soar_network_blocks' AND policyname = 'Allow all access to soar_network_blocks'
    ) THEN
        CREATE POLICY "Allow all access to soar_network_blocks"
        ON public.soar_network_blocks
        FOR ALL
        TO anon, authenticated
        USING (true)
        WITH CHECK (true);
    END IF;
END $$;

-- ==============================================================================
-- 8. LIVE MONITORING & VULNERABILITY SCHEMA EXTENSION
-- ==============================================================================

-- Create Devices Table
CREATE TABLE IF NOT EXISTS public.soar_devices (
    device_id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    ip_address TEXT DEFAULT '127.0.0.1',
    mac_address TEXT DEFAULT '',
    os_type TEXT DEFAULT 'windows',
    os_version TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'online',
    risk_score INTEGER NOT NULL DEFAULT 0,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- Create Events Table
CREATE TABLE IF NOT EXISTS public.soar_events (
    event_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'low',
    raw_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Create Threats Table
CREATE TABLE IF NOT EXISTS public.soar_threats (
    threat_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    numeric_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    status TEXT NOT NULL DEFAULT 'active',
    mitre_technique TEXT DEFAULT '',
    target TEXT NOT NULL,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ
);

-- Create Vulnerabilities Table
CREATE TABLE IF NOT EXISTS public.soar_vulnerabilities (
    vuln_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    cve_id TEXT DEFAULT '',
    title TEXT NOT NULL,
    software_name TEXT DEFAULT '',
    installed_version TEXT DEFAULT '',
    fixed_version TEXT DEFAULT '',
    cvss_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    severity TEXT NOT NULL DEFAULT 'low',
    description TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Create Playbook Runs Table
CREATE TABLE IF NOT EXISTS public.soar_playbook_runs (
    run_id TEXT PRIMARY KEY,
    playbook_name TEXT NOT NULL,
    target TEXT NOT NULL,
    parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'pending_approval',
    dry_run BOOLEAN NOT NULL DEFAULT true,
    executed_by TEXT NOT NULL DEFAULT 'system',
    execution_result JSONB NOT NULL DEFAULT '{}'::jsonb,
    rollback_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);

-- Performance Indexes for New Tables
CREATE INDEX IF NOT EXISTS idx_soar_devices_status ON public.soar_devices(status);
CREATE INDEX IF NOT EXISTS idx_soar_devices_last_seen ON public.soar_devices(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_soar_events_device_id ON public.soar_events(device_id);
CREATE INDEX IF NOT EXISTS idx_soar_events_timestamp ON public.soar_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_soar_threats_device_id ON public.soar_threats(device_id);
CREATE INDEX IF NOT EXISTS idx_soar_threats_status ON public.soar_threats(status);
CREATE INDEX IF NOT EXISTS idx_soar_threats_severity ON public.soar_threats(severity);
CREATE INDEX IF NOT EXISTS idx_soar_vulns_device_id ON public.soar_vulnerabilities(device_id);
CREATE INDEX IF NOT EXISTS idx_soar_vulns_cve ON public.soar_vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_soar_playbook_runs_status ON public.soar_playbook_runs(status);

-- Enable RLS and Policies for New Tables
DO $$
DECLARE
    tbl text;
    tables text[] := ARRAY['soar_devices', 'soar_events', 'soar_threats', 'soar_vulnerabilities', 'soar_playbook_runs'];
BEGIN
    FOREACH tbl IN ARRAY tables LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY;', tbl);
        IF NOT EXISTS (
            SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = tbl AND policyname = format('Allow all access to %s', tbl)
        ) THEN
            EXECUTE format('CREATE POLICY "Allow all access to %s" ON public.%I FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);', tbl, tbl);
        END IF;
    END LOOP;
END $$;
