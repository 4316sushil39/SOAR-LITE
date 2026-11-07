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
