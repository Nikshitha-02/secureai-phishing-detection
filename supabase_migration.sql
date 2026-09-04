-- ============================================================
-- SecureAI – scan_results table migration
-- Run this in: Supabase Dashboard → SQL Editor → New Query
-- ============================================================

-- 1. Create the table
create table if not exists public.scan_results (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null references auth.users(id) on delete cascade,
  url          text not null,
  risk_score   integer not null check (risk_score >= 0 and risk_score <= 100),
  risk_level   text not null check (risk_level in ('safe', 'suspicious', 'dangerous')),
  scanned_at   timestamptz not null default now()
);

-- 2. Index for fast per-user history queries (newest first)
create index if not exists scan_results_user_id_scanned_at_idx
  on public.scan_results (user_id, scanned_at desc);

-- 3. Enable Row Level Security
alter table public.scan_results enable row level security;

-- 4. RLS policy: users can only SELECT their own rows
create policy "Users can read own scans"
  on public.scan_results
  for select
  using (auth.uid() = user_id);

-- 5. RLS policy: backend service role bypasses RLS automatically.
--    We also add an INSERT policy so authenticated users (via anon key)
--    cannot insert directly — only the service role (backend) can.
--    This keeps write access exclusively on the server side.
--
--    NOTE: the backend uses the service_role key which bypasses RLS entirely,
--    so no INSERT policy is needed for it. The absence of a user INSERT policy
--    is intentional — it blocks direct client-side inserts.

-- 6. Verify
select 'scan_results table created successfully' as status;
