-- CybrScan domain model (CYB-34, Workstream 1)
-- Scans, domain ownership verifications, and per-account RLS.
-- Builds on 00001_baseline.sql (profiles, audit_log, set_updated_at()).

-- =========================================================
-- Domain ownership verifications
-- Active/continuous scans are gated behind proven ownership (safety mandate,
-- Head of Security). The free passive scan does NOT require a row here.
-- =========================================================
create table if not exists public.domain_verifications (
  id          uuid primary key default uuid_generate_v4(),
  account_id  uuid not null references auth.users(id) on delete cascade,
  domain      text not null,
  method      text not null check (method in ('dns_txt', 'http_file')),
  token       text not null,
  verified_at timestamptz,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  unique (account_id, domain)
);

comment on table public.domain_verifications is
  'Proof-of-ownership records. A domain may be monitored only after verified_at is set.';

create trigger domain_verifications_set_updated_at
  before update on public.domain_verifications
  for each row execute procedure public.set_updated_at();

-- =========================================================
-- Scans
-- One row per scan request. `result` holds the engine output (ScanResult shape
-- from src/lib/scan/types.ts). grade/score are denormalized for cheap listing.
-- =========================================================
create table if not exists public.scans (
  id          uuid primary key default uuid_generate_v4(),
  account_id  uuid not null references auth.users(id) on delete cascade,
  domain      text not null,
  scan_type   text not null default 'passive_free'
                check (scan_type in ('passive_free', 'monitored')),
  status      text not null default 'pending'
                check (status in ('pending', 'running', 'complete', 'failed')),
  grade       text check (grade in ('A', 'B', 'C', 'D', 'F')),
  score       integer check (score between 0 and 100),
  result      jsonb,
  error       text,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

comment on table public.scans is 'Customer scan requests and their graded results.';

create trigger scans_set_updated_at
  before update on public.scans
  for each row execute procedure public.set_updated_at();

create index if not exists scans_account_created_idx
  on public.scans(account_id, created_at desc);
create index if not exists domain_verifications_account_idx
  on public.domain_verifications(account_id);

-- =========================================================
-- Row Level Security — strict per-account isolation
-- =========================================================
alter table public.scans enable row level security;
alter table public.domain_verifications enable row level security;

-- Scans: owners read/insert their own; updates (status -> complete) are done
-- server-side with the service role, which bypasses RLS, so no update policy
-- is granted to end users.
create policy "scans: select own" on public.scans
  for select using (auth.uid() = account_id);

create policy "scans: insert own" on public.scans
  for insert with check (auth.uid() = account_id);

-- Domain verifications: owners manage their own.
create policy "domain_verifications: select own" on public.domain_verifications
  for select using (auth.uid() = account_id);

create policy "domain_verifications: insert own" on public.domain_verifications
  for insert with check (auth.uid() = account_id);

create policy "domain_verifications: update own" on public.domain_verifications
  for update using (auth.uid() = account_id)
  with check (auth.uid() = account_id);
