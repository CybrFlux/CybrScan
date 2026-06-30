-- Baseline schema for all CybrFlux client projects
-- Applied once per new engagement via: npx supabase db push

-- =========================================================
-- Extensions
-- =========================================================
create extension if not exists "uuid-ossp";

-- =========================================================
-- Profiles (extends Supabase auth.users)
-- =========================================================
create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  email       text not null,
  full_name   text,
  avatar_url  text,
  role        text not null default 'user' check (role in ('user', 'admin')),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

comment on table public.profiles is 'Extended user profile data mirroring auth.users.';

-- Auto-create profile on new user signup
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, full_name, avatar_url)
  values (
    new.id,
    new.email,
    new.raw_user_meta_data ->> 'full_name',
    new.raw_user_meta_data ->> 'avatar_url'
  );
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- Auto-update updated_at
create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger profiles_set_updated_at
  before update on public.profiles
  for each row execute procedure public.set_updated_at();

-- =========================================================
-- Row Level Security — profiles
-- =========================================================
alter table public.profiles enable row level security;

-- Users can read their own profile
create policy "profiles: select own" on public.profiles
  for select using (auth.uid() = id);

-- Users can update their own profile (not role)
create policy "profiles: update own" on public.profiles
  for update using (auth.uid() = id)
  with check (auth.uid() = id and role = (select role from public.profiles where id = auth.uid()));

-- Admins can read all profiles
create policy "profiles: admin select all" on public.profiles
  for select using (
    exists (select 1 from public.profiles where id = auth.uid() and role = 'admin')
  );

-- =========================================================
-- Audit log
-- =========================================================
create table if not exists public.audit_log (
  id          uuid primary key default uuid_generate_v4(),
  actor_id    uuid references auth.users(id) on delete set null,
  action      text not null,
  table_name  text,
  record_id   text,
  old_data    jsonb,
  new_data    jsonb,
  ip_address  inet,
  created_at  timestamptz not null default now()
);

comment on table public.audit_log is 'Append-only audit trail of user actions.';

alter table public.audit_log enable row level security;

-- Only admins can read audit log
create policy "audit_log: admin select" on public.audit_log
  for select using (
    exists (select 1 from public.profiles where id = auth.uid() and role = 'admin')
  );

-- Service role can insert (called from server-side only)
create policy "audit_log: service insert" on public.audit_log
  for insert with check (true);

-- =========================================================
-- Indexes
-- =========================================================
create index if not exists profiles_email_idx on public.profiles(email);
create index if not exists audit_log_actor_idx on public.audit_log(actor_id);
create index if not exists audit_log_created_at_idx on public.audit_log(created_at desc);
