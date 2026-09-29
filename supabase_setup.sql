-- ============================================================================
-- SALT Creative Summit — Supabase setup
-- Run this ONCE in your Supabase project's SQL editor (Dashboard → SQL Editor
-- → New query → paste all of this → Run).
-- Safe to re-run: uses IF NOT EXISTS / CREATE OR REPLACE / DROP POLICY IF EXISTS.
-- ============================================================================

-- Needed for salted password hashing (crypt/gen_salt) and gen_random_uuid().
-- Supabase installs this into the "extensions" schema, not "public" — so
-- functions that call crypt()/gen_salt() must schema-qualify them (below)
-- rather than rely on search_path alone.
create extension if not exists pgcrypto with schema extensions;

-- ----------------------------------------------------------------------------
-- 1. submissions table — one row per applicant
-- ----------------------------------------------------------------------------
create table if not exists public.submissions (
  id           uuid primary key default gen_random_uuid(),
  order_code   text unique not null,
  created_at   timestamptz not null default now(),
  lang         text,
  name         text not null,
  phone        text not null,
  email        text not null,
  role         text,
  exp          text,
  edu          text,
  skills       text[] default '{}',
  style        text,
  avail        text,
  contract     text,
  burger       text,
  cv_method    text,              -- 'upload' | 'email'
  cv_email     text,              -- careers inbox, when cv_method = 'email'
  cv_path      text,              -- storage object path, when cv_method = 'upload'
  cv_filename  text,
  cv_size_bytes bigint,
  device       text,              -- which kiosk/tablet this came from
  status       text not null default 'new',   -- 'new' | 'reviewed' | 'shortlisted' | 'rejected'
  notes        text
);

create index if not exists submissions_created_at_idx on public.submissions (created_at desc);
create index if not exists submissions_role_idx on public.submissions (role);
create index if not exists submissions_status_idx on public.submissions (status);

alter table public.submissions enable row level security;

-- Kiosk visitors (anon key) may INSERT new applications.
drop policy if exists "anon can insert submissions" on public.submissions;
create policy "anon can insert submissions"
  on public.submissions for insert
  to anon
  with check (true);

-- NOTE ON SECURITY MODEL:
-- admin.html uses a custom login screen (checked via the admin_login()
-- function below) instead of real Supabase Auth sessions. Because of that,
-- Postgres has no way to tell an "admin" apart from any other anon-key caller
-- — RLS below grants the SAME anon key read/update/delete access, and
-- admin.html's login screen is the only real gate in front of it.
-- This means anyone who extracts your anon key from the page source (view
-- source / browser devtools) could call the Supabase API directly and read,
-- edit, or delete every submission and CV — bypassing the login screen
-- entirely. If that risk matters to you later, switch to real Supabase Auth
-- (a session-based "authenticated" role) and tighten these policies to
-- `to authenticated` instead of `to anon`.
drop policy if exists "anon can read submissions" on public.submissions;
create policy "anon can read submissions"
  on public.submissions for select
  to anon
  using (true);

drop policy if exists "anon can update submissions" on public.submissions;
create policy "anon can update submissions"
  on public.submissions for update
  to anon
  using (true)
  with check (true);

drop policy if exists "anon can delete submissions" on public.submissions;
create policy "anon can delete submissions"
  on public.submissions for delete
  to anon
  using (true);

-- ----------------------------------------------------------------------------
-- 1b. app_config — small single-row table for settings the kiosk reads live,
--     e.g. the careers inbox address used for the "send CV from my phone" QR.
--     Managed from admin.html; readable by anon so the kiosk can pick it up.
-- ----------------------------------------------------------------------------
create table if not exists public.app_config (
  id       int primary key default 1,
  cv_email text,
  check (id = 1)
);

insert into public.app_config (id, cv_email) values (1, null)
on conflict (id) do nothing;

alter table public.app_config enable row level security;

drop policy if exists "anon can read app_config" on public.app_config;
create policy "anon can read app_config"
  on public.app_config for select
  to anon
  using (true);

drop policy if exists "anon can update app_config" on public.app_config;
create policy "anon can update app_config"
  on public.app_config for update
  to anon
  using (true)
  with check (true);

-- ----------------------------------------------------------------------------
-- 2. admin_config table — holds the salted/hashed admin credential
--    (never exposed directly to the anon key; only reachable through the
--    SECURITY DEFINER function below)
-- ----------------------------------------------------------------------------
create table if not exists public.admin_config (
  email         text primary key,
  password_hash text not null,
  updated_at    timestamptz not null default now()
);

alter table public.admin_config enable row level security;
-- No policies granted to anon/authenticated at all: this table is only ever
-- touched through the SECURITY DEFINER functions below, which run as the
-- table owner regardless of the caller's row-level permissions.

-- Seed / reset the admin credential: salt.creative@indpt.com / Admin@indpt
insert into public.admin_config (email, password_hash)
values ('salt.creative@indpt.com', extensions.crypt('Admin@indpt', extensions.gen_salt('bf')))
on conflict (email) do update
  set password_hash = excluded.password_hash,
      updated_at = now();

-- ----------------------------------------------------------------------------
-- 3. admin_login RPC — verifies email+password against admin_config.
--    Callable by anon (that's how the login screen checks credentials before
--    anything sensitive is readable), but it only ever returns true/false —
--    it never returns the hash itself.
-- ----------------------------------------------------------------------------
create or replace function public.admin_login(p_email text, p_password text)
returns boolean
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_hash text;
begin
  select password_hash into v_hash
  from public.admin_config
  where lower(email) = lower(p_email);

  if v_hash is null then
    return false;
  end if;

  return v_hash = extensions.crypt(p_password, v_hash);
end;
$$;

revoke all on function public.admin_login(text, text) from public;
grant execute on function public.admin_login(text, text) to anon, authenticated;

-- ----------------------------------------------------------------------------
-- 4. Storage bucket for compressed CV PDFs
-- ----------------------------------------------------------------------------
insert into storage.buckets (id, name, public)
values ('cvs', 'cvs', false)
on conflict (id) do nothing;

-- Anon (kiosk + admin.html, same key — see note above) can upload, read and
-- delete CVs in this bucket. admin.html's login screen is what actually gates
-- who gets to use those reads/deletes in practice.
drop policy if exists "anon can upload cvs" on storage.objects;
create policy "anon can upload cvs"
  on storage.objects for insert
  to anon
  with check (bucket_id = 'cvs');

drop policy if exists "anon can read cvs" on storage.objects;
create policy "anon can read cvs"
  on storage.objects for select
  to anon
  using (bucket_id = 'cvs');

drop policy if exists "anon can delete cvs" on storage.objects;
create policy "anon can delete cvs"
  on storage.objects for delete
  to anon
  using (bucket_id = 'cvs');

-- ============================================================================
-- Done. What this gives you:
--   - public.submissions   : every applicant + all their form answers
--   - public.admin_config  : salted admin password (salt.creative@indpt.com)
--   - public.admin_login() : the function admin.html calls to check the login
--   - storage bucket "cvs" : compressed PDF CVs, admin-only to read/download
--
-- To change the admin password later, run:
--   update public.admin_config
--   set password_hash = extensions.crypt('NewPassword123', extensions.gen_salt('bf'))
--   where email = 'salt.creative@indpt.com';
-- ============================================================================
