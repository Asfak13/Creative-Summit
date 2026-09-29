-- ============================================================================
-- SALT Creative Summit — migrate admin login to real Supabase Auth
-- Run this ONCE in your Supabase project's SQL editor, AFTER supabase_setup.sql
-- has already been run.
--
-- What this does:
--   1. Creates a real Supabase Auth user for salt.creative@indpt.com
--      (inserted directly into auth.users/auth.identities — see the warning
--      below).
--   2. Flips submissions + storage.objects RLS from "to anon" to
--      "to authenticated", so only a signed-in session can read/update/
--      delete — the public anon key goes back to insert-only.
--   3. Drops the old admin_login() function and admin_config table, which
--      are no longer used once admin.html signs in via Supabase Auth
--      directly.
--
-- ⚠️ ABOUT STEP 1: Supabase officially recommends creating auth users via the
-- Dashboard (Authentication → Users → Add user) or the Admin API, not by
-- inserting into auth.users directly. Those internal tables are not a
-- documented/stable public interface — a future Supabase platform upgrade
-- could change their shape and break a raw insert like this one. It works on
-- current Supabase (Postgres + GoTrue) as of writing. If it ever stops
-- working after a Supabase upgrade, create the user via the Dashboard
-- instead (Authentication → Users → Add user → email + password, and tick
-- "Auto Confirm User"), then skip straight to step 2 below.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Create the real Supabase Auth user
-- ----------------------------------------------------------------------------
do $$
declare
  v_user_id uuid;
begin
  select id into v_user_id from auth.users where email = 'salt.creative@indpt.com';

  if v_user_id is null then
    v_user_id := gen_random_uuid();

    -- NOTE: GoTrue (Supabase Auth) reads several auth.users text columns as
    -- plain strings and errors with "Database error querying schema" if any
    -- of them are NULL, even though Postgres's own schema allows NULL there.
    -- They must all be explicitly set to '' (empty string), not left to
    -- their column default — this bit us in testing, hence being explicit
    -- about every one of them here rather than relying on defaults.
    insert into auth.users (
      id, instance_id, aud, role, email, encrypted_password,
      email_confirmed_at, created_at, updated_at,
      raw_app_meta_data, raw_user_meta_data, is_super_admin,
      confirmation_token, recovery_token, email_change_token_new,
      email_change, email_change_token_current, phone_change, phone_change_token
    ) values (
      v_user_id, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated',
      'salt.creative@indpt.com', extensions.crypt('Admin@indpt', extensions.gen_salt('bf')),
      now(), now(), now(),
      '{"provider":"email","providers":["email"]}', '{}', false,
      '', '', '', '', '', '', ''
    );

    insert into auth.identities (
      id, user_id, provider_id, identity_data, provider, created_at, updated_at
    ) values (
      gen_random_uuid(), v_user_id, v_user_id::text,
      jsonb_build_object('sub', v_user_id::text, 'email', 'salt.creative@indpt.com'),
      'email', now(), now()
    );

    raise notice 'Created auth user salt.creative@indpt.com';
  else
    -- User already exists (e.g. re-running this script, or created via the
    -- Dashboard already) — reset the password, and repair any NULL text
    -- columns GoTrue needs as '' (see the note above; this heals a user
    -- created by an earlier, buggy version of this same script).
    update auth.users
    set encrypted_password = extensions.crypt('Admin@indpt', extensions.gen_salt('bf')),
        email_confirmed_at = coalesce(email_confirmed_at, now()),
        updated_at = now(),
        confirmation_token = coalesce(confirmation_token, ''),
        recovery_token = coalesce(recovery_token, ''),
        email_change_token_new = coalesce(email_change_token_new, ''),
        email_change = coalesce(email_change, ''),
        email_change_token_current = coalesce(email_change_token_current, ''),
        phone_change = coalesce(phone_change, ''),
        phone_change_token = coalesce(phone_change_token, '')
    where id = v_user_id;

    raise notice 'auth user salt.creative@indpt.com already existed — password reset and NULL fields repaired';
  end if;
end $$;

-- ----------------------------------------------------------------------------
-- 2. Tighten RLS: submissions — authenticated only for read/update/delete.
--    Kiosk visitors (anon) keep insert-only access.
-- ----------------------------------------------------------------------------
drop policy if exists "anon can read submissions" on public.submissions;
drop policy if exists "anon can update submissions" on public.submissions;
drop policy if exists "anon can delete submissions" on public.submissions;

drop policy if exists "authenticated can read submissions" on public.submissions;
create policy "authenticated can read submissions"
  on public.submissions for select
  to authenticated
  using (true);

drop policy if exists "authenticated can update submissions" on public.submissions;
create policy "authenticated can update submissions"
  on public.submissions for update
  to authenticated
  using (true)
  with check (true);

drop policy if exists "authenticated can delete submissions" on public.submissions;
create policy "authenticated can delete submissions"
  on public.submissions for delete
  to authenticated
  using (true);

-- app_config: the kiosk needs to READ this (careers inbox address for the
-- "send CV from my phone" QR), so that stays anon-readable. Only WRITING to
-- it (done from admin.html) needs to move to authenticated.
drop policy if exists "anon can update app_config" on public.app_config;
drop policy if exists "authenticated can update app_config" on public.app_config;
create policy "authenticated can update app_config"
  on public.app_config for update
  to authenticated
  using (true)
  with check (true);

-- ----------------------------------------------------------------------------
-- 3. Tighten RLS: cvs storage bucket — authenticated only for read/delete.
--    Kiosk visitors (anon) keep upload-only access.
-- ----------------------------------------------------------------------------
drop policy if exists "anon can read cvs" on storage.objects;
drop policy if exists "anon can delete cvs" on storage.objects;

drop policy if exists "authenticated can read cvs" on storage.objects;
create policy "authenticated can read cvs"
  on storage.objects for select
  to authenticated
  using (bucket_id = 'cvs');

drop policy if exists "authenticated can delete cvs" on storage.objects;
create policy "authenticated can delete cvs"
  on storage.objects for delete
  to authenticated
  using (bucket_id = 'cvs');

-- ----------------------------------------------------------------------------
-- 4. Clean up the old custom-login machinery — no longer used.
-- ----------------------------------------------------------------------------
drop function if exists public.admin_login(text, text);
drop table if exists public.admin_config;

-- ============================================================================
-- Done. What changed:
--   - salt.creative@indpt.com is now a real Supabase Auth user.
--   - The anon key (visible in index.html / admin.html source) can no longer
--     read, update, or delete submissions or CVs — only insert new ones.
--   - admin.html must sign in via supabase.auth.signInWithPassword() to see
--     or export anything now (this SQL migration alone does not update
--     admin.html — that's a separate file change).
--
-- To change the admin password later, easiest via the Supabase Dashboard:
--   Authentication → Users → salt.creative@indpt.com → Reset password.
-- Or via SQL:
--   update auth.users
--   set encrypted_password = extensions.crypt('NewPassword123', extensions.gen_salt('bf')),
--       updated_at = now()
--   where email = 'salt.creative@indpt.com';
-- ============================================================================
