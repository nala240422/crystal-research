-- ================================================================
-- Crystal Intelligence — Supabase Security Rules (RLS)
-- Run this in: Supabase Dashboard → SQL Editor → New query → Run
-- This REPLACES the open "allow all" policies with proper restrictions
-- ================================================================

-- Drop old open policies
drop policy if exists "allow all users"        on users;
drop policy if exists "allow all vasps"        on vasps;
drop policy if exists "allow all assignments"  on vasp_assignments;
drop policy if exists "allow all attributions" on attributions;
drop policy if exists "allow all progress"     on vasp_progress;

-- ================================================================
-- USERS table
-- ================================================================

-- Anyone can read users (needed for login check)
create policy "users_select"
  on users for select
  using (true);

-- Only insert if no user with that username exists yet (registration)
create policy "users_insert"
  on users for insert
  with check (true);

-- Only update your own row (password change) OR if you are admin
create policy "users_update"
  on users for update
  using (
    username = current_setting('app.current_user', true)
    or current_setting('app.role', true) = 'admin'
  );

-- Only admin can delete users
create policy "users_delete"
  on users for delete
  using (current_setting('app.role', true) = 'admin');

-- ================================================================
-- VASPS table
-- ================================================================

-- Anyone logged in can read VASPs
create policy "vasps_select"
  on vasps for select
  using (true);

-- Only admin can insert/update/delete VASPs
create policy "vasps_insert"
  on vasps for insert
  with check (current_setting('app.role', true) = 'admin');

create policy "vasps_update"
  on vasps for update
  using (current_setting('app.role', true) = 'admin');

create policy "vasps_delete"
  on vasps for delete
  using (current_setting('app.role', true) = 'admin');

-- ================================================================
-- VASP_ASSIGNMENTS table
-- ================================================================

-- Researchers can read their own assignments, admin reads all
create policy "assignments_select"
  on vasp_assignments for select
  using (
    username = current_setting('app.current_user', true)
    or current_setting('app.role', true) = 'admin'
  );

-- Only admin can assign VASPs
create policy "assignments_insert"
  on vasp_assignments for insert
  with check (current_setting('app.role', true) = 'admin');

create policy "assignments_delete"
  on vasp_assignments for delete
  using (current_setting('app.role', true) = 'admin');

-- ================================================================
-- ATTRIBUTIONS table
-- ================================================================

-- Researchers read only their own, admin reads all
create policy "attributions_select"
  on attributions for select
  using (
    researcher = current_setting('app.current_user', true)
    or current_setting('app.role', true) = 'admin'
  );

-- Researchers can only insert their own attributions
create policy "attributions_insert"
  on attributions for insert
  with check (
    researcher = current_setting('app.current_user', true)
  );

-- Only admin can update status (approve/deny)
create policy "attributions_update"
  on attributions for update
  using (current_setting('app.role', true) = 'admin');

-- Nobody can delete attributions
create policy "attributions_no_delete"
  on attributions for delete
  using (false);

-- ================================================================
-- VASP_PROGRESS table
-- ================================================================

-- Researchers read only their own, admin reads all
create policy "progress_select"
  on vasp_progress for select
  using (
    username = current_setting('app.current_user', true)
    or current_setting('app.role', true) = 'admin'
  );

-- Researchers can only upsert their own progress
create policy "progress_insert"
  on vasp_progress for insert
  with check (
    username = current_setting('app.current_user', true)
  );

create policy "progress_update"
  on vasp_progress for update
  using (
    username = current_setting('app.current_user', true)
    or current_setting('app.role', true) = 'admin'
  );

-- Nobody can delete progress rows
create policy "progress_no_delete"
  on vasp_progress for delete
  using (false);

-- ================================================================
-- SESSION HELPER FUNCTION
-- Called by the dashboard on login to set RLS context
-- ================================================================
create or replace function set_session(p_username text, p_role text)
returns void
language plpgsql
security definer
as $$
begin
  perform set_config('app.current_user', p_username, true);
  perform set_config('app.role',         p_role,     true);
end;
$$;

-- Allow anyone to call this function (login sets the session)
grant execute on function set_session(text, text) to anon, authenticated;
