-- Shift It Labs: security hardening baseline
-- Review in Supabase SQL Editor before running. Intended for the existing Labs schema.
-- Goal: prevent client-side role escalation and make sensitive writes server/admin controlled.

begin;

-- RLS must be enabled on every app table.
alter table if exists public.profiles enable row level security;
alter table if exists public.locum_profiles enable row level security;
alter table if exists public.organisations enable row level security;
alter table if exists public.organisation_members enable row level security;
alter table if exists public.locations enable row level security;
alter table if exists public.shifts enable row level security;
alter table if exists public.applications enable row level security;
alter table if exists public.bookings enable row level security;
alter table if exists public.verification_checks enable row level security;
alter table if exists public.nmc_verifications enable row level security;
alter table if exists public.agreements enable row level security;
alter table if exists public.timesheets enable row level security;
alter table if exists public.invoices enable row level security;
alter table if exists public.platform_fees enable row level security;
alter table if exists public.audit_log enable row level security;

-- Never expose privileged tables to anonymous users.
revoke all on table public.verification_checks from anon;
revoke all on table public.nmc_verifications from anon;
revoke all on table public.platform_fees from anon;
revoke all on table public.audit_log from anon;

-- Client users must never directly write official verification, fee or audit decisions.
revoke insert, update, delete on table public.verification_checks from authenticated;
revoke insert, update, delete on table public.nmc_verifications from authenticated;
revoke insert, update, delete on table public.platform_fees from authenticated;
revoke insert, update, delete on table public.audit_log from authenticated;

-- Protect profiles.role from self-service escalation.
create or replace function public.protect_profile_role()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() = old.id and new.role is distinct from old.role then
    raise exception 'role changes are not allowed from the client';
  end if;
  return new;
end;
$$;

drop trigger if exists protect_profile_role_trigger on public.profiles;
create trigger protect_profile_role_trigger
before update on public.profiles
for each row execute function public.protect_profile_role();

-- Minimal self-profile policies. Drop broad equivalents before/after applying as appropriate.
drop policy if exists "shiftit_profiles_select_own" on public.profiles;
create policy "shiftit_profiles_select_own" on public.profiles
for select to authenticated using (id = auth.uid() or public.is_shift_it_admin());

drop policy if exists "shiftit_profiles_update_own" on public.profiles;
create policy "shiftit_profiles_update_own" on public.profiles
for update to authenticated
using (id = auth.uid() or public.is_shift_it_admin())
with check (id = auth.uid() or public.is_shift_it_admin());

-- Locum private profile: owner or Shift It admin only.
drop policy if exists "shiftit_locum_profile_owner" on public.locum_profiles;
create policy "shiftit_locum_profile_owner" on public.locum_profiles
for all to authenticated
using (user_id = auth.uid() or public.is_shift_it_admin())
with check (user_id = auth.uid() or public.is_shift_it_admin());

-- Sensitive verification results: subject can read own result; only admin can mutate.
drop policy if exists "shiftit_verification_read_own" on public.verification_checks;
create policy "shiftit_verification_read_own" on public.verification_checks
for select to authenticated
using (user_id = auth.uid() or public.is_shift_it_admin());

drop policy if exists "shiftit_nmc_read_own" on public.nmc_verifications;
create policy "shiftit_nmc_read_own" on public.nmc_verifications
for select to authenticated
using (user_id = auth.uid() or public.is_shift_it_admin());

-- Audit log is admin-readable only. Writes should come from trusted server functions/service role.
drop policy if exists "shiftit_audit_admin_read" on public.audit_log;
create policy "shiftit_audit_admin_read" on public.audit_log
for select to authenticated using (public.is_shift_it_admin());

commit;

-- IMPORTANT follow-up before production:
-- 1. Inspect and remove any older broad policies that conflict with these restrictions.
-- 2. Add organisation-member policies using the exact owner/member column names in your schema.
-- 3. Add bookings/agreements/timesheets/invoices policies using the exact participant columns.
-- 4. Keep service_role and verification-provider secrets out of browser code.
-- 5. Test every policy as anon, locum, agency/provider member, unrelated user and admin.
