-- MFA, WebAuthn, recovery codes, and security audit tables.
-- Apply after 001_profiles (and related auth triggers).

-- Shared trigger helper (safe to replace)
create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

-- ---------------------------------------------------------------------------
-- mfa_settings
-- ---------------------------------------------------------------------------
create table if not exists public.mfa_settings (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references auth.users (id) on delete cascade,
  totp_enabled boolean not null default false,
  encrypted_totp_secret text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint mfa_totp_enabled_requires_secret check (
    not totp_enabled or encrypted_totp_secret is not null
  )
);

drop trigger if exists mfa_settings_set_updated_at on public.mfa_settings;
create trigger mfa_settings_set_updated_at
  before update on public.mfa_settings
  for each row
  execute function public.set_updated_at();

create index if not exists mfa_settings_user_id_idx on public.mfa_settings (user_id);

alter table public.mfa_settings enable row level security;

drop policy if exists "mfa_settings_select_own" on public.mfa_settings;
create policy "mfa_settings_select_own"
  on public.mfa_settings for select
  using (auth.uid() = user_id);

drop policy if exists "mfa_settings_insert_own" on public.mfa_settings;
create policy "mfa_settings_insert_own"
  on public.mfa_settings for insert
  with check (auth.uid() = user_id);

drop policy if exists "mfa_settings_update_own" on public.mfa_settings;
create policy "mfa_settings_update_own"
  on public.mfa_settings for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists "mfa_settings_delete_own" on public.mfa_settings;
create policy "mfa_settings_delete_own"
  on public.mfa_settings for delete
  using (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- webauthn_credentials
-- ---------------------------------------------------------------------------
create table if not exists public.webauthn_credentials (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  credential_id text not null,
  public_key text not null,
  sign_count bigint not null default 0,
  device_name text not null default 'Security key',
  transports jsonb not null default '[]'::jsonb,
  authenticator_type text not null default 'unknown',
  created_at timestamptz not null default now(),
  last_used_at timestamptz,
  constraint webauthn_credentials_id_len check (char_length(credential_id) <= 2048),
  constraint webauthn_credentials_authenticator_type_check check (
    authenticator_type in ('platform', 'cross-platform', 'hybrid', 'unknown')
  )
);

create unique index if not exists webauthn_credentials_credential_id_uidx
  on public.webauthn_credentials (credential_id);

create index if not exists webauthn_credentials_user_id_idx
  on public.webauthn_credentials (user_id);

alter table public.webauthn_credentials enable row level security;

drop policy if exists "webauthn_credentials_select_own" on public.webauthn_credentials;
create policy "webauthn_credentials_select_own"
  on public.webauthn_credentials for select
  using (auth.uid() = user_id);

drop policy if exists "webauthn_credentials_insert_own" on public.webauthn_credentials;
create policy "webauthn_credentials_insert_own"
  on public.webauthn_credentials for insert
  with check (auth.uid() = user_id);

drop policy if exists "webauthn_credentials_update_own" on public.webauthn_credentials;
create policy "webauthn_credentials_update_own"
  on public.webauthn_credentials for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists "webauthn_credentials_delete_own" on public.webauthn_credentials;
create policy "webauthn_credentials_delete_own"
  on public.webauthn_credentials for delete
  using (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- webauthn_challenges
-- ---------------------------------------------------------------------------
create table if not exists public.webauthn_challenges (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  challenge text not null,
  challenge_type text not null,
  expires_at timestamptz not null,
  used boolean not null default false,
  created_at timestamptz not null default now(),
  constraint webauthn_challenges_type_check check (
    challenge_type in ('registration', 'authentication')
  )
);

create index if not exists webauthn_challenges_user_id_idx
  on public.webauthn_challenges (user_id);

create index if not exists webauthn_challenges_expires_at_idx
  on public.webauthn_challenges (expires_at);

create index if not exists webauthn_challenges_user_unused_idx
  on public.webauthn_challenges (user_id, used, expires_at);

alter table public.webauthn_challenges enable row level security;

drop policy if exists "webauthn_challenges_select_own" on public.webauthn_challenges;
create policy "webauthn_challenges_select_own"
  on public.webauthn_challenges for select
  using (auth.uid() = user_id);

drop policy if exists "webauthn_challenges_insert_own" on public.webauthn_challenges;
create policy "webauthn_challenges_insert_own"
  on public.webauthn_challenges for insert
  with check (auth.uid() = user_id);

drop policy if exists "webauthn_challenges_update_own" on public.webauthn_challenges;
create policy "webauthn_challenges_update_own"
  on public.webauthn_challenges for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists "webauthn_challenges_delete_own" on public.webauthn_challenges;
create policy "webauthn_challenges_delete_own"
  on public.webauthn_challenges for delete
  using (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- recovery_codes
-- ---------------------------------------------------------------------------
create table if not exists public.recovery_codes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  code_hash text not null,
  used boolean not null default false,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists recovery_codes_user_id_idx on public.recovery_codes (user_id);
create index if not exists recovery_codes_user_unused_idx
  on public.recovery_codes (user_id, used);

alter table public.recovery_codes enable row level security;

drop policy if exists "recovery_codes_select_own" on public.recovery_codes;
create policy "recovery_codes_select_own"
  on public.recovery_codes for select
  using (auth.uid() = user_id);

drop policy if exists "recovery_codes_insert_own" on public.recovery_codes;
create policy "recovery_codes_insert_own"
  on public.recovery_codes for insert
  with check (auth.uid() = user_id);

drop policy if exists "recovery_codes_update_own" on public.recovery_codes;
create policy "recovery_codes_update_own"
  on public.recovery_codes for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists "recovery_codes_delete_own" on public.recovery_codes;
create policy "recovery_codes_delete_own"
  on public.recovery_codes for delete
  using (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- security_audit_logs
-- ---------------------------------------------------------------------------
create table if not exists public.security_audit_logs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  action text not null,
  metadata jsonb not null default '{}'::jsonb,
  ip_address text,
  user_agent text,
  created_at timestamptz not null default now()
);

create index if not exists security_audit_logs_user_id_created_idx
  on public.security_audit_logs (user_id, created_at desc);

alter table public.security_audit_logs enable row level security;

drop policy if exists "security_audit_logs_select_own" on public.security_audit_logs;
create policy "security_audit_logs_select_own"
  on public.security_audit_logs for select
  using (auth.uid() = user_id);

drop policy if exists "security_audit_logs_insert_own" on public.security_audit_logs;
create policy "security_audit_logs_insert_own"
  on public.security_audit_logs for insert
  with check (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- Cleanup: expired or already-used challenges for the current user (RLS applies)
-- ---------------------------------------------------------------------------
create or replace function public.cleanup_expired_webauthn_challenges()
returns integer
language plpgsql
security invoker
set search_path = public
as $$
declare
  deleted_count integer;
begin
  delete from public.webauthn_challenges
  where user_id = auth.uid()
    and (expires_at < now() or used = true);

  get diagnostics deleted_count = row_count;
  return coalesce(deleted_count, 0);
end;
$$;

revoke all on function public.cleanup_expired_webauthn_challenges() from public;
grant execute on function public.cleanup_expired_webauthn_challenges() to authenticated;
grant execute on function public.cleanup_expired_webauthn_challenges() to service_role;
