-- Run in Supabase: SQL Editor → New query → paste → Run
-- Safe to re-run if a previous attempt partially applied.

create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  created_at timestamptz not null default now()
);

-- Add columns when profiles already existed (e.g. Supabase starter schema)
alter table public.profiles add column if not exists username text;
alter table public.profiles add column if not exists created_at timestamptz not null default now();

-- Backfill username for any existing rows
update public.profiles p
set username = lower(split_part(u.email, '@', 1))
from auth.users u
where p.id = u.id
  and (p.username is null or p.username = '');

-- Constraints (drop first so re-run is safe)
alter table public.profiles drop constraint if exists profiles_username_length;
alter table public.profiles drop constraint if exists profiles_username_format;

alter table public.profiles
  alter column username set not null;

alter table public.profiles
  add constraint profiles_username_length check (char_length(username) between 3 and 24);

alter table public.profiles
  add constraint profiles_username_format check (username ~ '^[a-z0-9_]+$');

drop index if exists public.profiles_username_lower_idx;

create unique index profiles_username_lower_idx
  on public.profiles (lower(username));

alter table public.profiles enable row level security;

drop policy if exists "Profiles are viewable by everyone" on public.profiles;
create policy "Profiles are viewable by everyone"
  on public.profiles for select
  using (true);

drop policy if exists "Users can insert their own profile" on public.profiles;
create policy "Users can insert their own profile"
  on public.profiles for insert
  with check (auth.uid() = id);

drop policy if exists "Users can update their own profile" on public.profiles;
create policy "Users can update their own profile"
  on public.profiles for update
  using (auth.uid() = id);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  raw_username text;
begin
  raw_username := lower(trim(coalesce(new.raw_user_meta_data ->> 'username', '')));

  if raw_username = '' then
    raw_username := lower(split_part(new.email, '@', 1));
  end if;

  insert into public.profiles (id, username)
  values (new.id, raw_username)
  on conflict (id) do update
    set username = excluded.username;

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;

create trigger on_auth_user_created
  after insert on auth.users
  for each row
  execute function public.handle_new_user();
