-- Fixes "Database error saving new user" on signup.
-- Run in Supabase SQL Editor after 001 and 002.

-- Remove broken auto-confirm trigger (confirmed_at may not exist on auth.users)
drop trigger if exists on_auth_user_auto_confirm on auth.users;
drop function if exists public.auto_confirm_user();

-- Confirm email before insert (no extra columns required)
create or replace function public.auto_confirm_user()
returns trigger
language plpgsql
security definer
set search_path = auth, public
as $$
begin
  if new.email_confirmed_at is null then
    new.email_confirmed_at := now();
  end if;
  return new;
end;
$$;

drop trigger if exists on_auth_user_auto_confirm on auth.users;

create trigger on_auth_user_auto_confirm
  before insert on auth.users
  for each row
  execute function public.auto_confirm_user();

-- Profile row: sanitize username so constraints never fail the signup
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

  raw_username := regexp_replace(raw_username, '[^a-z0-9_]', '', 'g');

  if char_length(raw_username) < 3 then
    raw_username := 'user_' || substr(replace(new.id::text, '-', ''), 1, 8);
  end if;

  if char_length(raw_username) > 24 then
    raw_username := substr(raw_username, 1, 24);
  end if;

  insert into public.profiles (id, username)
  values (new.id, raw_username)
  on conflict (id) do update
    set username = excluded.username;

  return new;
exception
  when unique_violation then
    raise exception 'username_taken'
      using hint = 'That username is already taken.';
  when others then
    raise exception 'profile_create_failed'
      using hint = sqlerrm;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;

create trigger on_auth_user_created
  after insert on auth.users
  for each row
  execute function public.handle_new_user();
