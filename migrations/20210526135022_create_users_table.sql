-- Add migration script here
begin;
create or replace function set_updated_at() returns trigger as $$
  BEGIN
    NEW.updated_at := current_timestamp;
  END;
$$ language plpgsql;

create table if not exists users (
  id bigserial primary key,
  name text,
  email text unique,
  created_at timestamptz default now(),
  updated_at timestamptz
);

create trigger user_set_updated_at before update on users
  for each row execute function set_updated_at();
commit;
