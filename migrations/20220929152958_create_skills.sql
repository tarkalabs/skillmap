-- Add migration script here
begin;
create table if not exists skills (
  id bigserial primary key,
  name text,
  created_at timestamptz default now(),
  updated_at timestamptz
);

create trigger skill_set_updated_at before update on skills
  for each row execute function set_updated_at();
commit;
