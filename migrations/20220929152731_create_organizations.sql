-- Add migration script here
begin;
create table if not exists organizations (
  id bigserial primary key,
  name text,
  owner_id bigserial references users(id),
  created_at timestamptz default now(),
  updated_at timestamptz
);

create trigger organization_set_updated_at before update on organizations
  for each row execute function set_updated_at();
commit;
