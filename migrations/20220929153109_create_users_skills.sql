-- Add migration script here
begin;
create table if not exists capabilities (
  user_id bigserial references users(id) on delete cascade,
  skill_id bigserial references skills(id) on delete cascade,
  proficiency text,
  created_at timestamptz default now(),
  updated_at timestamptz
);

create trigger capability_set_updated_at before update on capabilities
  for each row execute function set_updated_at();
commit;
