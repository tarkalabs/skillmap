-- Add migration script here
create table if not exists users_organizations (
  user_id bigserial references users(id) on delete cascade,
  organization_id bigserial references organizations(id) on delete cascade
);
