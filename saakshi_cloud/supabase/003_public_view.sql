-- SAAKSHI online dashboard: public view-only access (10 Oct 2026).
-- An organisation can switch on "public view": then anyone opening the dashboard without logging in
-- sees that organisation's dashboard read-only (nodes, trips, charts, alerts, anchors, buyer QR).
-- Nothing can be written through these functions. Team, invite codes, sync codes, requests and
-- people's names are never included. Switch it off again with set_public_view(false) (Team page).

alter table public.orgs add column if not exists public_view boolean not null default false;

-- the one organisation shown to visitors (the earliest one that switched public view on)
create or replace function public.public_org() returns uuid
language sql stable security definer set search_path = '' as $$
  select id from public.orgs where public_view order by created_at limit 1
$$;

create or replace function public.public_overview() returns jsonb
language plpgsql stable security definer set search_path = '' as $$
declare oid uuid := public.public_org();
begin
  if oid is null then return null; end if;
  return jsonb_build_object(
    'org', (select name from public.orgs where id = oid),
    'views', coalesce((select jsonb_agg(jsonb_build_object('node', node, 'data', data)) from public.node_views where org_id = oid), '[]'::jsonb),
    'nodes', coalesce((select jsonb_agg(jsonb_build_object('node', node, 'settings', settings)) from public.nodes where org_id = oid), '[]'::jsonb),
    'alerts', coalesce((select jsonb_agg(data) from public.alerts where org_id = oid), '[]'::jsonb),
    -- who acknowledged is not shown to visitors
    'acks', coalesce((select jsonb_agg(jsonb_build_object('alert_id', alert_id, 'by_name', 'the team', 'at', at))
                      from public.alert_acks where org_id = oid), '[]'::jsonb),
    'status', (select jsonb_build_object('data', data, 'synced_at', synced_at) from public.sync_status where org_id = oid));
end $$;

create or replace function public.public_trip(p_node text, p_chain text) returns jsonb
language sql stable security definer set search_path = '' as $$
  select data from public.trip_views
  where org_id = public.public_org() and node = p_node and chain = p_chain
$$;

create or replace function public.public_pulse() returns text
language sql stable security definer set search_path = '' as $$
  select coalesce(data ->> 'fp', synced_at::text) from public.sync_status where org_id = public.public_org()
$$;

-- the switch, for the organisation's admin (Team page)
create or replace function public.set_public_view(p_on boolean) returns boolean
language plpgsql security definer set search_path = '' as $$
begin
  if not exists (select 1 from public.org_members where user_id = auth.uid() and role = 'admin') then
    raise exception 'Admins only.';
  end if;
  update public.orgs set public_view = coalesce(p_on, false) where id = public.my_org();
  return coalesce(p_on, false);
end $$;

create or replace function public.public_view_on() returns boolean
language sql stable security definer set search_path = '' as $$
  select coalesce((select public_view from public.orgs where id = public.my_org()), false)
$$;

revoke execute on function public.public_org(), public.public_overview(), public.public_trip(text, text),
  public.public_pulse(), public.set_public_view(boolean), public.public_view_on() from public, anon, authenticated;
grant execute on function public.public_overview(), public.public_trip(text, text), public.public_pulse() to anon, authenticated;
grant execute on function public.set_public_view(boolean), public.public_view_on() to authenticated;

-- switch it on for samxdevs@gmail.com's organisation
update public.orgs set public_view = true
where id = (select om.org_id from public.org_members om join auth.users u on u.id = om.user_id
            where u.email = 'samxdevs@gmail.com');

select name, public_view from public.orgs where public_view;
