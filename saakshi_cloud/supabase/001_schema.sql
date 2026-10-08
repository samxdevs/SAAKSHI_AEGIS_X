-- SAAKSHI online dashboard: schema, row-level security, functions.
-- Applied to the Supabase project "saakshi" (ap-south-1). Kept here so it can be re-created.
--
-- Trust model: the Mac's ledger is the only thing that checks chip signatures. The Mac pushes
-- its already-verified view through sync_push(), authorised by a sync link (a random token
-- whose SHA-256 is stored here) that is tied to ONE organisation. No service key leaves Supabase.

-- ------------------------------------------------------------------ tables
create table public.profiles (
  user_id uuid primary key references auth.users on delete cascade,
  email text not null,
  name text not null default '',
  created_at timestamptz not null default now()
);

create table public.orgs (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 80),
  invite_code text not null unique default encode(extensions.gen_random_bytes(5), 'hex'),
  created_at timestamptz not null default now()
);

create table public.org_members (
  org_id uuid not null references public.orgs on delete cascade,
  user_id uuid not null unique references auth.users on delete cascade,   -- one organisation per account
  role text not null check (role in ('admin', 'member')),
  created_at timestamptz not null default now(),
  primary key (org_id, user_id)
);

create table public.staff (                    -- AEGIS_X people who see node requests from the public page
  user_id uuid primary key references auth.users on delete cascade
);

create table public.nodes (
  node text primary key check (node ~ '^SAAKSHI-[0-9A-F]{8}$'),
  org_id uuid not null references public.orgs on delete cascade,
  settings jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

create table public.node_views (               -- the Mac dashboard's per-node overview entry
  node text primary key references public.nodes on delete cascade,
  org_id uuid not null references public.orgs on delete cascade,
  data jsonb not null,
  updated_at timestamptz not null default now()
);

create table public.trip_views (               -- the Mac dashboard's trip page (stats, chart buckets, anchor, share)
  node text not null references public.nodes on delete cascade,
  chain text not null check (chain ~ '^[0-9a-f]{8}$'),
  org_id uuid not null references public.orgs on delete cascade,
  data jsonb not null,
  updated_at timestamptz not null default now(),
  primary key (node, chain)
);

create table public.alerts (
  org_id uuid not null references public.orgs on delete cascade,
  id text not null,
  node text,
  data jsonb not null,
  updated_at timestamptz not null default now(),
  primary key (org_id, id)
);

create table public.alert_acks (
  org_id uuid not null references public.orgs on delete cascade,
  alert_id text not null check (char_length(alert_id) <= 200),
  by_user uuid not null references auth.users on delete cascade,
  by_name text not null default '',
  at timestamptz not null default now(),
  primary key (org_id, alert_id)
);

create table public.readings (                 -- every verified ledger row, kept as the exact CSV line
  node text not null references public.nodes on delete cascade,
  chain text not null,
  seq integer not null,
  org_id uuid not null references public.orgs on delete cascade,
  t bigint,                                    -- unix time, null when the board's clock wasn't set
  temp_c numeric, rh_pct numeric, flags integer not null default 0,
  line text not null,
  primary key (node, chain, seq)
);

create table public.sync_links (
  token_hash text primary key,
  org_id uuid not null references public.orgs on delete cascade,
  created_by uuid references auth.users on delete set null,
  created_at timestamptz not null default now(),
  last_used_at timestamptz
);

create table public.sync_status (
  org_id uuid primary key references public.orgs on delete cascade,
  data jsonb not null,
  synced_at timestamptz not null default now()
);

create table public.orders (                   -- "Request nodes" form on the public page
  id bigint generated always as identity primary key,
  name text not null check (char_length(btrim(name)) between 1 and 80),
  company text not null default '' check (char_length(company) <= 120),
  contact text not null check (char_length(btrim(contact)) between 3 and 120),
  nodes integer not null default 1 check (nodes between 1 and 10000),
  product text not null default '' check (char_length(product) <= 120),
  note text not null default '' check (char_length(note) <= 600),
  status text not null default 'new' check (status in ('new', 'contacted', 'done')),
  created_at timestamptz not null default now()
);

create index on public.readings (org_id);
create index on public.alerts (org_id, node);
create index on public.trip_views (org_id);
create index on public.node_views (org_id);
create index on public.nodes (org_id);
create index on public.org_members (org_id);
create index on public.alert_acks (by_user);
create index on public.sync_links (org_id);
create index on public.sync_links (created_by);

-- ------------------------------------------------------------------ helpers
create function public.my_org() returns uuid
language sql stable security definer set search_path = '' as $$
  select org_id from public.org_members where user_id = (select auth.uid())
$$;

create function public.is_staff() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.staff where user_id = (select auth.uid()))
$$;

create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (user_id, email, name)
  values (new.id, coalesce(new.email, ''), left(btrim(coalesce(new.raw_user_meta_data ->> 'name', '')), 80));
  return new;
end $$;

create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- ------------------------------------------------------------------ row-level security
alter table public.profiles    enable row level security;
alter table public.orgs        enable row level security;
alter table public.org_members enable row level security;
alter table public.staff       enable row level security;
alter table public.nodes       enable row level security;
alter table public.node_views  enable row level security;
alter table public.trip_views  enable row level security;
alter table public.alerts      enable row level security;
alter table public.alert_acks  enable row level security;
alter table public.readings    enable row level security;
alter table public.sync_links  enable row level security;
alter table public.sync_status enable row level security;
alter table public.orders      enable row level security;

-- Start from nothing, then grant exactly what the app uses.
revoke all on all tables in schema public from anon, authenticated;
grant select on public.nodes, public.node_views, public.trip_views, public.alerts,
                public.alert_acks, public.readings, public.sync_status to authenticated;
grant insert, delete on public.alert_acks to authenticated;
grant insert (name, company, contact, nodes, product, note) on public.orders to anon, authenticated;
grant select, update (status) on public.orders to authenticated;

create policy "members read nodes"       on public.nodes       for select to authenticated using (org_id = (select public.my_org()));
create policy "members read node views"  on public.node_views  for select to authenticated using (org_id = (select public.my_org()));
create policy "members read trip views"  on public.trip_views  for select to authenticated using (org_id = (select public.my_org()));
create policy "members read alerts"      on public.alerts      for select to authenticated using (org_id = (select public.my_org()));
create policy "members read readings"    on public.readings    for select to authenticated using (org_id = (select public.my_org()));
create policy "members read sync status" on public.sync_status for select to authenticated using (org_id = (select public.my_org()));
create policy "members read acks"        on public.alert_acks  for select to authenticated using (org_id = (select public.my_org()));
create policy "members add acks"         on public.alert_acks  for insert to authenticated
  with check (org_id = (select public.my_org()) and by_user = (select auth.uid()));
create policy "members remove acks"      on public.alert_acks  for delete to authenticated using (org_id = (select public.my_org()));

create policy "anyone sends a request"   on public.orders for insert to anon, authenticated with check (status = 'new');
create policy "staff read requests"      on public.orders for select to authenticated using ((select public.is_staff()));
create policy "staff update requests"    on public.orders for update to authenticated
  using ((select public.is_staff())) with check ((select public.is_staff()));
-- profiles, orgs, org_members, staff, sync_links: no direct access; only through the functions below.

-- ------------------------------------------------------------------ app functions (logged-in users)
create function public.my_context() returns jsonb
language plpgsql stable security definer set search_path = '' as $$
declare uid uuid := auth.uid(); m record; p record;
begin
  if uid is null then return null; end if;
  select * into p from public.profiles where user_id = uid;
  select o.id, o.name, o.invite_code, om.role into m
    from public.org_members om join public.orgs o on o.id = om.org_id where om.user_id = uid;
  return jsonb_build_object(
    'user', jsonb_build_object('name', coalesce(nullif(p.name, ''), p.email), 'email', p.email,
                               'role', coalesce(m.role, 'none'), 'staff', public.is_staff()),
    'org', case when m.id is null then null else jsonb_build_object('id', m.id, 'name', m.name) end);
end $$;

create function public.create_org(p_name text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare uid uuid := auth.uid(); oid uuid;
begin
  if uid is null then raise exception 'Log in first.'; end if;
  if exists (select 1 from public.org_members where user_id = uid) then
    raise exception 'This account already belongs to an organisation.';
  end if;
  if char_length(btrim(coalesce(p_name, ''))) not between 1 and 80 then
    raise exception 'Give the organisation a name (up to 80 characters).';
  end if;
  insert into public.orgs (name) values (btrim(p_name)) returning id into oid;
  insert into public.org_members (org_id, user_id, role) values (oid, uid, 'admin');
  return public.my_context();
end $$;

create function public.join_org(p_code text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare uid uuid := auth.uid(); oid uuid;
begin
  if uid is null then raise exception 'Log in first.'; end if;
  if exists (select 1 from public.org_members where user_id = uid) then
    raise exception 'This account already belongs to an organisation.';
  end if;
  select id into oid from public.orgs where invite_code = lower(btrim(coalesce(p_code, '')));
  if oid is null then
    raise exception 'That invite code isn''t right. Ask your admin for the code under Team.';
  end if;
  insert into public.org_members (org_id, user_id, role) values (oid, uid, 'member');
  return public.my_context();
end $$;

create function public.team() returns jsonb
language plpgsql stable security definer set search_path = '' as $$
declare oid uuid := public.my_org();
begin
  if not exists (select 1 from public.org_members where user_id = auth.uid() and role = 'admin') then
    raise exception 'Admins only.';
  end if;
  return jsonb_build_object(
    'invite', (select invite_code from public.orgs where id = oid),
    'org', (select name from public.orgs where id = oid),
    'links', (select count(*) from public.sync_links where org_id = oid),
    'lastSync', (select extract(epoch from synced_at)::bigint from public.sync_status where org_id = oid),
    'users', coalesce((select jsonb_agg(jsonb_build_object('email', p.email, 'name', p.name, 'role', om.role,
                         'created', extract(epoch from om.created_at)::bigint) order by om.created_at)
                       from public.org_members om join public.profiles p on p.user_id = om.user_id
                       where om.org_id = oid), '[]'::jsonb));
end $$;

create function public.rotate_invite() returns text
language plpgsql security definer set search_path = '' as $$
declare code text := encode(extensions.gen_random_bytes(5), 'hex');
begin
  if not exists (select 1 from public.org_members where user_id = auth.uid() and role = 'admin') then
    raise exception 'Admins only.';
  end if;
  update public.orgs set invite_code = code where id = public.my_org();
  return code;
end $$;

create function public.save_node_settings(p_node text, p_settings jsonb) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare cur jsonb; lo numeric; hi numeric;
begin
  select settings into cur from public.nodes where node = p_node and org_id = public.my_org();
  if cur is null then raise exception 'No such node in your organisation.'; end if;
  if p_settings ? 'name' then
    cur := cur || jsonb_build_object('name', left(btrim(coalesce(p_settings ->> 'name', '')), 60));
  end if;
  begin
    if p_settings ? 'lo' then
      cur := cur || jsonb_build_object('lo', case when coalesce(p_settings ->> 'lo', '') = '' then null
                                                  else round((p_settings ->> 'lo')::numeric, 2) end);
    end if;
    if p_settings ? 'hi' then
      cur := cur || jsonb_build_object('hi', case when coalesce(p_settings ->> 'hi', '') = '' then null
                                                  else round((p_settings ->> 'hi')::numeric, 2) end);
    end if;
    if p_settings ? 'minutes' then
      cur := cur || jsonb_build_object('minutes', greatest(0, least(1440, coalesce(nullif(p_settings ->> 'minutes', ''), '0')::numeric::int)));
    end if;
    if p_settings ? 'offlineMinutes' then
      cur := cur || jsonb_build_object('offlineMinutes', greatest(0, least(1440, coalesce(nullif(p_settings ->> 'offlineMinutes', ''), '0')::numeric::int)));
    end if;
  exception when invalid_text_representation or numeric_value_out_of_range then
    raise exception 'Numbers only, please.';
  end;
  lo := (cur ->> 'lo')::numeric; hi := (cur ->> 'hi')::numeric;
  if lo is not null and hi is not null and lo >= hi then
    raise exception 'The lowest temperature must be below the highest.';
  end if;
  update public.nodes set settings = cur, updated_at = now() where node = p_node;
  return cur;
end $$;

create function public.create_sync_link() returns text
language plpgsql security definer set search_path = '' as $$
declare tok text := 'sync_' || encode(extensions.gen_random_bytes(24), 'hex'); oid uuid := public.my_org();
begin
  if not exists (select 1 from public.org_members where user_id = auth.uid() and role = 'admin') then
    raise exception 'Admins only.';
  end if;
  insert into public.sync_links (token_hash, org_id, created_by)
    values (encode(sha256(convert_to(tok, 'UTF8')), 'hex'), oid, auth.uid());
  return tok;                                  -- shown once; only its hash is kept
end $$;

create function public.revoke_sync_links() returns integer
language plpgsql security definer set search_path = '' as $$
declare n integer;
begin
  if not exists (select 1 from public.org_members where user_id = auth.uid() and role = 'admin') then
    raise exception 'Admins only.';
  end if;
  delete from public.sync_links where org_id = public.my_org();
  get diagnostics n = row_count;
  return n;
end $$;

-- ------------------------------------------------------------------ sync functions (the Mac, by token)
create function public.sync_org(p_token text) returns uuid
language plpgsql security definer set search_path = '' as $$
declare oid uuid;
begin
  update public.sync_links set last_used_at = now()
    where token_hash = encode(sha256(convert_to(coalesce(p_token, ''), 'UTF8')), 'hex')
    returning org_id into oid;
  if oid is null then raise exception 'SYNC LINK NOT RECOGNISED'; end if;
  return oid;
end $$;

create function public.sync_pull(p_token text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare oid uuid := public.sync_org(p_token);
begin
  return jsonb_build_object(
    'org', (select jsonb_build_object('id', id, 'name', name) from public.orgs where id = oid),
    'settings', coalesce((select jsonb_object_agg(node, settings) from public.nodes where org_id = oid), '{}'::jsonb),
    'acks', coalesce((select jsonb_object_agg(alert_id, jsonb_build_object('by', by_name, 'at', extract(epoch from at)::bigint))
                      from public.alert_acks where org_id = oid), '{}'::jsonb),
    'readings', coalesce((select jsonb_object_agg(node || '_' || chain, mx) from
                      (select node, chain, max(seq) mx from public.readings where org_id = oid group by node, chain) r), '{}'::jsonb),
    'taken', coalesce((select jsonb_agg(node) from public.nodes where org_id <> oid), '[]'::jsonb));
end $$;

create function public.sync_push(p_token text, p jsonb) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare oid uuid := public.sync_org(p_token); mine text[]; n_read integer := 0;
begin
  -- nodes: claim new ones for this organisation; never take a node another organisation holds
  insert into public.nodes (node, org_id)
    select x ->> 'node', oid from jsonb_array_elements(coalesce(p -> 'nodes', '[]')) x
    on conflict (node) do nothing;
  select coalesce(array_agg(node), '{}') into mine from public.nodes where org_id = oid;

  insert into public.node_views (node, org_id, data, updated_at)
    select x ->> 'node', oid, x -> 'view', now() from jsonb_array_elements(coalesce(p -> 'nodes', '[]')) x
    where x ->> 'node' = any (mine)
    on conflict (node) do update set data = excluded.data, updated_at = now();

  insert into public.trip_views (node, chain, org_id, data, updated_at)
    select x ->> 'node', x ->> 'chain', oid, x -> 'view', now() from jsonb_array_elements(coalesce(p -> 'trips', '[]')) x
    where x ->> 'node' = any (mine)
    on conflict (node, chain) do update set data = excluded.data, updated_at = now();

  if p ? 'alerts' then                         -- the full current set: replace
    delete from public.alerts where org_id = oid
      and id not in (select x ->> 'id' from jsonb_array_elements(p -> 'alerts') x);
    insert into public.alerts (org_id, id, node, data, updated_at)
      select oid, x ->> 'id', x ->> 'node', x, now() from jsonb_array_elements(p -> 'alerts') x
      where x ->> 'node' is null or x ->> 'node' = any (mine)
      on conflict (org_id, id) do update set data = excluded.data, node = excluded.node, updated_at = now();
  end if;

  insert into public.readings (node, chain, seq, org_id, t, temp_c, rh_pct, flags, line)
    select x ->> 'node', x ->> 'chain', (x ->> 'seq')::int, oid, nullif(x ->> 't', '')::bigint,
           nullif(x ->> 'temp', '')::numeric, nullif(x ->> 'rh', '')::numeric, coalesce((x ->> 'flags')::int, 0), x ->> 'line'
    from jsonb_array_elements(coalesce(p -> 'readings', '[]')) x
    where x ->> 'node' = any (mine)
    on conflict (node, chain, seq) do nothing;
  get diagnostics n_read = row_count;

  if p ? 'status' then
    insert into public.sync_status (org_id, data, synced_at) values (oid, p -> 'status', now())
      on conflict (org_id) do update set data = excluded.data, synced_at = now();
  end if;
  return jsonb_build_object('ok', true, 'nodes', cardinality(mine), 'readings', n_read);
end $$;

-- ------------------------------------------------------------------ who may call what
revoke execute on all functions in schema public from public, anon, authenticated;
grant execute on function public.my_org(), public.is_staff(), public.my_context(), public.create_org(text),
  public.join_org(text), public.team(), public.rotate_invite(), public.save_node_settings(text, jsonb),
  public.create_sync_link(), public.revoke_sync_links() to authenticated;
grant execute on function public.sync_pull(text), public.sync_push(text, jsonb) to anon, authenticated;
