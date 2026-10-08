-- SAAKSHI online dashboard: hardening after the security review (9 Oct 2026).

-- 1. The public "Request nodes" form can't be used to flood the database:
--    at most 20 requests in any 10 minutes, across everyone.
create function public.orders_rate_limit() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if (select count(*) from public.orders where created_at > now() - interval '10 minutes') >= 20 then
    raise exception 'Too many requests right now. Please try again in a few minutes.';
  end if;
  return new;
end $$;
create trigger orders_rate_limit before insert on public.orders
  for each row execute function public.orders_rate_limit();

-- 2. "Acknowledged by" always shows the real account's name: the database fills it in,
--    whatever the browser sent.
create function public.alert_acks_who() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  new.by_user := auth.uid();
  new.by_name := coalesce((select nullif(name, '') from public.profiles where user_id = auth.uid()),
                          (select email from public.profiles where user_id = auth.uid()), '');
  new.at := now();
  return new;
end $$;
create trigger alert_acks_who before insert on public.alert_acks
  for each row execute function public.alert_acks_who();

revoke execute on function public.orders_rate_limit(), public.alert_acks_who() from public, anon, authenticated;
