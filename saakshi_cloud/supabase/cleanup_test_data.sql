-- Remove the automated test data (accounts samxdevs+st-*@gmail.com, their TEST organisations with the
-- SIMULATED nodes, and the test node requests). Touches nothing else.
delete from public.orgs where id in (
  select om.org_id from public.org_members om join auth.users u on u.id = om.user_id
  where u.email like 'samxdevs+st-%@gmail.com');
delete from auth.users where email like 'samxdevs+st-%@gmail.com';
delete from public.orders where note = 'automated test, please delete';
select (select count(*) from auth.users where email like 'samxdevs+st-%') as test_users_left,
       (select count(*) from public.orgs where name like 'TEST %') as test_orgs_left,
       (select count(*) from public.nodes) as nodes_left,
       (select count(*) from public.orders) as requests_left;
