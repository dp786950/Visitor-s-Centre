-- Parliament of Ghana Visitors Centre: run once in a NEW Supabase project (SQL Editor)
create extension if not exists pgcrypto;
create table profiles(id uuid primary key references auth.users(id) on delete cascade, full_name text, email text, role text not null default 'reception' check(role in('admin','reception')), status text not null default 'inactive' check(status in('active','inactive')), created_at timestamptz default now());
create table reception_posts(id bigint generated always as identity primary key, name text unique not null, location text, active boolean default true);
create table mp_office_directory(id bigint generated always as identity primary key, mp_name text, office_name text, department text, designation text, receiving_officer text, location text, active boolean default true);
create table visitors(id bigint generated always as identity primary key, full_name text not null, gender text, nationality text, phone text, email text, organisation text, created_at timestamptz default now(), created_by uuid);
create table visitor_identification(id bigint generated always as identity primary key, visitor_id bigint not null references visitors(id), id_type text, id_masked text, verification_status text default 'Not Verified', issuing_country text, verified_by uuid, created_at timestamptz default now());
create table visit_records(id bigint generated always as identity primary key, visitor_reference text unique not null, group_reference text, group_leader text, group_size int default 1,
 visitor_id bigint not null references visitors(id), host_name text, host_designation text, office text, destination_room text, purpose text, appointment_type text, person_contacted text,
 entry_post_id bigint references reception_posts(id), entry_officer uuid, entry_at timestamptz, expected_at timestamptz, exit_at timestamptz, exit_post_id bigint references reception_posts(id), exit_officer uuid,
 status text not null default 'Expected' check(status in('Expected','Checked In','Checked Out','Cancelled')), pass_generated boolean default false, pass_printed_at timestamptz, pass_print_count int default 0,
 registered_by uuid, created_at timestamptz default now(), created_by uuid default auth.uid(), updated_at timestamptz default now(), updated_by uuid);
create index on visit_records(group_reference); create index on visit_records(status); create index on visit_records(created_at); create index on visit_records(visitor_id);
create table system_settings(key text primary key, value text);
create table audit_logs(id bigint generated always as identity primary key, user_id uuid, action text, record_type text, record_id text, details jsonb, created_at timestamptz default now());
create table ref_counters(key text primary key, last bigint not null default 0);

create function is_staff() returns boolean language sql stable security definer set search_path=public as $$ select exists(select 1 from profiles where id=auth.uid() and status='active') $$;
create function is_admin() returns boolean language sql stable security definer set search_path=public as $$ select exists(select 1 from profiles where id=auth.uid() and status='active' and role='admin') $$;
create function handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$ begin insert into profiles(id,email,full_name) values(new.id,new.email,coalesce(new.raw_user_meta_data->>'full_name',split_part(new.email,'@',1))); return new; end $$;
create trigger on_auth_user after insert on auth.users for each row execute function handle_new_user();
create function stamp() returns trigger language plpgsql set search_path=public as $$ begin new.updated_at:=now(); new.updated_by:=auth.uid(); return new; end $$;
create trigger trg_stamp before update on visit_records for each row execute function stamp();
create function audit() returns trigger language plpgsql security definer set search_path=public as $$ begin
 insert into audit_logs(user_id,action,record_type,record_id,details) values(auth.uid(),tg_op,tg_table_name,coalesce((to_jsonb(new)->>'id'),(to_jsonb(old)->>'id')),jsonb_build_object('old',to_jsonb(old),'new',to_jsonb(new))); return null; end $$;
create trigger a1 after insert or update or delete on visit_records for each row execute function audit();
create trigger a2 after insert or update or delete on reception_posts for each row execute function audit();
create trigger a3 after insert or update or delete on mp_office_directory for each row execute function audit();
create trigger a4 after update or delete on profiles for each row execute function audit();

-- Staff-safe logbook view (phone masked for non-admins; identification numbers never exposed)
create view visit_log as select r.id,r.visitor_reference,r.group_reference,r.group_leader,r.group_size,v.full_name,v.gender,v.nationality,
 case when is_admin() then v.phone else left(v.phone,3)||repeat('*',greatest(length(v.phone)-5,0))||right(v.phone,2) end as phone, v.organisation,
 i.id_type,i.verification_status,r.host_name,r.host_designation,r.office,r.destination_room,r.purpose,r.appointment_type,r.person_contacted,
 p.name as entry_post,r.entry_post_id,r.entry_at,r.expected_at,r.exit_at,xp.name as exit_post,r.status,r.pass_generated,r.pass_print_count,r.pass_printed_at,
 pr.full_name as registered_by_name,r.created_at,(coalesce(r.entry_at,r.expected_at,r.created_at) at time zone 'Africa/Accra')::date as visit_date
from visit_records r join visitors v on v.id=r.visitor_id
left join lateral (select id_type,verification_status from visitor_identification where visitor_id=v.id limit 1) i on true
left join reception_posts p on p.id=r.entry_post_id left join reception_posts xp on xp.id=r.exit_post_id left join profiles pr on pr.id=r.registered_by
where is_staff();
revoke all on visit_log from anon; grant select on visit_log to authenticated;

-- Registration: references generated atomically on the server (never duplicated, never reused)
create function register_visit(p jsonb) returns jsonb language plpgsql security definer set search_path=public as $$
declare yr text:=to_char(now() at time zone 'Africa/Accra','YYYY'); ppl jsonb:=p->'people'; n int:=jsonb_array_length(p->'people'); gref text; x jsonb; vid bigint; c bigint; ref text; res jsonb:='[]'; leader text:=p->'people'->0->>'full_name';
 st text:=case when p->>'mode'='checkin' then 'Checked In' else 'Expected' end;
begin
 if not is_staff() then raise exception 'Not authorised'; end if;
 if n<1 or n>50 then raise exception 'Invalid group size'; end if;
 if n>1 then insert into ref_counters(key,last) values('G'||yr,1) on conflict(key) do update set last=ref_counters.last+1 returning last into c; gref:='PG-GR-'||yr||'-'||lpad(c::text,5,'0'); end if;
 for x in select value from jsonb_array_elements(ppl) loop
  insert into visitors(full_name,gender,nationality,phone,email,organisation,created_by) values(trim(x->>'full_name'),x->>'gender',x->>'nationality',x->>'phone',x->>'email',x->>'organisation',auth.uid()) returning id into vid;
  if coalesce(x->>'id_type','')<>'' then insert into visitor_identification(visitor_id,id_type,id_masked,verification_status,issuing_country,verified_by) values(vid,x->>'id_type',x->>'id_masked',coalesce(x->>'verification_status','Not Verified'),x->>'issuing_country',auth.uid()); end if;
  insert into ref_counters(key,last) values('V'||yr,1) on conflict(key) do update set last=ref_counters.last+1 returning last into c;
  ref:='PG-VC-'||yr||'-'||lpad(c::text,5,'0');
  insert into visit_records(visitor_reference,group_reference,group_leader,group_size,visitor_id,host_name,host_designation,office,destination_room,purpose,appointment_type,person_contacted,entry_post_id,entry_officer,entry_at,expected_at,status,registered_by)
  values(ref,gref,case when n>1 then leader end,n,vid,p->>'host_name',p->>'host_designation',p->>'office',p->>'destination_room',p->>'purpose',p->>'appointment_type',p->>'person_contacted',nullif(p->>'post_id','')::bigint,
   case when st='Checked In' then auth.uid() end,case when st='Checked In' then now() end,coalesce(nullif(p->>'expected_at','')::timestamptz,now()),st,auth.uid());
  res:=res||jsonb_build_object('ref',ref,'gref',gref);
 end loop;
 insert into audit_logs(user_id,action,record_type,record_id,details) values(auth.uid(),'register','visit',coalesce(gref,ref),jsonb_build_object('people',n));
 return res;
end $$;

create function visit_action(vid bigint, act text, post bigint default null) returns void language plpgsql security definer set search_path=public as $$
begin
 if not is_staff() then raise exception 'Not authorised'; end if;
 if act='checkin' then update visit_records set status='Checked In',entry_at=now(),entry_post_id=coalesce(post,entry_post_id),entry_officer=auth.uid() where id=vid and status='Expected';
 elsif act='checkout' then update visit_records set status='Checked Out',exit_at=now(),exit_post_id=post,exit_officer=auth.uid() where id=vid and status='Checked In';
 elsif act='cancel' then if not is_admin() then raise exception 'Only administrators can cancel records'; end if; update visit_records set status='Cancelled' where id=vid and status in('Expected','Checked In');
 elsif act='print' then update visit_records set pass_generated=true,pass_print_count=pass_print_count+1,pass_printed_at=coalesce(pass_printed_at,now()) where id=vid;
 else raise exception 'Unknown action'; end if;
 if not found then raise exception 'Action not allowed for the current visit status'; end if;
 insert into audit_logs(user_id,action,record_type,record_id,details) values(auth.uid(),act,'visit',vid::text,null);
end $$;

create function period_stats(a date,b date) returns jsonb language sql stable security definer set search_path=public as $$
with v as (select * from visit_log where status<>'Cancelled' and visit_date between a and b)
select case when not is_staff() then null else jsonb_build_object(
 'total',(select count(*) from v),
 'inside',(select count(*) from visit_log where status='Checked In'),
 'out',(select count(*) from v where status='Checked Out'),
 'expected',(select count(*) from visit_log where status='Expected' and visit_date>=a),
 'offices',(select count(distinct office) from v),
 'by_day',(select coalesce(jsonb_agg(jsonb_build_object('k',k,'n',n) order by k),'[]') from (select visit_date k,count(*) n from v group by 1) t),
 'by_month',(select coalesce(jsonb_agg(jsonb_build_object('k',k,'n',n) order by k),'[]') from (select extract(month from visit_date)::int k,count(*) n from v group by 1) t),
 'by_year',(select coalesce(jsonb_agg(jsonb_build_object('k',k,'n',n) order by k),'[]') from (select extract(year from visit_date)::int k,count(*) n from visit_log where status<>'Cancelled' group by 1) t),
 'gender',(select coalesce(jsonb_agg(jsonb_build_object('k',k,'n',n)),'[]') from (select coalesce(gender,'Not stated') k,count(*) n from v group by 1) t),
 'office',(select coalesce(jsonb_agg(jsonb_build_object('k',k,'n',n)),'[]') from (select coalesce(office,host_name,'Unspecified') k,count(*) n from v group by 1 order by n desc limit 10) t),
 'entrance',(select coalesce(jsonb_agg(jsonb_build_object('k',k,'n',n)),'[]') from (select coalesce(entry_post,'Unassigned') k,count(*) n from v group by 1 order by n desc) t)) end $$;
revoke execute on function register_visit(jsonb),visit_action(bigint,text,bigint),period_stats(date,date) from public, anon;
grant execute on function register_visit(jsonb),visit_action(bigint,text,bigint),period_stats(date,date) to authenticated;

-- Row Level Security (raw tables hold personal data: only administrators read/write them directly)
alter table profiles enable row level security; alter table reception_posts enable row level security; alter table mp_office_directory enable row level security; alter table visitors enable row level security;
alter table visitor_identification enable row level security; alter table visit_records enable row level security; alter table system_settings enable row level security; alter table audit_logs enable row level security; alter table ref_counters enable row level security;
create policy "own profile" on profiles for select to authenticated using (id=auth.uid() or is_admin());
create policy "admin profiles" on profiles for update to authenticated using (is_admin()) with check (is_admin());
create policy "staff read posts" on reception_posts for select to authenticated using (is_staff());
create policy "admin posts" on reception_posts for all to authenticated using (is_admin()) with check (is_admin());
create policy "staff read dir" on mp_office_directory for select to authenticated using (is_staff());
create policy "admin dir" on mp_office_directory for all to authenticated using (is_admin()) with check (is_admin());
create policy "admin visitors" on visitors for all to authenticated using (is_admin()) with check (is_admin());
create policy "admin ident" on visitor_identification for all to authenticated using (is_admin()) with check (is_admin());
create policy "staff read visits" on visit_records for select to authenticated using (is_staff());
create policy "admin visits" on visit_records for update to authenticated using (is_admin()) with check (is_admin());
create policy "staff read settings" on system_settings for select to authenticated using (is_staff());
create policy "admin settings" on system_settings for all to authenticated using (is_admin()) with check (is_admin());
create policy "admin audit" on audit_logs for select to authenticated using (is_admin());
-- no DELETE policy anywhere: historical visitor records cannot be deleted through the app
alter publication supabase_realtime add table visit_records;

-- SAMPLE SETUP DATA (edit in the app)
insert into reception_posts(name) values('Main Reception Entrance'),('Visitors Centre Reception'),('Chamber Annex Entrance'),('Job 600 Annex Entrance'),('Speaker''s Block Entrance');
insert into mp_office_directory(mp_name,office_name,department,designation,receiving_officer,location) values
 ('Sample MP (demo)','Office of the Sample MP','Parliamentary Services','Member of Parliament','Clerk (demo)','Job 600, Room 101'),
 (null,'Public Relations Office (demo)','Public Affairs','Office','Officer (demo)','Main Building, Ground Floor');
insert into system_settings values('retention_months','84');

-- AFTER creating your first user in Authentication > Users, make them the administrator:
-- update profiles set role='admin', status='active' where email='you@example.com';
