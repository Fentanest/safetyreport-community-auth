-- Synthetic fixtures only. Caller MUST wrap this entire file and migration in BEGIN/ROLLBACK.
-- Existing shared-stack rows are hidden only within the transaction, following map's SQL test pattern.
alter table private.community_report_facts disable trigger user;
delete from private.community_report_facts;
alter table private.community_report_facts enable trigger user;
delete from private.community_connections;
create temp table binding_users as
select n as idx, gen_random_uuid() as id, gen_random_uuid() as session_id,
       null::uuid as connection_id, null::uuid as grant_id, null::bigint as epoch
from generate_series(1,3) n;
insert into auth.users(id,aud,role,created_at,updated_at)
select id,'authenticated','authenticated',now(),now() from binding_users;
insert into auth.identities(provider_id,user_id,identity_data,provider,created_at,updated_at)
select id::text,id,jsonb_build_object('sub',id::text),'kakao',now(),now() from binding_users;
insert into auth.sessions(id,user_id,created_at,updated_at,aal)
select session_id,id,now(),now(),'aal1' from binding_users;
create function pg_temp.binding_connect(i integer, dataset text, takeover boolean default false) returns jsonb
language plpgsql as $$ declare r jsonb; u record; begin
 select * into u from binding_users where idx=i;
 r := public.internal_account_register_connection(u.id,u.session_id,'safetyreport','server','linux',
       'binding synthetic',dataset,repeat('a',64),takeover);
 if r ? 'connection_id' then
   update binding_users set connection_id=(r->>'connection_id')::uuid, epoch=(r->>'writer_epoch')::bigint where idx=i;
 end if;
 return r;
end $$;
create function pg_temp.binding_consent(i integer) returns jsonb language plpgsql as $$
declare r jsonb; u record; p private.community_policies; begin
 select * into u from binding_users where idx=i;
 p := private.community_current_policy(false);
 r := public.internal_account_grant_consent(u.id,u.session_id,p.version,p.consent_text_sha256,'safetyreport_server');
 update binding_users set grant_id=(r->>'grant_id')::uuid where idx=i;
 return r;
end $$;
