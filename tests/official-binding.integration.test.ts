import { describe, expect, it } from 'vitest';
import { bindingSql } from './support/official-binding-db';
const D = "repeat('a',64)", E = "repeat('b',64)";
const status = 'public.internal_account_status(u.id,u.session_id,null)';
const deletion = 'public.internal_community_delete_contributions(u.id,u.session_id)';
const release = (owner = 'u.id') => `public.internal_account_release_official_account(${D},${owner},'ticket-synthetic','verified test')`;
const connect = (i: number, d = D, takeover = false) => `select pg_temp.binding_connect(${i},${d},${takeover});`;
describe.skipIf(process.env.COMMUNITY_STACK !== '1')('official binding on local PostgreSQL (rollback)', () => {
  it('returns null binding then binds atomically, with only own status', () => {
    const rows = bindingSql(`select ${status} from binding_users u where idx=1;${connect(1)}
      select ${status} from binding_users u order by idx;`);
    expect(rows).toHaveLength(5);
    expect(rows[0].official_account).toEqual({ dataset_key: null, bound_at: null });
    expect(rows[1].connection_id).toBeTypeOf('string');
    expect(rows[2].official_account.dataset_key).toBe('a'.repeat(64));
    expect(Date.parse(rows[2].official_account.bound_at)).not.toBeNaN();
    expect(rows[3].official_account.dataset_key).toBeNull();
    expect(rows[4].official_account.dataset_key).toBeNull();
  });
  it('rejects mismatch/taken even with takeover, leaving exactly one connection and binding', () => {
    const rows = bindingSql(`${connect(1)}${connect(1,E,true)}${connect(2,D,true)}
      select jsonb_build_object('connections',(select count(*) from private.community_connections),
        'bindings',(select count(*) from private.community_official_account_bindings));`);
    expect(rows).toHaveLength(4);
    expect(rows[1]).toEqual({ error: 'official_account_mismatch', bound_dataset_key: 'a'.repeat(64) });
    expect(rows[2]).toEqual({ error: 'official_account_taken' });
    expect(rows[3]).toEqual({ connections: 1, bindings: 1 });
  });
  it('preserves writer conflict/takeover and connection revocation keeps binding', () => {
    const rows = bindingSql(`${connect(1)}${connect(1)}${connect(1,D,true)}
      select public.internal_account_revoke_connection(id,connection_id) from binding_users where idx=1;
      select ${status} from binding_users u where idx=1;`);
    expect(rows).toHaveLength(5);
    expect(rows[1].error).toBe('writer_conflict');
    expect(rows[2].superseded_previous).toBe(true);
    expect(rows[2].writer_epoch).toBeGreaterThan(rows[0].writer_epoch);
    expect(rows[4].official_account.dataset_key).toBe('a'.repeat(64));
  });
  it('delete releases binding, revokes connection, records audit and allows account change; repeat is safe', () => {
    const rows = bindingSql(`${connect(1)}select ${deletion} from binding_users u where idx=1;
      select ${deletion} from binding_users u where idx=1;${connect(1,E)}${connect(2,D)}
      select jsonb_build_object('audit',(select count(*) from private.community_official_account_audit),
        'fence',(select count(*) from private.community_deletion_fences where contributor_id=(select id from binding_users where idx=1)));`);
    expect(rows).toHaveLength(6);
    expect(rows[1]).toMatchObject({ official_account_released: true, revoked_connections: 1 });
    expect(rows[2]).toMatchObject({ official_account_released: true, revoked_connections: 0 });
    expect(rows[3].connection_id).toBeTypeOf('string'); expect(rows[4].connection_id).toBeTypeOf('string');
    expect(rows[5]).toEqual({ audit: 1, fence: 1 });
  });
  it('operator release is audited, revokes writers, refuses stale owner and does not free replacement', () => {
    const rows = bindingSql(`${connect(1)}
      select ${release()} from binding_users u where idx=2;
      select ${release()} from binding_users u where idx=1;${connect(2)}
      select ${release()} from binding_users u where idx=1;
      select jsonb_build_object('n',count(*),'reason',min(reason),'operator',min(operator_ref)) from private.community_official_account_audit;`);
    expect(rows).toHaveLength(6);
    expect(rows[1]).toEqual({ error: 'not_found' });
    expect(rows[2]).toMatchObject({ official_account_released: true, revoked_connections: 1 });
    expect(rows[4]).toEqual({ error: 'not_found' });
    expect(rows[5]).toEqual({ n: 1, reason: 'verified test', operator: 'ticket-synthetic' });
  });
  it('denies public roles and grants only service execution/read audit', () => {
    const rows = bindingSql(`select jsonb_build_object('anon',has_function_privilege('anon','public.internal_account_release_official_account(text,uuid,text,text)','execute'),
      'authenticated',has_function_privilege('authenticated','public.internal_account_release_official_account(text,uuid,text,text)','execute'),
      'service',has_function_privilege('service_role','public.internal_account_release_official_account(text,uuid,text,text)','execute'),
      'table',has_table_privilege('authenticated','private.community_official_account_bindings','select'),
      'audit_mutation',has_table_privilege('service_role','private.community_official_account_audit','update'));`);
    expect(rows).toEqual([{ anon: false, authenticated: false, service: true, table: false, audit_mutation: false }]);
  });
  it('backfills a revoked connection but excludes connections before a completed deletion fence', () => {
    const rows = bindingSql(`select ${status} from binding_users u order by idx;`, `${connect(1)}${connect(2,E)}
      update private.community_connections set status='revoked';
      select ${deletion} from binding_users u where idx=2;`);
    expect(rows).toHaveLength(6);
    expect(rows[3].official_account.dataset_key).toBe('a'.repeat(64));
    expect(rows[4].official_account.dataset_key).toBeNull();
  });
  it.each(['user', 'dataset'])('fails backfill on %s conflict (no overwrite)', kind => {
    expect(() => bindingSql('', `${connect(1)}${kind === 'user' ? connect(1,E) : connect(2,D)}`))
      .toThrow(/OFFICIAL_ACCOUNT_BACKFILL_CONFLICT/);
  });
  it('enforces both unique constraints even for privileged direct SQL', () => {
    const r = bindingSql(`${connect(1)}do $$ declare u1 uuid; u2 uuid; begin
      select id into u1 from binding_users where idx=1; select id into u2 from binding_users where idx=2;
      begin insert into private.community_official_account_bindings(user_id,dataset_key) values(u1,${E});
        raise exception 'user uniqueness missing'; exception when unique_violation then null; end;
      begin insert into private.community_official_account_bindings(user_id,dataset_key) values(u2,${D});
        raise exception 'dataset uniqueness missing'; exception when unique_violation then null; end;
      end $$;select jsonb_build_object('n',count(*)) from private.community_official_account_bindings;`);
    expect(r).toHaveLength(2); expect(r[1]).toEqual({ n: 1 });
  });
  it('executes release as service_role, rejects blank operator audit context', () => {
    const r = bindingSql(`${connect(1)}
      select public.internal_account_release_official_account(${D},id,' ','why') from binding_users where idx=1;
      grant select on binding_users to service_role;set local role service_role;
      select ${release()} from binding_users u where idx=1;reset role;`);
    expect(r).toHaveLength(3); expect(r[1]).toEqual({ error: 'invalid_request' });
    expect(r[2]).toMatchObject({ official_account_released: true, revoked_connections: 1 });
  });
  it('rolls back binding and takeover if the connection insert fails', () => {
    const rows = bindingSql(`do $$ declare u record; begin
      select * into u from binding_users where idx=1;
      begin perform public.internal_account_register_connection(u.id,u.session_id,'safetyreport','server','bad-platform','test',${D},repeat('a',64),false);
        raise exception 'expected failure'; exception when check_violation then null; end;
      end $$; select jsonb_build_object('n',count(*)) from private.community_official_account_bindings;`);
    expect(rows).toEqual([{ n: 0 }]);
  });
  it('operator deletion affects only the expected user/dataset and persists complete audit counts', () => {
    const r = bindingSql(`${connect(1)}${connect(2,E)}
      insert into private.community_connections(user_id,bound_session_id,connection_secret_sha256,source_app,source_mode,platform,device_label,dataset_key)
      select id,session_id,repeat('a',64),'safetyreport','server','linux','legacy',${E} from binding_users where idx=1;
      insert into private.community_report_facts(contributor_id,dataset_key,source_report_key,source_report_id,latest_receipt_id,
        consent_grant_id,writer_epoch,source_revision,payload_sha256,public_state,category,status,disposition,amount_kind,coord_source)
      select u.id,d,repeat('f',64),'SCOPE',gen_random_uuid(),gen_random_uuid(),1,1,repeat('f',64),
        'completed','traffic','accepted','none','unknown','none'
      from binding_users u cross join (values (${D}),(${E})) datasets(d) where u.idx in (1,2);
      create temp table prior_version as select dataset_version from private.analytics_state;
      select ${release()} from binding_users u where idx=1;
      select jsonb_build_object('facts', (select count(*) from private.community_report_facts),
        'other_connections', (select count(*) from private.community_connections where status='active'),
        'global_fence', (select count(*) from private.community_deletion_fences where contributor_id in (select id from binding_users)),
        'scoped_fence', (select count(*) from private.community_dataset_deletion_fences),
        'tombstones', (select count(*) from private.community_dataset_fact_tombstones),
        'projection_changed', (select a.dataset_version<>p.dataset_version from private.analytics_state a cross join prior_version p),
        'audit', (select jsonb_build_object('owner',user_id=(select id from binding_users where idx=1),
          'dataset',dataset_key,'deleted',deleted_facts,'tombstones',tombstoned_identities,'connections',revoked_connections,
          'fenced',fenced_at is not null,'dated',occurred_at is not null,'deletion',deletion_id) from private.community_official_account_audit));`);
    expect(r).toHaveLength(4);
    expect(r[2]).toMatchObject({ deleted_facts: 1, tombstoned_identities: 1, revoked_connections: 1, official_account_released: true });
    expect(r[3]).toEqual({ facts: 3, other_connections: 2, global_fence: 0, scoped_fence: 1, tombstones: 1,
      projection_changed: true, audit: { owner: true, dataset: 'a'.repeat(64), deleted: 1, tombstones: 1,
        connections: 1, fenced: true, dated: true, deletion: r[2].deletion_id } });
  });
  it('rolls back deletion, fence, revocation and binding release when audit insertion fails', () => {
    const r = bindingSql(`${connect(1)}
      insert into private.community_report_facts(contributor_id,dataset_key,source_report_key,source_report_id,latest_receipt_id,
        consent_grant_id,writer_epoch,source_revision,payload_sha256,public_state,category,status,disposition,amount_kind,coord_source)
      select id,${D},repeat('f',64),'ATOMIC',gen_random_uuid(),gen_random_uuid(),1,1,repeat('f',64),
        'completed','traffic','accepted','none','unknown','none' from binding_users where idx=1;
      create function pg_temp.reject_audit() returns trigger language plpgsql as $$ begin raise exception 'synthetic audit failure'; end $$;
      create trigger reject_audit before insert on private.community_official_account_audit for each row execute function pg_temp.reject_audit();
      do $$ begin
        begin perform public.internal_account_release_official_account(${D},(select id from binding_users where idx=1),'ticket','reason');
          raise exception 'expected audit failure';
        exception when raise_exception then if sqlerrm <> 'synthetic audit failure' then raise; end if; end;
      end $$;
      select jsonb_build_object('bindings',(select count(*) from private.community_official_account_bindings),
        'active',(select count(*) from private.community_connections where status='active'),
        'fences',(select count(*) from private.community_dataset_deletion_fences),
        'facts',(select count(*) from private.community_report_facts),
        'tombstones',(select count(*) from private.community_dataset_fact_tombstones),
        'audit',(select count(*) from private.community_official_account_audit));`);
    expect(r).toHaveLength(2); expect(r[1]).toEqual({ bindings: 1, active: 1, fences: 0, facts: 1, tombstones: 0, audit: 0 });
  });
  it('keeps Kakao mandatory for the replacement owner', () => {
    const r = bindingSql(`${connect(1)}select ${release()} from binding_users u where idx=1;
      delete from auth.identities where user_id=(select id from binding_users where idx=2);${connect(2)}
      select jsonb_build_object('bindings',count(*)) from private.community_official_account_bindings;`);
    expect(r).toHaveLength(4); expect(r[2]).toEqual({ error: 'kakao_required' }); expect(r[3]).toEqual({ bindings: 0 });
  });

  it('never moves a scoped fence backwards and denies client reads or service direct mutations', () => {
    const r = bindingSql(`${connect(1)}
      insert into private.community_dataset_deletion_fences(contributor_id,dataset_key,deletion_id,fenced_at)
      select id,${D},gen_random_uuid(),'2099-01-01Z' from binding_users where idx=1;
      select ${release()} from binding_users u where idx=1;
      select jsonb_build_object('monotonic',fenced_at='2099-01-01Z'::timestamptz,
        'anon',has_table_privilege('anon','private.community_dataset_deletion_fences','select'),
        'authenticated',has_table_privilege('authenticated','private.community_dataset_fact_tombstones','select'),
        'service_mutation',has_table_privilege('service_role','private.community_dataset_deletion_fences','update'))
      from private.community_dataset_deletion_fences;`);
    expect(r).toHaveLength(3);
    expect(r[1]).toMatchObject({ deleted_facts: 0, tombstoned_identities: 0, revoked_connections: 1 });
    expect(r[2]).toEqual({ monotonic: true, anon: false, authenticated: false, service_mutation: false });
  });

});
