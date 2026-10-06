-- Official account binding v1. Owner: auth. Apply before map 202610061101 and Edge.
-- Depends on map 202609281800_rating.sql (facts, fences and deletion RPC).
begin;
-- Block legacy writers during the snapshot/backfill and RPC replacement.
lock table private.community_connections, private.community_report_facts in share row exclusive mode;
create table private.community_official_account_bindings (
    user_id uuid primary key references auth.users(id) on delete cascade,
    dataset_key text not null unique check (dataset_key ~ '^[0-9a-f]{64}$'),
    bound_at timestamptz not null default clock_timestamp()
);
create table private.community_official_account_audit (
    audit_id uuid primary key default gen_random_uuid(),
    occurred_at timestamptz not null default clock_timestamp(),
    action text not null check (action in ('operator_release', 'contributions_delete')),
    user_id uuid,
    dataset_key text not null,
    operator_ref text,
    reason text,
    revoked_connections integer not null default 0,
    deleted_facts integer not null default 0,
    tombstoned_identities integer not null default 0,
    deletion_id uuid,
    fenced_at timestamptz
);
alter table private.community_official_account_bindings enable row level security;
alter table private.community_official_account_audit enable row level security;
revoke all on private.community_official_account_bindings, private.community_official_account_audit from public, anon, authenticated, service_role;
grant select on private.community_official_account_bindings, private.community_official_account_audit to service_role;

-- Operator deletion is scoped to the previous contributor AND dataset. Keep the existing
-- all-contributions fence/tombstones intact for the user-initiated delete endpoint.
create table private.community_dataset_deletion_fences (
    contributor_id uuid not null,
    dataset_key text not null check (dataset_key ~ '^[0-9a-f]{64}$'),
    deletion_id uuid not null,
    fenced_at timestamptz not null,
    primary key (contributor_id, dataset_key)
);
create table private.community_dataset_fact_tombstones (
    contributor_id uuid not null,
    dataset_key text not null check (dataset_key ~ '^[0-9a-f]{64}$'),
    source_report_key text not null,
    deletion_id uuid not null,
    deleted_at timestamptz not null default clock_timestamp(),
    primary key (contributor_id, dataset_key, source_report_key)
);
alter table private.community_dataset_deletion_fences enable row level security;
alter table private.community_dataset_fact_tombstones enable row level security;
revoke all on private.community_dataset_deletion_fences, private.community_dataset_fact_tombstones
    from public, anon, authenticated, service_role;
grant select on private.community_dataset_deletion_fences, private.community_dataset_fact_tombstones to service_role;

-- Revocation alone retains the binding. A completed contributions-delete is the only historical
-- release boundary: inactive connections created before that user's fence must not resurrect it.
-- Active writers are retained even when their transaction began before a concurrent deletion.
create temporary table official_binding_backfill on commit drop as
select user_id, dataset_key, min(bound_at) as bound_at from (
    select c.user_id, c.dataset_key, c.created_at as bound_at
      from private.community_connections c
     where c.status = 'active' or not exists (select 1 from private.community_deletion_fences f
                       where f.contributor_id=c.user_id and c.created_at <= f.fenced_at)
    union all
    select contributor_id, dataset_key, first_accepted_at from private.community_report_facts
) s group by user_id, dataset_key;
do $$ begin
    if exists (select 1 from official_binding_backfill group by user_id having count(*) > 1)
       or exists (select 1 from official_binding_backfill group by dataset_key having count(*) > 1) then
        raise exception 'OFFICIAL_ACCOUNT_BACKFILL_CONFLICT' using errcode='23505';
    end if;
end $$;
insert into private.community_official_account_bindings(user_id,dataset_key,bound_at)
select user_id,dataset_key,bound_at from official_binding_backfill;

create or replace function public.internal_account_register_connection(
    p_user uuid, p_session uuid, p_source_app text, p_source_mode text, p_platform text,
    p_device_label text, p_dataset_key text, p_secret_sha256 text, p_takeover boolean)
returns jsonb language plpgsql volatile security definer set search_path = '' as $$
declare
    v_policy private.community_policies%rowtype := private.community_current_policy(true);
    v_id jsonb := private.community_identity_state(p_user, p_session);
    v_bound text;
    v_other private.community_connections%rowtype;
    v_new private.community_connections%rowtype;
begin
    if not ((v_id->>'user_ok')::boolean and (v_id->>'kakao')::boolean and (v_id->>'session')::boolean) then
        return jsonb_build_object('error', 'kakao_required');
    end if;
    perform private.community_lock_contributor(p_user, true);
    if p_dataset_key is null or p_dataset_key !~ '^[0-9a-f]{64}$' then
        return jsonb_build_object('error', 'invalid_request');
    end if;
    select dataset_key into v_bound from private.community_official_account_bindings where user_id=p_user;
    if v_bound is not null and v_bound <> p_dataset_key then
        return jsonb_build_object('error', 'official_account_mismatch', 'bound_dataset_key', v_bound);
    end if;
    -- User mutex above handles same-user races. UNIQUE(dataset_key) arbitrates cross-user races.
    if v_bound is null then
        insert into private.community_official_account_bindings(user_id,dataset_key)
        values (p_user,p_dataset_key) on conflict (dataset_key) do nothing;
        if not found then return jsonb_build_object('error', 'official_account_taken'); end if;
    end if;
    select * into v_other from private.community_connections
     where user_id = p_user and dataset_key = p_dataset_key and status = 'active' for update;
    if v_other.connection_id is not null then
        if not coalesce(p_takeover, false) then
            return jsonb_build_object('error', 'writer_conflict', 'active_writer', jsonb_build_object(
                'device_label', v_other.device_label, 'platform', v_other.platform, 'source_app', v_other.source_app,
                'created_at', v_other.created_at));
        end if;
        update private.community_connections set status = 'superseded', revoked_at = now(), revoke_reason = 'takeover'
         where connection_id = v_other.connection_id;
    end if;
    insert into private.community_connections(user_id, bound_session_id, connection_secret_sha256, source_app,
        source_mode, platform, device_label, dataset_key)
    values (p_user, p_session, p_secret_sha256, p_source_app, p_source_mode, p_platform, p_device_label, p_dataset_key)
    returning * into v_new;
    return jsonb_build_object('connection_id', v_new.connection_id, 'writer_epoch', v_new.writer_epoch,
        'superseded_previous', v_other.connection_id is not null);
end;
$$;

create or replace function public.internal_account_status(p_user uuid, p_session uuid, p_connection uuid)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare
    v_binding private.community_official_account_bindings%rowtype;
    v_id jsonb := private.community_identity_state(p_user, p_session);
    v_policy private.community_policies%rowtype := private.community_current_policy(false);
    v_grant private.community_consent_grants%rowtype;
    v_last_revoked timestamptz;
    v_profile private.contributor_profiles%rowtype;
    v_conn private.community_connections%rowtype;
    v_reasons text[] := '{}';
    v_consent_state text;
    v_kakao boolean;
    v_ready boolean;
begin
    select * into v_binding from private.community_official_account_bindings where user_id=p_user;
    select * into v_profile from private.contributor_profiles where user_id = p_user;
    select * into v_grant from private.community_consent_grants where user_id = p_user and revoked_at is null;
    select max(revoked_at) into v_last_revoked from private.community_consent_grants where user_id = p_user;
    v_kakao := (v_id->>'user_ok')::boolean and (v_id->>'kakao')::boolean and (v_id->>'session')::boolean;
    if not (v_id->>'user_ok')::boolean then v_reasons := array_append(v_reasons, 'user_not_eligible'); end if;
    if not (v_id->>'kakao')::boolean then v_reasons := array_append(v_reasons, 'kakao_missing'); end if;
    if not (v_id->>'session')::boolean then v_reasons := array_append(v_reasons, 'session_missing'); end if;
    if v_grant.grant_id is null then
        v_consent_state := case when v_last_revoked is null then 'none' else 'revoked' end;
        v_reasons := array_append(v_reasons, 'consent_' || v_consent_state);
    elsif not private.community_grant_is_current(v_grant, v_policy) then
        v_consent_state := 'outdated';
        v_reasons := array_append(v_reasons, 'consent_outdated');
    else
        v_consent_state := 'active';
    end if;
    if v_profile.user_id is not null and v_profile.status <> 'active' then
        v_reasons := array_append(v_reasons, 'contributor_suspended');
    end if;
    if p_connection is not null then
        select * into v_conn from private.community_connections where connection_id = p_connection and user_id = p_user;
    end if;
    select ready into v_ready from private.analytics_state where singleton;
    return jsonb_build_object(
        'official_account', jsonb_build_object('dataset_key', v_binding.dataset_key, 'bound_at', v_binding.bound_at),
        'gate', jsonb_build_object('kakao', v_kakao, 'consent', v_consent_state = 'active',
            'can_enter', v_kakao and v_consent_state = 'active' and coalesce(v_profile.status, 'active') = 'active',
            'reasons', to_jsonb(v_reasons)),
        'policy', jsonb_build_object('required_version', v_policy.version, 'consent_text_sha256', v_policy.consent_text_sha256),
        'consent', jsonb_build_object('state', v_consent_state, 'grant_id', v_grant.grant_id,
            'policy_version', v_grant.policy_version, 'consent_text_sha256', v_grant.consent_text_sha256,
            'granted_at', v_grant.granted_at),
        'contributor', jsonb_build_object('status', case when v_profile.user_id is null then 'none' else v_profile.status end),
        'connection', case when v_conn.connection_id is null then null else jsonb_build_object(
            'status', v_conn.status, 'writer_epoch', v_conn.writer_epoch,
            'bound_to_current_session', v_conn.bound_session_id = p_session,
            'last_accepted_revision', v_conn.last_accepted_revision,
            'source_app', v_conn.source_app, 'source_mode', v_conn.source_mode, 'dataset_key', v_conn.dataset_key) end,
        'projection', jsonb_build_object('ready', coalesce(v_ready, false)));
end;
$$;

create or replace function public.internal_community_delete_contributions(p_user uuid, p_session uuid)
returns jsonb language plpgsql volatile security definer set search_path = '' as $$
declare
    v_policy private.community_policies%rowtype := private.community_current_policy(true);
    v_id jsonb := private.community_identity_state(p_user, p_session);
    v_deletion uuid := gen_random_uuid();
    v_count integer;
    v_conns integer;
    v_tombstones integer;
    v_fence_at timestamptz;
begin
    if not ((v_id->>'user_ok')::boolean and (v_id->>'kakao')::boolean and (v_id->>'session')::boolean) then
        return jsonb_build_object('error', 'kakao_required');
    end if;
    perform private.community_lock_contributor(p_user, false);
    perform 1 from private.community_consent_grants where user_id = p_user for update;
    perform 1 from private.community_connections where user_id = p_user for update;
    update private.community_connections set status = 'revoked', revoked_at = now(), revoke_reason = 'contributions_deleted'
     where user_id = p_user and status = 'active';
    get diagnostics v_conns = row_count;
    -- clock_timestamp() AFTER the locks (now() is the transaction start and can be older than a concurrent deletion);
    -- the stored fence never moves backwards (N-06).
    v_fence_at := clock_timestamp();
    insert into private.community_deletion_fences(contributor_id, deletion_id, fenced_at) values (p_user, v_deletion, v_fence_at)
    on conflict (contributor_id) do update
        set deletion_id = excluded.deletion_id,
            fenced_at = greatest(private.community_deletion_fences.fenced_at, excluded.fenced_at)
    returning fenced_at into v_fence_at;
    insert into private.community_fact_tombstones(contributor_id, source_report_key, deletion_id)
    select distinct contributor_id, source_report_key, v_deletion from private.community_report_facts
     where contributor_id = p_user
    on conflict do nothing;
    get diagnostics v_tombstones = row_count;
    delete from private.community_report_facts where contributor_id = p_user;
    get diagnostics v_count = row_count;
    with released as (
        delete from private.community_official_account_bindings where user_id=p_user returning *
    ) insert into private.community_official_account_audit(action,user_id,dataset_key,revoked_connections,
        deleted_facts,tombstoned_identities,deletion_id,fenced_at)
      select 'contributions_delete',user_id,dataset_key,v_conns,v_count,v_tombstones,v_deletion,v_fence_at from released;
    perform private.community_bump_projection();  -- also when there were no facts (fence/revocation changed state)
    return jsonb_build_object('deletion_id', v_deletion, 'deleted_facts', v_count, 'revoked_connections', v_conns,
        'deleted_at', v_fence_at, 'official_account_released', true);
end;
$$;

-- Trusted service operator supplies a ticket/operator reference and reason; never a client endpoint.
-- Expected owner rejects a replacement owner; same-user rebindings still require a fresh operator review.
create or replace function public.internal_account_release_official_account(
    p_dataset_key text, p_expected_user uuid, p_operator_ref text, p_reason text)
returns jsonb language plpgsql volatile security definer set search_path = '' as $$
declare
    v_policy private.community_policies%rowtype := private.community_current_policy(true);
    v_binding private.community_official_account_bindings%rowtype;
    v_count integer;
    v_deleted integer;
    v_tombstones integer;
    v_deletion uuid := gen_random_uuid();
    v_fence_at timestamptz;
    v_audit uuid;
begin
    if p_dataset_key is null or p_dataset_key !~ '^[0-9a-f]{64}$' or p_expected_user is null
       or nullif(btrim(p_operator_ref),'') is null or char_length(p_operator_ref)>200
       or nullif(btrim(p_reason),'') is null or char_length(p_reason)>1000 then
        return jsonb_build_object('error','invalid_request');
    end if;
    perform private.community_lock_contributor(p_expected_user, false);
    select * into v_binding from private.community_official_account_bindings
     where dataset_key=p_dataset_key and user_id=p_expected_user for update;
    if not found then return jsonb_build_object('error','not_found'); end if;
    -- Contributor mutex serializes account writes and conflicts with ingest's profile FOR SHARE.
    perform 1 from private.community_connections
     where user_id=p_expected_user and dataset_key=p_dataset_key for update;
    update private.community_connections set status='revoked', revoked_at=clock_timestamp(),
        revoke_reason='official_account_operator_release'
     where user_id=p_expected_user and dataset_key=p_dataset_key and status='active';
    get diagnostics v_count=row_count;
    v_fence_at := clock_timestamp();
    insert into private.community_dataset_deletion_fences(contributor_id,dataset_key,deletion_id,fenced_at)
    values (p_expected_user,p_dataset_key,v_deletion,v_fence_at)
    on conflict (contributor_id,dataset_key) do update
        set deletion_id=excluded.deletion_id,
            fenced_at=greatest(private.community_dataset_deletion_fences.fenced_at,excluded.fenced_at)
    returning fenced_at into v_fence_at;
    insert into private.community_dataset_fact_tombstones(contributor_id,dataset_key,source_report_key,deletion_id)
    select contributor_id,dataset_key,source_report_key,v_deletion from private.community_report_facts
     where contributor_id=p_expected_user and dataset_key=p_dataset_key
    on conflict do nothing;
    get diagnostics v_tombstones=row_count;
    delete from private.community_report_facts
     where contributor_id=p_expected_user and dataset_key=p_dataset_key;
    get diagnostics v_deleted=row_count;
    delete from private.community_official_account_bindings
     where user_id=p_expected_user and dataset_key=p_dataset_key;
    insert into private.community_official_account_audit(action,user_id,dataset_key,operator_ref,reason,
        revoked_connections,deleted_facts,tombstoned_identities,deletion_id,fenced_at)
    values ('operator_release',p_expected_user,p_dataset_key,btrim(p_operator_ref),btrim(p_reason),
        v_count,v_deleted,v_tombstones,v_deletion,v_fence_at)
    returning audit_id into v_audit;
    perform private.community_bump_projection();
    return jsonb_build_object('official_account_released',true,'revoked_connections',v_count,'audit_id',v_audit,
        'deleted_facts',v_deleted,'tombstoned_identities',v_tombstones,'deletion_id',v_deletion,'deleted_at',v_fence_at);
end;
$$;
revoke all on function public.internal_account_release_official_account(text,uuid,text,text) from public, anon, authenticated;
grant execute on function public.internal_account_release_official_account(text,uuid,text,text) to service_role;

commit;
