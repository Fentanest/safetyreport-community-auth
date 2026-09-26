-- Community account registry: required share-consent policy, consent grants, writer connections.
-- Owner: safetyreport-community-auth. service_role only; called by the `community-account` Edge Function
-- after it verified the user JWT (getUser + claims). Composed with the map repository's migrations through
-- safetyreport-community-map/docs/integration/community-ingest/migration-manifest.json.
-- Depends on map 202608150001_initial_schema.sql (private schema, private.contributor_profiles) and
-- map 202609240001_analytics_v2.sql (private.analytics_state, private.invalidate_analytics_v2).
--
-- Lock order shared by every RPC here and by the map ingest RPC (deadlock avoidance):
--   policy_current -> contributor_profiles -> consent_grants -> connections -> (map) tombstones/facts -> analytics_state
-- Account mutations take the contributor row FOR UPDATE (one mutex per user); ingest takes it FOR SHARE, so a
-- revoke that commits first is always seen by ingest and a later revoke waits for the ingest commit.

begin;

-- Policy history is append-only: a published (version, text hash) pair never changes (N-03).
create table private.community_policies (
    version text primary key check (version ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}\.[0-9]{1,3}$'),
    consent_text_sha256 text not null check (consent_text_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz not null default now()
);
create table private.community_policy_current (
    singleton boolean primary key default true check (singleton),
    version text not null references private.community_policies(version),
    effective_at timestamptz not null default now()
);

create or replace function private.community_policies_immutable()
returns trigger language plpgsql set search_path = '' as $$
begin
    raise exception 'COMMUNITY_POLICY_IMMUTABLE: publish a new version instead';
end;
$$;
create trigger community_policies_no_update before update or delete on private.community_policies
for each row execute function private.community_policies_immutable();

insert into private.community_policies(version, consent_text_sha256)
values ('2026-09-26.1', '818703977dbf1596a82df8ff68408d0907280adbda7ce2140879a2ab5fd6a6fa');
insert into private.community_policy_current(version) values ('2026-09-26.1');

-- lineage_id: a grant that only replaces an outdated-policy grant of the same user continues its lineage, so
-- facts shared under the older terms stay public until the USER revokes. A consent given after a user revocation
-- starts a new lineage (never revives facts of a revoked lineage — S-02).
create table private.community_consent_grants (
    grant_id uuid primary key default gen_random_uuid(),
    lineage_id uuid not null,
    superseded_by uuid,
    user_id uuid not null references auth.users(id) on delete cascade,
    policy_version text not null references private.community_policies(version),
    consent_text_sha256 text not null check (consent_text_sha256 ~ '^[0-9a-f]{64}$'),
    granted_via text not null check (granted_via in ('safetyreport_server', 'mobile_standalone', 'mobile_client')),
    granted_session_id uuid not null,
    granted_at timestamptz not null default now(),
    revoked_at timestamptz,
    revoked_session_id uuid,
    revoke_reason text check (revoke_reason is null or revoke_reason in ('user', 'superseded_policy', 'operator', 'account_deleted'))
);
create unique index community_consent_grants_one_active
    on private.community_consent_grants(user_id) where revoked_at is null;
create index community_consent_grants_lineage on private.community_consent_grants(lineage_id) where revoked_at is null;

create sequence private.community_writer_epoch_seq as bigint;

create table private.community_connections (
    connection_id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    bound_session_id uuid not null,
    connection_secret_sha256 text not null check (connection_secret_sha256 ~ '^[0-9a-f]{64}$'),
    source_app text not null check (source_app in ('safetyreport', 'safetyreport-mobile')),
    source_mode text not null check (source_mode in ('server', 'standalone')),
    platform text not null check (platform in ('windows', 'linux', 'macos', 'docker', 'android', 'ios', 'other')),
    device_label text not null check (char_length(device_label) between 1 and 40),
    dataset_key text not null check (dataset_key ~ '^[0-9a-f]{64}$'),
    writer_epoch bigint not null default nextval('private.community_writer_epoch_seq'),
    status text not null default 'active' check (status in ('active', 'superseded', 'revoked', 'suspended')),
    last_accepted_revision bigint not null default 0 check (last_accepted_revision >= 0),
    created_at timestamptz not null default now(),
    rebound_at timestamptz,
    revoked_at timestamptz,
    revoke_reason text,
    check ((source_app = 'safetyreport' and source_mode = 'server') or
           (source_app = 'safetyreport-mobile' and source_mode = 'standalone'))
);
create unique index community_connections_one_active_writer
    on private.community_connections(user_id, dataset_key) where status = 'active';
create unique index community_connections_epoch on private.community_connections(writer_epoch);
create index community_connections_user on private.community_connections(user_id);

alter table private.community_policies enable row level security;
alter table private.community_policy_current enable row level security;
alter table private.community_consent_grants enable row level security;
alter table private.community_connections enable row level security;
revoke all on private.community_policies, private.community_policy_current,
    private.community_consent_grants, private.community_connections from public, anon, authenticated;
grant select on private.community_policies, private.community_policy_current to service_role;
grant select, insert, update on private.community_consent_grants, private.community_connections to service_role;
revoke all on sequence private.community_writer_epoch_seq from public, anon, authenticated;
grant usage, select on sequence private.community_writer_epoch_seq to service_role;
revoke all on function private.community_policies_immutable() from public, anon, authenticated;

-- K: a real, non-anonymous, not banned/deleted user with a Kakao identity whose JWT session still exists.
-- Only auth.* rows GoTrue owns are consulted; user-editable metadata is never trusted.
create or replace function private.community_identity_state(p_user uuid, p_session uuid)
returns jsonb language sql stable security definer set search_path = '' as $$
    select jsonb_build_object(
        'user_ok', coalesce((select u.deleted_at is null and not coalesce(u.is_anonymous, false)
                                    and (u.banned_until is null or u.banned_until <= now())
                               from auth.users u where u.id = p_user), false),
        'kakao', exists(select 1 from auth.identities i where i.user_id = p_user and i.provider = 'kakao'),
        'session', exists(select 1 from auth.sessions s where s.id = p_session and s.user_id = p_user
                            and (s.not_after is null or s.not_after > now()))
    );
$$;
revoke all on function private.community_identity_state(uuid, uuid) from public, anon, authenticated;

create or replace function private.community_current_policy(p_lock boolean)
returns private.community_policies language plpgsql volatile security definer set search_path = '' as $$
declare v private.community_policies%rowtype;
begin
    if p_lock then
        perform 1 from private.community_policy_current where singleton for share;
    end if;
    select p.* into v from private.community_policies p
      join private.community_policy_current c on c.version = p.version where c.singleton;
    return v;
end;
$$;
revoke all on function private.community_current_policy(boolean) from public, anon, authenticated;

-- Per-user mutex (FOR UPDATE). Creates a placeholder profile (not consented) when asked.
create or replace function private.community_lock_contributor(p_user uuid, p_create boolean)
returns private.contributor_profiles language plpgsql volatile security definer set search_path = '' as $$
declare v private.contributor_profiles%rowtype;
begin
    if p_create then
        insert into private.contributor_profiles(user_id, consent_version, privacy_policy_version, consented_at, revoked_at, status)
        values (p_user, 'none', 'none', now(), now(), 'active')
        on conflict (user_id) do nothing;
    end if;
    select * into v from private.contributor_profiles where user_id = p_user for update;
    return v;
end;
$$;
revoke all on function private.community_lock_contributor(uuid, boolean) from public, anon, authenticated;

-- Visibility of already accepted facts: the fact's grant lineage still has an active (not user-revoked) grant.
create or replace function private.community_lineage_active(p_grant uuid)
returns boolean language sql stable security definer set search_path = '' as $$
    select exists (select 1 from private.community_consent_grants g
                     join private.community_consent_grants a on a.lineage_id = g.lineage_id and a.user_id = g.user_id
                    where g.grant_id = p_grant and a.revoked_at is null);
$$;
revoke all on function private.community_lineage_active(uuid) from public, anon, authenticated;

-- A grant counts for NEW uploads and the entry gate only when its (version, text hash) pair equals the current policy.
create or replace function private.community_grant_is_current(p_grant private.community_consent_grants, p_policy private.community_policies)
returns boolean language sql immutable set search_path = '' as $$
    select p_grant.grant_id is not null and p_grant.revoked_at is null
       and p_grant.policy_version = p_policy.version and p_grant.consent_text_sha256 = p_policy.consent_text_sha256;
$$;
revoke all on function private.community_grant_is_current(private.community_consent_grants, private.community_policies) from public, anon, authenticated;

create or replace function private.community_bump_projection()
returns void language sql volatile security definer set search_path = '' as $$
    update private.analytics_state
       set dataset_version = gen_random_uuid()::text, source_updated_at = now(), generated_at = now()
     where singleton = true;
$$;
revoke all on function private.community_bump_projection() from public, anon, authenticated;

create or replace function public.internal_account_status(p_user uuid, p_session uuid, p_connection uuid)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare
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

create or replace function public.internal_account_grant_consent(
    p_user uuid, p_session uuid, p_policy_version text, p_text_sha256 text, p_via text)
returns jsonb language plpgsql volatile security definer set search_path = '' as $$
declare
    v_policy private.community_policies%rowtype := private.community_current_policy(true);
    v_id jsonb := private.community_identity_state(p_user, p_session);
    v_profile private.contributor_profiles%rowtype;
    v_grant private.community_consent_grants%rowtype;
    v_new_id uuid;
    v_lineage uuid;
begin
    if not ((v_id->>'user_ok')::boolean and (v_id->>'kakao')::boolean and (v_id->>'session')::boolean) then
        return jsonb_build_object('error', 'kakao_required');
    end if;
    if p_policy_version is distinct from v_policy.version or p_text_sha256 is distinct from v_policy.consent_text_sha256 then
        return jsonb_build_object('error', 'policy_mismatch', 'required_version', v_policy.version);
    end if;
    if p_via is null or p_via not in ('safetyreport_server', 'mobile_standalone', 'mobile_client') then
        return jsonb_build_object('error', 'invalid_request');
    end if;
    v_profile := private.community_lock_contributor(p_user, true);
    if v_profile.status <> 'active' then return jsonb_build_object('error', 'contributor_suspended'); end if;
    select * into v_grant from private.community_consent_grants where user_id = p_user and revoked_at is null for update;
    if private.community_grant_is_current(v_grant, v_policy) then
        return jsonb_build_object('grant_id', v_grant.grant_id, 'policy_version', v_grant.policy_version,
            'granted_at', v_grant.granted_at, 'created', false);
    end if;
    v_new_id := gen_random_uuid();
    if v_grant.grant_id is not null then
        -- outdated-policy grant: close it and continue its lineage (not a user revocation)
        update private.community_consent_grants set revoked_at = now(), revoked_session_id = p_session,
            revoke_reason = 'superseded_policy', superseded_by = v_new_id where grant_id = v_grant.grant_id;
        v_lineage := v_grant.lineage_id;
    else
        v_lineage := v_new_id;
    end if;
    insert into private.community_consent_grants(grant_id, lineage_id, user_id, policy_version, consent_text_sha256,
        granted_via, granted_session_id)
    values (v_new_id, v_lineage, p_user, v_policy.version, v_policy.consent_text_sha256, p_via, p_session)
    returning * into v_grant;
    update private.contributor_profiles set consent_version = v_policy.version,
        privacy_policy_version = v_policy.version, consented_at = v_grant.granted_at,
        revoked_at = null, updated_at = now() where user_id = p_user;
    return jsonb_build_object('grant_id', v_grant.grant_id, 'policy_version', v_grant.policy_version,
        'granted_at', v_grant.granted_at, 'created', true);
end;
$$;

-- Revocation resolves to the ACTIVE grant of the lineage the given grant belongs to (N-04): a stale id of a grant
-- that a policy re-consent superseded still revokes the lineage the user actually sees. Idempotent when nothing is active.
create or replace function public.internal_account_revoke_consent(p_user uuid, p_session uuid, p_grant uuid)
returns jsonb language plpgsql volatile security definer set search_path = '' as $$
declare
    v_policy private.community_policies%rowtype := private.community_current_policy(true);
    v_given private.community_consent_grants%rowtype;
    v_active private.community_consent_grants%rowtype;
begin
    perform private.community_lock_contributor(p_user, false);
    select * into v_given from private.community_consent_grants where grant_id = p_grant and user_id = p_user;
    if v_given.grant_id is null then return jsonb_build_object('error', 'not_found'); end if;
    select * into v_active from private.community_consent_grants
     where user_id = p_user and lineage_id = v_given.lineage_id and revoked_at is null for update;
    if v_active.grant_id is null then
        -- The given lineage is already closed. If the user now has ANOTHER active lineage, this request refers to an
        -- outdated consent: refuse instead of reporting a success the user would misread (N-04-L).
        if exists (select 1 from private.community_consent_grants where user_id = p_user and revoked_at is null) then
            return jsonb_build_object('error', 'stale_grant');
        end if;
        return jsonb_build_object('grant_id', p_grant, 'revoked', true, 'already_revoked', true, 'lineage_active', false);
    end if;
    update private.community_consent_grants set revoked_at = now(), revoked_session_id = p_session, revoke_reason = 'user'
     where grant_id = v_active.grant_id;
    update private.contributor_profiles set revoked_at = now(), updated_at = now() where user_id = p_user;
    return jsonb_build_object('grant_id', v_active.grant_id, 'revoked', true, 'already_revoked', false,
        'lineage_active', private.community_lineage_active(v_active.grant_id));
end;
$$;

create or replace function public.internal_account_register_connection(
    p_user uuid, p_session uuid, p_source_app text, p_source_mode text, p_platform text,
    p_device_label text, p_dataset_key text, p_secret_sha256 text, p_takeover boolean)
returns jsonb language plpgsql volatile security definer set search_path = '' as $$
declare
    v_policy private.community_policies%rowtype := private.community_current_policy(true);
    v_id jsonb := private.community_identity_state(p_user, p_session);
    v_other private.community_connections%rowtype;
    v_new private.community_connections%rowtype;
begin
    if not ((v_id->>'user_ok')::boolean and (v_id->>'kakao')::boolean and (v_id->>'session')::boolean) then
        return jsonb_build_object('error', 'kakao_required');
    end if;
    perform private.community_lock_contributor(p_user, true);
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

create or replace function public.internal_account_rebind_connection(
    p_user uuid, p_session uuid, p_connection uuid, p_secret_sha256 text)
returns jsonb language plpgsql volatile security definer set search_path = '' as $$
declare
    v_policy private.community_policies%rowtype := private.community_current_policy(true);
    v_id jsonb := private.community_identity_state(p_user, p_session);
    v_conn private.community_connections%rowtype;
begin
    if not ((v_id->>'user_ok')::boolean and (v_id->>'kakao')::boolean and (v_id->>'session')::boolean) then
        return jsonb_build_object('error', 'kakao_required');
    end if;
    perform private.community_lock_contributor(p_user, false);
    select * into v_conn from private.community_connections where connection_id = p_connection for update;
    -- Same answer for "no such connection", "someone else's connection" and "wrong secret" (no oracle).
    if v_conn.connection_id is null or v_conn.user_id <> p_user or v_conn.connection_secret_sha256 <> p_secret_sha256 then
        return jsonb_build_object('error', 'not_found');
    end if;
    if v_conn.status <> 'active' then return jsonb_build_object('error', 'connection_' || v_conn.status); end if;
    update private.community_connections set bound_session_id = p_session, rebound_at = now()
     where connection_id = p_connection;
    return jsonb_build_object('connection_id', p_connection, 'writer_epoch', v_conn.writer_epoch,
        'last_accepted_revision', v_conn.last_accepted_revision);
end;
$$;

create or replace function public.internal_account_revoke_connection(p_user uuid, p_connection uuid)
returns jsonb language plpgsql volatile security definer set search_path = '' as $$
declare
    v_policy private.community_policies%rowtype := private.community_current_policy(true);
    v_conn private.community_connections%rowtype;
begin
    perform private.community_lock_contributor(p_user, false);
    select * into v_conn from private.community_connections where connection_id = p_connection for update;
    if v_conn.connection_id is null or v_conn.user_id <> p_user then return jsonb_build_object('error', 'not_found'); end if;
    if v_conn.status = 'active' then
        update private.community_connections set status = 'revoked', revoked_at = now(), revoke_reason = 'user'
         where connection_id = p_connection;
    end if;
    return jsonb_build_object('connection_id', p_connection, 'status', 'revoked');
end;
$$;

-- Rate limit for the account function reuses the relay's fixed-window counter (bucket prefix sa:account:).

do $$
declare f text;
begin
    foreach f in array array[
        'public.internal_account_status(uuid, uuid, uuid)',
        'public.internal_account_grant_consent(uuid, uuid, text, text, text)',
        'public.internal_account_revoke_consent(uuid, uuid, uuid)',
        'public.internal_account_register_connection(uuid, uuid, text, text, text, text, text, text, boolean)',
        'public.internal_account_rebind_connection(uuid, uuid, uuid, text)',
        'public.internal_account_revoke_connection(uuid, uuid)'] loop
        execute format('revoke all on function %s from public, anon, authenticated', f);
        execute format('grant execute on function %s to service_role', f);
    end loop;
end $$;

commit;
