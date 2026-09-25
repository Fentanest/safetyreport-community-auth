-- Community account device-link relay (safeauth.worklazy.net).
-- Self-contained and additive: it creates only community_auth_* objects (and the
-- private schema if missing) and does not depend on other repositories' migrations.
--
-- The relay lets a PC/Docker safetyreport server that owns a PKCE verifier receive
-- the Supabase auth code produced by a central browser page. The table stores only
-- purpose-bound HMAC digests of capabilities, the S256 challenge, and a short-lived
-- AEAD-encrypted auth code. It never stores verifiers, device secrets, browser
-- secrets, tickets, access tokens or refresh tokens in plain text.
--
-- Every state transition happens inside one SQL function under a row lock so that
-- concurrent Edge instances cannot race. The functions are SECURITY DEFINER with an
-- empty search_path and are executable by service_role only; anon/authenticated
-- have no table or function access. Account linking here is NOT contributor consent:
-- nothing in this migration writes private.contributor_profiles.

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;
grant usage on schema private to service_role;

-- Fixed-window counters for the relay. Buckets are purpose-prefixed HMAC digests;
-- raw IP addresses are never stored.
create table private.community_auth_rate_limits (
    bucket text not null,
    window_start timestamptz not null,
    request_count integer not null default 0 check (request_count >= 0),
    primary key (bucket, window_start)
);
create index community_auth_rate_limits_window_idx on private.community_auth_rate_limits(window_start);
alter table private.community_auth_rate_limits enable row level security;
revoke all on table private.community_auth_rate_limits from public, anon, authenticated;
grant select, insert, update, delete on table private.community_auth_rate_limits to service_role;

create table private.community_auth_requests (
    id uuid primary key,
    protocol_version smallint not null check (protocol_version = 1),
    client_kind text not null check (client_kind in ('pc', 'docker', 'mobile_client_server')),
    device_label text not null check (char_length(device_label) between 1 and 40),
    display_code text not null check (display_code ~ '^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$'),
    code_challenge text not null check (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    challenge_method text not null default 's256' check (challenge_method = 's256'),
    create_idem_hash text not null unique check (create_idem_hash ~ '^[0-9a-f]{64}$'),
    device_secret_hash text not null check (device_secret_hash ~ '^[0-9a-f]{64}$'),
    install_hash text check (install_hash is null or install_hash ~ '^[0-9a-f]{64}$'),
    bootstrap_ticket_hash text not null check (bootstrap_ticket_hash ~ '^[0-9a-f]{64}$'),
    browser_secret_hash text check (browser_secret_hash is null or browser_secret_hash ~ '^[0-9a-f]{64}$'),
    status text not null default 'created' check (status in (
        'created', 'claimed', 'oauth_started', 'code_ready', 'code_delivered',
        'device_confirmed', 'cancelled', 'expired', 'failed')),
    prepare_count smallint not null default 0 check (prepare_count between 0 and 3),
    encrypted_auth_code text check (encrypted_auth_code is null or char_length(encrypted_auth_code) <= 2048),
    code_digest text check (code_digest is null or code_digest ~ '^[0-9a-f]{64}$'),
    delivery_key_hash text check (delivery_key_hash is null or delivery_key_hash ~ '^[0-9a-f]{64}$'),
    user_id uuid references auth.users(id) on delete set null,
    session_id uuid,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    code_expires_at timestamptz,
    claimed_at timestamptz,
    oauth_started_at timestamptz,
    published_at timestamptz,
    delivered_at timestamptz,
    completed_at timestamptz,
    cancelled_at timestamptz,
    cancelled_by text check (cancelled_by is null or cancelled_by in ('device', 'browser', 'oauth')),
    failed_at timestamptz,
    failed_reason_code text check (failed_reason_code is null or failed_reason_code in (
        'oauth_error', 'code_expired', 'server_error')),
    check (expires_at > created_at and expires_at <= created_at + interval '30 minutes'),
    check (code_expires_at is null or code_expires_at <= expires_at),
    check (encrypted_auth_code is null or status in ('code_ready', 'code_delivered')),
    check (status <> 'device_confirmed' or (user_id is not null and session_id is not null))
);

comment on table private.community_auth_requests is
    'Short-lived device-link relay state for safeauth.worklazy.net. Not contributor consent.';

create index community_auth_requests_expires_idx on private.community_auth_requests(expires_at);
create index community_auth_requests_install_active_idx
    on private.community_auth_requests(install_hash)
    where status in ('created', 'claimed', 'oauth_started', 'code_ready', 'code_delivered');

alter table private.community_auth_requests enable row level security;
-- No policies: roles that do not bypass RLS see nothing even if a grant is added later.
revoke all on table private.community_auth_requests from public, anon, authenticated;
grant select, insert, update, delete on table private.community_auth_requests to service_role;

-- Marks a non-terminal row expired and wipes the code. Caller holds the row lock.
create or replace function private.safeauth_expire_if_needed(p_row private.community_auth_requests)
returns text
language plpgsql
security definer
set search_path = ''
as $$
begin
    if p_row.status in ('device_confirmed', 'cancelled', 'expired', 'failed') then
        return p_row.status;
    end if;
    if p_row.expires_at <= now() then
        update private.community_auth_requests
           set status = 'expired', encrypted_auth_code = null
         where id = p_row.id;
        return 'expired';
    end if;
    return p_row.status;
end;
$$;
revoke all on function private.safeauth_expire_if_needed(private.community_auth_requests) from public, anon, authenticated;

create or replace function public.internal_safeauth_create(
    p_id uuid,
    p_protocol integer,
    p_client_kind text,
    p_device_label text,
    p_display_code text,
    p_code_challenge text,
    p_create_idem_hash text,
    p_device_secret_hash text,
    p_install_hash text,
    p_ticket_hash text,
    p_ttl_seconds integer,
    p_max_active_per_install integer,
    p_max_active_total integer
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
    v_existing uuid;
    v_count integer;
    v_row private.community_auth_requests;
begin
    if p_ttl_seconds is null or p_ttl_seconds < 60 or p_ttl_seconds > 1800 then
        raise exception 'SAFEAUTH_INVALID_TTL';
    end if;

    select id into v_existing
      from private.community_auth_requests
     where create_idem_hash = p_create_idem_hash;
    if found then
        return jsonb_build_object('existing', true, 'request_id', v_existing);
    end if;

    select count(*) into v_count
      from private.community_auth_requests
     where status in ('created', 'claimed', 'oauth_started', 'code_ready', 'code_delivered')
       and expires_at > now();
    if v_count >= p_max_active_total then
        return jsonb_build_object('error', 'capacity');
    end if;

    if p_install_hash is not null then
        select count(*) into v_count
          from private.community_auth_requests
         where install_hash = p_install_hash
           and status in ('created', 'claimed', 'oauth_started', 'code_ready', 'code_delivered')
           and expires_at > now();
        if v_count >= p_max_active_per_install then
            return jsonb_build_object('error', 'too_many_pending');
        end if;
    end if;

    insert into private.community_auth_requests (
        id, protocol_version, client_kind, device_label, display_code, code_challenge,
        create_idem_hash, device_secret_hash, install_hash, bootstrap_ticket_hash, expires_at)
    values (
        p_id, p_protocol, p_client_kind, p_device_label, p_display_code, p_code_challenge,
        p_create_idem_hash, p_device_secret_hash, p_install_hash, p_ticket_hash,
        now() + make_interval(secs => p_ttl_seconds))
    on conflict (create_idem_hash) do nothing
    returning * into v_row;

    if v_row.id is null then
        select id into v_existing
          from private.community_auth_requests
         where create_idem_hash = p_create_idem_hash;
        return jsonb_build_object('existing', true, 'request_id', v_existing);
    end if;

    return jsonb_build_object(
        'existing', false,
        'request_id', v_row.id,
        'display_code', v_row.display_code,
        'expires_at', v_row.expires_at);
end;
$$;

-- Idempotent create retry: the lost response's ticket was never seen, so a fresh
-- ticket replaces it while the request is still unclaimed.
create or replace function public.internal_safeauth_rotate_ticket(
    p_id uuid,
    p_device_secret_hash text,
    p_ticket_hash text
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
    v_row private.community_auth_requests;
    v_status text;
begin
    select * into v_row from private.community_auth_requests where id = p_id for update;
    if not found or v_row.device_secret_hash <> p_device_secret_hash then
        return jsonb_build_object('error', 'not_found');
    end if;
    v_status := private.safeauth_expire_if_needed(v_row);
    if v_status <> 'created' then
        return jsonb_build_object('error', 'request_not_reusable', 'status', v_status);
    end if;
    update private.community_auth_requests
       set bootstrap_ticket_hash = p_ticket_hash
     where id = p_id;
    return jsonb_build_object(
        'request_id', v_row.id,
        'display_code', v_row.display_code,
        'expires_at', v_row.expires_at);
end;
$$;

create or replace function public.internal_safeauth_claim(
    p_id uuid,
    p_ticket_hash text,
    p_browser_secret_hash text
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
    v_row private.community_auth_requests;
    v_status text;
begin
    select * into v_row from private.community_auth_requests where id = p_id for update;
    if not found or v_row.bootstrap_ticket_hash <> p_ticket_hash then
        return jsonb_build_object('error', 'not_found');
    end if;
    v_status := private.safeauth_expire_if_needed(v_row);
    if v_status in ('expired', 'cancelled', 'failed') then
        return jsonb_build_object('error', v_status);
    end if;

    if v_status = 'created' then
        update private.community_auth_requests
           set status = 'claimed', browser_secret_hash = p_browser_secret_hash, claimed_at = now()
         where id = p_id;
        v_status := 'claimed';
    elsif v_row.browser_secret_hash is distinct from p_browser_secret_hash then
        return jsonb_build_object('error', 'already_claimed');
    end if;

    return jsonb_build_object(
        'phase', v_status,
        'client_kind', v_row.client_kind,
        'device_label', v_row.device_label,
        'display_code', v_row.display_code,
        'expires_at', v_row.expires_at);
end;
$$;

create or replace function public.internal_safeauth_prepare(
    p_id uuid,
    p_browser_secret_hash text
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
    v_row private.community_auth_requests;
    v_status text;
begin
    select * into v_row from private.community_auth_requests where id = p_id for update;
    if not found or v_row.browser_secret_hash is distinct from p_browser_secret_hash then
        return jsonb_build_object('error', 'not_found');
    end if;
    v_status := private.safeauth_expire_if_needed(v_row);
    if v_status in ('expired', 'cancelled', 'failed') then
        return jsonb_build_object('error', v_status);
    end if;
    if v_status not in ('claimed', 'oauth_started') then
        return jsonb_build_object('error', 'invalid_state', 'phase', v_status);
    end if;
    if v_row.prepare_count >= 3 then
        return jsonb_build_object('error', 'prepare_limit');
    end if;
    update private.community_auth_requests
       set status = 'oauth_started',
           prepare_count = prepare_count + 1,
           oauth_started_at = coalesce(oauth_started_at, now())
     where id = p_id;
    return jsonb_build_object(
        'phase', 'oauth_started',
        'code_challenge', v_row.code_challenge,
        'expires_at', v_row.expires_at);
end;
$$;

create or replace function public.internal_safeauth_publish(
    p_id uuid,
    p_browser_secret_hash text,
    p_kind text,
    p_code_digest text,
    p_encrypted_code text,
    p_code_ttl_seconds integer,
    p_error_reason text
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
    v_row private.community_auth_requests;
    v_status text;
begin
    if p_kind not in ('code', 'denied', 'error') then
        raise exception 'SAFEAUTH_INVALID_KIND';
    end if;
    select * into v_row from private.community_auth_requests where id = p_id for update;
    if not found or v_row.browser_secret_hash is distinct from p_browser_secret_hash then
        return jsonb_build_object('error', 'not_found');
    end if;
    v_status := private.safeauth_expire_if_needed(v_row);

    -- A repeated publish of the same code is idempotent in every later phase.
    if p_kind = 'code' and v_row.code_digest is not null then
        if v_row.code_digest = p_code_digest then
            return jsonb_build_object('phase', v_status);
        end if;
        return jsonb_build_object('error', 'code_conflict');
    end if;

    if v_status in ('expired', 'cancelled', 'failed') then
        return jsonb_build_object('error', v_status);
    end if;
    if v_status <> 'oauth_started' then
        return jsonb_build_object('error', 'invalid_state', 'phase', v_status);
    end if;

    if p_kind = 'code' then
        if p_code_ttl_seconds is null or p_code_ttl_seconds < 10 or p_code_ttl_seconds > 300 then
            raise exception 'SAFEAUTH_INVALID_TTL';
        end if;
        update private.community_auth_requests
           set status = 'code_ready',
               encrypted_auth_code = p_encrypted_code,
               code_digest = p_code_digest,
               code_expires_at = least(now() + make_interval(secs => p_code_ttl_seconds), v_row.expires_at),
               published_at = now()
         where id = p_id;
        return jsonb_build_object('phase', 'code_ready');
    elsif p_kind = 'denied' then
        update private.community_auth_requests
           set status = 'cancelled', cancelled_at = now(), cancelled_by = 'oauth'
         where id = p_id;
        return jsonb_build_object('phase', 'cancelled');
    else
        update private.community_auth_requests
           set status = 'failed', failed_at = now(), failed_reason_code = 'oauth_error'
         where id = p_id;
        return jsonb_build_object('phase', 'failed');
    end if;
end;
$$;

-- Exactly one delivery recipient (the pinned delivery key) may read the code.
-- The same recipient may re-read it until code_expires_at so that a lost poll
-- response is recoverable without a second Auth exchange.
create or replace function public.internal_safeauth_poll(
    p_id uuid,
    p_device_secret_hash text,
    p_delivery_key_hash text
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
    v_row private.community_auth_requests;
    v_status text;
begin
    select * into v_row from private.community_auth_requests where id = p_id for update;
    if not found or v_row.device_secret_hash <> p_device_secret_hash then
        return jsonb_build_object('error', 'not_found');
    end if;
    v_status := private.safeauth_expire_if_needed(v_row);

    if v_status in ('created', 'claimed', 'oauth_started') then
        return jsonb_build_object('status', 'pending', 'phase', v_status, 'expires_at', v_row.expires_at);
    elsif v_status = 'device_confirmed' then
        return jsonb_build_object('status', 'completed');
    elsif v_status in ('expired', 'cancelled', 'failed') then
        return jsonb_build_object('status', v_status, 'reason',
            coalesce(v_row.failed_reason_code, v_row.cancelled_by));
    end if;

    if v_row.delivery_key_hash is not null and v_row.delivery_key_hash <> p_delivery_key_hash then
        return jsonb_build_object('error', 'delivery_conflict');
    end if;
    if v_row.code_expires_at <= now() then
        update private.community_auth_requests
           set encrypted_auth_code = null,
               status = case when status = 'code_ready' then 'failed' else status end,
               failed_at = case when status = 'code_ready' then now() else failed_at end,
               failed_reason_code = case when status = 'code_ready' then 'code_expired' else failed_reason_code end
         where id = p_id;
        return jsonb_build_object('status', 'code_expired');
    end if;
    if v_row.encrypted_auth_code is null then
        return jsonb_build_object('status', 'code_expired');
    end if;

    if v_status = 'code_ready' then
        update private.community_auth_requests
           set status = 'code_delivered', delivery_key_hash = p_delivery_key_hash, delivered_at = now()
         where id = p_id;
    end if;
    return jsonb_build_object(
        'status', 'code',
        'encrypted_auth_code', v_row.encrypted_auth_code,
        'code_expires_at', v_row.code_expires_at);
end;
$$;

create or replace function public.internal_safeauth_browser_status(
    p_id uuid,
    p_browser_secret_hash text
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
    v_row private.community_auth_requests;
    v_status text;
begin
    select * into v_row from private.community_auth_requests where id = p_id for update;
    if not found or v_row.browser_secret_hash is distinct from p_browser_secret_hash then
        return jsonb_build_object('error', 'not_found');
    end if;
    v_status := private.safeauth_expire_if_needed(v_row);
    return jsonb_build_object('phase', v_status, 'expires_at', v_row.expires_at);
end;
$$;

-- p_user_id/p_session_id/p_token_issued_at come from a JWT that the Edge function
-- has already validated with Supabase Auth; they are never taken from the request body.
create or replace function public.internal_safeauth_complete(
    p_id uuid,
    p_device_secret_hash text,
    p_user_id uuid,
    p_session_id uuid,
    p_token_issued_at timestamptz
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
    v_row private.community_auth_requests;
    v_status text;
begin
    select * into v_row from private.community_auth_requests where id = p_id for update;
    if not found or v_row.device_secret_hash <> p_device_secret_hash then
        return jsonb_build_object('error', 'not_found');
    end if;
    v_status := private.safeauth_expire_if_needed(v_row);
    if v_status = 'device_confirmed' then
        if v_row.user_id = p_user_id and v_row.session_id = p_session_id then
            return jsonb_build_object('phase', 'device_confirmed');
        end if;
        return jsonb_build_object('error', 'invalid_state', 'phase', v_status);
    end if;
    if v_status in ('expired', 'cancelled', 'failed') then
        return jsonb_build_object('error', v_status);
    end if;
    if v_status <> 'code_delivered' then
        return jsonb_build_object('error', 'invalid_state', 'phase', v_status);
    end if;
    if p_token_issued_at < v_row.created_at - interval '60 seconds' then
        return jsonb_build_object('error', 'session_mismatch');
    end if;
    update private.community_auth_requests
       set status = 'device_confirmed',
           user_id = p_user_id,
           session_id = p_session_id,
           completed_at = now(),
           encrypted_auth_code = null
     where id = p_id;
    return jsonb_build_object('phase', 'device_confirmed');
end;
$$;

create or replace function public.internal_safeauth_cancel(
    p_id uuid,
    p_actor text,
    p_secret_hash text
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
    v_row private.community_auth_requests;
    v_status text;
    v_expected text;
begin
    if p_actor not in ('device', 'browser') then
        raise exception 'SAFEAUTH_INVALID_ACTOR';
    end if;
    select * into v_row from private.community_auth_requests where id = p_id for update;
    if not found then
        return jsonb_build_object('error', 'not_found');
    end if;
    v_expected := case when p_actor = 'device' then v_row.device_secret_hash else v_row.browser_secret_hash end;
    if v_expected is null or v_expected <> p_secret_hash then
        return jsonb_build_object('error', 'not_found');
    end if;
    v_status := private.safeauth_expire_if_needed(v_row);
    if v_status = 'device_confirmed' then
        return jsonb_build_object('error', 'already_completed');
    end if;
    if v_status in ('cancelled', 'expired', 'failed') then
        return jsonb_build_object('phase', v_status);
    end if;
    update private.community_auth_requests
       set status = 'cancelled', cancelled_at = now(), cancelled_by = p_actor, encrypted_auth_code = null
     where id = p_id;
    return jsonb_build_object('phase', 'cancelled');
end;
$$;

-- Fixed-window counter on private.community_auth_rate_limits.
create or replace function public.internal_safeauth_rate_limit(
    p_bucket text,
    p_limit integer,
    p_window_seconds integer
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
    v_window timestamptz;
    v_count integer;
begin
    if p_bucket is null or p_bucket !~ '^sa:[a-z_]{2,16}:[0-9a-f]{64}$' then
        raise exception 'SAFEAUTH_INVALID_BUCKET';
    end if;
    if p_window_seconds is null or p_window_seconds < 1 or p_window_seconds > 3600 or p_limit < 1 then
        raise exception 'SAFEAUTH_INVALID_WINDOW';
    end if;
    v_window := to_timestamp(floor(extract(epoch from now()) / p_window_seconds) * p_window_seconds);
    insert into private.community_auth_rate_limits(bucket, window_start, request_count)
    values (p_bucket, v_window, 1)
    on conflict (bucket, window_start) do update
        set request_count = private.community_auth_rate_limits.request_count + 1
    returning request_count into v_count;
    return jsonb_build_object(
        'allowed', v_count <= p_limit,
        'retry_after', greatest(1, ceil(extract(epoch from (v_window + make_interval(secs => p_window_seconds) - now())))::integer));
end;
$$;

-- Retention: rows are useless after expiry; keep one day for abuse diagnostics.
create or replace function public.internal_safeauth_cleanup()
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
    v_wiped integer;
    v_deleted integer;
begin
    update private.community_auth_requests
       set encrypted_auth_code = null
     where encrypted_auth_code is not null
       and (code_expires_at <= now() or expires_at <= now());
    get diagnostics v_wiped = row_count;

    update private.community_auth_requests
       set status = 'expired'
     where status in ('created', 'claimed', 'oauth_started', 'code_ready', 'code_delivered')
       and expires_at <= now();

    delete from private.community_auth_requests
     where expires_at < now() - interval '1 day';
    get diagnostics v_deleted = row_count;

    delete from private.community_auth_rate_limits
     where window_start < now() - interval '1 day';

    return jsonb_build_object('wiped_codes', v_wiped, 'deleted_requests', v_deleted);
end;
$$;

do $$
declare
    fn text;
begin
    foreach fn in array array[
        'public.internal_safeauth_create(uuid,integer,text,text,text,text,text,text,text,text,integer,integer,integer)',
        'public.internal_safeauth_rotate_ticket(uuid,text,text)',
        'public.internal_safeauth_claim(uuid,text,text)',
        'public.internal_safeauth_prepare(uuid,text)',
        'public.internal_safeauth_publish(uuid,text,text,text,text,integer,text)',
        'public.internal_safeauth_poll(uuid,text,text)',
        'public.internal_safeauth_browser_status(uuid,text)',
        'public.internal_safeauth_complete(uuid,text,uuid,uuid,timestamptz)',
        'public.internal_safeauth_cancel(uuid,text,text)',
        'public.internal_safeauth_rate_limit(text,integer,integer)',
        'public.internal_safeauth_cleanup()'
    ] loop
        execute format('revoke all on function %s from public, anon, authenticated', fn);
        execute format('grant execute on function %s to service_role', fn);
    end loop;
end;
$$;

-- Optional hourly schedule once pg_cron is confirmed on the project (not assumed):
-- select cron.schedule('safeauth-cleanup', '23 * * * *', 'select public.internal_safeauth_cleanup()');
