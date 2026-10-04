-- Relay hardening found in the 2026-10-04 review (safetyreport tech log D1-01, D1-02, D1-05).
-- Applied migrations are never edited; this file replaces the affected definitions.

-- D1-01: a completed request keeps user_id (CHECK: device_confirmed requires it), so ON DELETE SET NULL made
-- deleting such a user fail until cleanup removed the row. The row is short-lived relay state with no value
-- after the account is gone; remove it with the user.
alter table private.community_auth_requests
    drop constraint community_auth_requests_user_id_fkey,
    add constraint community_auth_requests_user_id_fkey
        foreign key (user_id) references auth.users(id) on delete cascade;

-- D1-02: capacity limits are checked and the row is inserted under one transaction-scoped lock.
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

    -- One creator at a time: the capacity counts below and the insert must see the same set of active rows.
    -- Row locks cannot protect rows that do not exist yet, so two concurrent creates could both pass the limit.
    perform pg_advisory_xact_lock(hashtextextended('safeauth:create-capacity', 0));

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

-- D1-05: browser-status only checked the whole request's expiry, so the central page kept saying the code could
-- still be collected after the code's own TTL (default 120 s). An undelivered expired code fails the request;
-- a delivered code is left alone because the device may already have exchanged it.
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
    if v_status = 'code_ready' and v_row.code_expires_at <= now() then
        update private.community_auth_requests
           set status = 'failed', encrypted_auth_code = null, failed_at = now(), failed_reason_code = 'code_expired'
         where id = p_id;
        v_status := 'failed';
    end if;
    return jsonb_build_object('phase', v_status, 'expires_at', v_row.expires_at);
end;
$$;

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
    -- An undelivered code that outlived its own TTL can no longer be exchanged: the request has failed
    -- (same transition as poll and browser-status), not merely lost its ciphertext.
    update private.community_auth_requests
       set status = 'failed', failed_at = now(), failed_reason_code = 'code_expired'
     where status = 'code_ready'
       and code_expires_at <= now()
       and expires_at > now();

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
        'public.internal_safeauth_browser_status(uuid,text)',
        'public.internal_safeauth_cleanup()'
    ] loop
        execute format('revoke all on function %s from public, anon, authenticated', fn);
        execute format('grant execute on function %s to service_role', fn);
    end loop;
end;
$$;
