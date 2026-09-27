-- Replace the consent text of policy 2026-09-28.1 in place (user decision 2026-09-27: the version was not in real use yet;
-- deletion requests and questions now go to the map repository's public Issues). Only the text hash changes.
-- Owner: safetyreport-community-auth. Depends on 202609280200.
-- Policies are immutable by design; this one-time correction is allowed only while NO grant references the version,
-- so nobody has agreed to the old wording. Otherwise it fails and a new version (2026-09-28.2) must be published instead.

begin;

do $$
begin
    if exists (select 1 from private.community_consent_grants where policy_version = '2026-09-28.1') then
        raise exception 'COMMUNITY_POLICY_IN_USE: 2026-09-28.1 already has grants; publish 2026-09-28.2 instead';
    end if;
end;
$$;

alter table private.community_policies disable trigger community_policies_no_update;
update private.community_policies
   set consent_text_sha256 = 'a775cc34a175ac880574976b011f2c16cce3b0d366aa7729c2128cd1f1f38670'
 where version = '2026-09-28.1';
alter table private.community_policies enable trigger community_policies_no_update;

commit;
