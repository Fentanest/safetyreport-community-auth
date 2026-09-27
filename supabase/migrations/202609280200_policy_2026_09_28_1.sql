-- Share-consent policy 2026-09-28.1: adds answered fine-amount statistics to the published items
-- (contracts/community-ingest/consent/share-consent-2026-09-28.1.md in safetyreport-community-map, sha256 below).
-- Owner: safetyreport-community-auth. Incremental, no destructive change: policies are immutable rows; this adds one
-- and makes it current. Grants under 2026-09-26.1 become outdated (not revoked): apps ask for the new consent and the
-- lineage continues (facts stay public, S-02 unchanged). Which versions publish amounts is the map's
-- private.community_policy_disclosures (map migration 202609280300).
-- Rollback: point community_policy_current back to '2026-09-26.1' (the new row stays; policies are never deleted).

begin;

insert into private.community_policies(version, consent_text_sha256)
values ('2026-09-28.1', '986cc1d6ec2fb850c5bfb20976a250f030f1c5249b97c7815cfdafbd34d2306a');

update private.community_policy_current set version = '2026-09-28.1', effective_at = now() where singleton;

commit;
