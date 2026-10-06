# Auth 소유 현재 함수와 호출

공유 전체 테이블·RLS·트리거·인덱스 및 map 소유 계정 함수는 map 저장소 `docs/implementation/query-audit-20261006/INVENTORY.md`가 정본이다. 아래는 그 기준 카탈로그에서 Auth 소유 현재 정의만 추출했다. 새 Auth SQL은 없다.

| 함수 | 현재 정의 | 직접 경로 / 내부 호출 | 빈도 |
|---|---|---|
| `community_bump_projection` | `supabase/migrations/202609260100_community_account_registry.sql:162` | `private.community_facts_projection_trigger`<br>`public.internal_community_delete_contributions` | 표의 상위 함수·트리거가 호출할 때 |
| `community_current_policy` | `supabase/migrations/202609260100_community_account_registry.sql:115` | `public.internal_account_grant_consent`<br>`public.internal_account_policy`<br>`public.internal_account_rebind_connection`<br>`public.internal_account_register_connection`<br>`public.internal_account_revoke_connection`<br>`public.internal_account_revoke_consent`<br>`public.internal_account_status`<br>`public.internal_community_delete_contributions`<br>`public.internal_community_ingest` | 표의 상위 함수·트리거가 호출할 때 |
| `community_grant_is_current` | `supabase/migrations/202609260100_community_account_registry.sql:155` | `public.internal_account_grant_consent`<br>`public.internal_account_status`<br>`public.internal_community_ingest` | 표의 상위 함수·트리거가 호출할 때 |
| `community_identity_state` | `supabase/migrations/202609260100_community_account_registry.sql:102` | `private.my_reports_gate`<br>`public.internal_account_grant_consent`<br>`public.internal_account_rebind_connection`<br>`public.internal_account_register_connection`<br>`public.internal_account_status`<br>`public.internal_analytics_viewer`<br>`public.internal_community_delete_contributions`<br>`public.internal_community_ingest`<br>`public.internal_community_manifest`<br>`public.internal_my_analytics_cohort_source`<br>`public.internal_my_analytics_source` | 표의 상위 함수·트리거가 호출할 때 |
| `community_lineage_active` | `supabase/migrations/202609260100_community_account_registry.sql:146` | `private.community_fact_publicly_listed`<br>`private.my_reports_own`<br>`private.ranking_representatives`<br>`public.internal_account_revoke_consent`<br>`public.internal_analytics_v2_facts`<br>`public.internal_analytics_v2_state`<br>`public.internal_analytics_viewer`<br>`public.internal_community_ingest` | 표의 상위 함수·트리거가 호출할 때 |
| `community_lock_contributor` | `supabase/migrations/202609260100_community_account_registry.sql:130` | `public.internal_account_grant_consent`<br>`public.internal_account_rebind_connection`<br>`public.internal_account_register_connection`<br>`public.internal_account_revoke_connection`<br>`public.internal_account_revoke_consent`<br>`public.internal_community_delete_contributions` | 표의 상위 함수·트리거가 호출할 때 |
| `community_policies_immutable` | `supabase/migrations/202609260100_community_account_registry.sql:27` |  | 정책 UPDATE/DELETE 시 불변성 거부 |
| `community_policy_texts_immutable` | `supabase/migrations/202609280600_policy_consent_text.sql:21` |  | 정책 UPDATE/DELETE 시 불변성 거부 |
| `safeauth_expire_if_needed` | `supabase/migrations/202609251200_community_auth_relay.sql:89` | `public.internal_safeauth_browser_status`<br>`public.internal_safeauth_cancel`<br>`public.internal_safeauth_claim`<br>`public.internal_safeauth_complete`<br>`public.internal_safeauth_poll`<br>`public.internal_safeauth_prepare`<br>`public.internal_safeauth_publish`<br>`public.internal_safeauth_rotate_ticket` | 표의 상위 함수·트리거가 호출할 때 |
| `internal_account_grant_consent` | `supabase/migrations/202609260100_community_account_registry.sql:225` | `server/account.ts:176` | 연결 단계마다; poll/browser_status는 대기 중 반복 |
| `internal_account_policy` | `supabase/migrations/202609280600_policy_consent_text.sql:216` | `server/account.ts:163` | 연결 단계마다; poll/browser_status는 대기 중 반복 |
| `internal_account_rebind_connection` | `supabase/migrations/202609260100_community_account_registry.sql:337` | `server/account.ts:199` | 연결 단계마다; poll/browser_status는 대기 중 반복 |
| `internal_account_register_connection` | `supabase/migrations/202609260100_community_account_registry.sql:303` | `server/account.ts:191` | 연결 단계마다; poll/browser_status는 대기 중 반복 |
| `internal_account_revoke_connection` | `supabase/migrations/202609260100_community_account_registry.sql:362` | `server/account.ts:204` | 연결 단계마다; poll/browser_status는 대기 중 반복 |
| `internal_account_revoke_consent` | `supabase/migrations/202609260100_community_account_registry.sql:275` | `server/account.ts:183` | 연결 단계마다; poll/browser_status는 대기 중 반복 |
| `internal_account_status` | `supabase/migrations/202609260100_community_account_registry.sql:170` | `server/account.ts:155` | 연결 단계마다; poll/browser_status는 대기 중 반복 |
| `internal_safeauth_browser_status` | `supabase/migrations/202610050100_relay_hardening.sql:101` | `server/relay.ts:320` | 연결 단계마다; poll/browser_status는 대기 중 반복 |
| `internal_safeauth_cancel` | `supabase/migrations/202609251200_community_auth_relay.sql:511` | `server/relay.ts:362` | 연결 단계마다; poll/browser_status는 대기 중 반복 |
| `internal_safeauth_claim` | `supabase/migrations/202609251200_community_auth_relay.sql:226` | `server/relay.ts:224` | 연결 단계마다; poll/browser_status는 대기 중 반복 |
| `internal_safeauth_cleanup` | `supabase/migrations/202610050100_relay_hardening.sql:130` | `server/relay.ts:175` | create 요청의 5% 비동기 청소, 선택적 cron |
| `internal_safeauth_complete` | `supabase/migrations/202609251200_community_auth_relay.sql:463` | `server/relay.ts:346` | 연결 단계마다; poll/browser_status는 대기 중 반복 |
| `internal_safeauth_create` | `supabase/migrations/202610050100_relay_hardening.sql:13` | `server/relay.ts:181` | 연결 단계마다; poll/browser_status는 대기 중 반복 |
| `internal_safeauth_poll` | `supabase/migrations/202609251200_community_auth_relay.sql:380` | `server/relay.ts:286` | 연결 단계마다; poll/browser_status는 대기 중 반복 |
| `internal_safeauth_prepare` | `supabase/migrations/202609251200_community_auth_relay.sql:268` | `server/relay.ts:242` | 연결 단계마다; poll/browser_status는 대기 중 반복 |
| `internal_safeauth_publish` | `supabase/migrations/202609251200_community_auth_relay.sql:308` | `server/relay.ts:268` | 연결 단계마다; poll/browser_status는 대기 중 반복 |
| `internal_safeauth_rate_limit` | `supabase/migrations/202609251200_community_auth_relay.sql:553` | `server/account.ts:141`<br>`server/relay.ts:145` | 연결 단계마다; poll/browser_status는 대기 중 반복 |
| `internal_safeauth_rotate_ticket` | `supabase/migrations/202609251200_community_auth_relay.sql:193` | `server/relay.ts:200` | 연결 단계마다; poll/browser_status는 대기 중 반복 |

Auth 사이트는 Auth/relay를 호출하고 제품 테이블을 직접 읽지 않는다. relay는 capability/Auth 검증·rate·액션 RPC 순서, community-account는 Auth·rate·액션 RPC 순서다. 행별 네트워크 N+1은 없다. 빈도는 소스 기반 추정이며 운영 통계가 아니다.
