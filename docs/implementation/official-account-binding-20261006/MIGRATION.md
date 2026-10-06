# 공식 계정 바인딩 적용·롤백·운영 런북

이 문서는 실행 준비용이다. 운영 SQL·Edge 배포는 이번 작업에서 실행하지 않았다.
두 SQL은 map `docs/integration/community-ingest/migration-manifest.json`에 각각 소유 레포·해시·의존성으로 등록한다.

## SQL → Edge 적용 순서

1. 승인된 운영 작업 창에서 쓰기 요청을 중지하고 실행 중인 ingest/account 트랜잭션이 끝난 것을 확인한다.
   바인딩 후보(삭제 fence 이전의 비활성 연결 제외, 활성 연결과 모든 현재 fact 포함)를 user/dataset 양쪽으로
   묶어 복수 상대가 있는지 확인한다. 충돌을 임의 정리하거나 가장 최신 행만 택하지 않는다.
2. 기존 함수 정의·권한과 관련 private 테이블을 승인된 보안 백업에 보존한다. 기존 migration 파일 전체를 재실행하면
   테이블/정책 DDL이 충돌하므로 함수 복구용 `pg_get_functiondef` 결과를 따로 확보한다.
3. **auth `202610061100_official_account_binding.sql` → map `202610061101_official_account_ingest.sql`** 순으로 적용한다.
   가능하면 외부 한 트랜잭션에서 두 파일의 최상위 BEGIN/COMMIT만 제거해 적용한다. 개별 적용 시 두 SQL이
   모두 성공할 때까지 쓰기를 재개하지 않는다. backfill은 양방향 충돌 시 `23505 / OFFICIAL_ACCOUNT_BACKFILL_CONFLICT`로 실패한다.
4. SQL 적용을 확인한 뒤 auth `community-account` 및 map `community-ingest` Edge를 새 handler로 교체한다.
   status의 null/실제 바인딩, 두 연결 409, 삭제 해제, ingest 거절/정상 업로드를 합성 계정으로 확인한 뒤 쓰기를 재개한다.
   구 Edge는 새 SQL 오류를 server_error로 해석할 수 있으므로 혼합 버전을 장기간 운영하지 않는다.

## 운영자 수동 해제

service_role 전용 RPC `internal_account_release_official_account(p_dataset_key text, p_expected_user uuid,
p_operator_ref text, p_reason text)`를 사용한다. anon/authenticated 실행 권한은 없다.
관리 도구에서만 바인딩 소유권과 사용자 문의를 확인하고 현재 소유자 UUID를 expected_user로 전달한다.
operator_ref에는 검증 가능한 내부 작업자/티켓 참조를, reason에는 확인 사유를 넣는다(비밀번호·토큰 금지).
두 필드는 필수이며 각각 200/1000자 이하이다. service key를 사용자/클라이언트에 전달하지 않는다.

```sql
-- 안전한 관리 세션에서 파라미터 바인딩으로 실행(값은 이 문서에 기록하지 않음).
select public.internal_account_release_official_account(
  :dataset_key, :expected_user, :operator_ref, :reason);
```

성공 시 **선점자(expected_user)의 지정 dataset_key 공유 fact 삭제**, identity tombstone, 삭제 fence,
그 dataset의 활성 연결 폐기, 바인딩 해제와 `private.community_official_account_audit` 기록을 한 트랜잭션으로 수행한다.
다른 사용자나 선점자의 다른 dataset fact·연결은 건드리지 않는다. 동의 상태는 유지한다.
반환값은 `{official_account_released:true, revoked_connections, deleted_facts, tombstoned_identities,
deletion_id, deleted_at, audit_id}`이다. tombstoned_identities는 이번에 새로 기록한 identity 수다.
감사에는 작업 시각·이전 user/dataset·작업자/티켓·사유·삭제 fact 수·신규 tombstone 수·폐기 연결 수·deletion_id·fence 시각이 남는다.
감사와 삭제 증거는 private 영역에 보존하며 사용자 API에는 노출하지 않는다.
검토 이후 소유자가 달라졌거나 이미 해제됐으면 `not_found`로 거절하고 추가 삭제·감사를 만들지 않는다.

호출 전 expected_user/dataset의 fact 수(숨겨진 fact 포함)와 활성 연결 수를 검토하고 기록한다.
호출 후 반환 수와 audit_id의 기록을 대조하고 해당 범위 fact 0건·활성 연결 0건·바인딩 없음인지 확인한다.
이어서 확인된 진짜 주인이 카카오 인증·필수 동의 후 같은 dataset으로 새 connections를 등록하고
같은 신고를 업로드해 accepted가 되는지 확인한다. 선점자의 구 writer는 connection_revoked여야 한다.
새 소유자의 계정에 이미 다른 바인딩이 있으면 정상 계정 변경 절차(contributions-delete)를 먼저 완료해야 한다.

수동 삭제는 `community_dataset_deletion_fences`의 `(contributor_id,dataset_key)`와
`community_dataset_fact_tombstones`의 `(contributor_id,dataset_key,source_report_key)`에 기록한다.
새 소유자에게 fence/tombstone을 복사하지 않는다. 기존 contributions-delete의 사용자 전체 삭제 증거도 그대로 검사한다.
선점자가 같은 dataset을 재연결하더라도 삭제된 identity와 fence 이전 이벤트는 `deleted`로 차단된다.
신고 source key 기준 identity는 기존 contributions-delete와 같으며 신고번호 자체를 전역 tombstone으로 만들지 않는다.
공개 projection 버전과 fact 삭제 트리거의 manifest 세대를 갱신한다. 원시 ingest receipt 이력은 기존 삭제와 같이 보존한다.
계정 소유 증명을 서버 해시 자체로 판단하지 않는다.
동일 사용자가 재바인딩한 경우도 가능한 만큼 작업 직전에 다시 조회한다. 서비스 키 공용 환경에서
operator_ref는 호출자가 기록하는 참조이지 암호학적으로 확인된 운영자 신원은 아니다.

## 롤백

쓰기 중지 → 변경 전 handler 복구 준비 → 백업한 ingest/register/status/delete 함수 정의·권한 복구 →
Edge 복구 → 검증 후 재개 순서로 진행한다. SQL을 되돌리면 1:1 보호가 사라지므로 보호 유지가 필요하면 쓰기를 계속 중지한다.
바인딩·감사 테이블은 기본적으로 보존한다. 삭제/수동 해제로 사라진 fact·연결 상태를 SQL rollback으로 자동 복구하지 않는다.
새 함수나 테이블을 완전히 제거해야 한다면 의존 함수 복구를 먼저 확인하고 감사 자료를 보안 백업한 뒤 별도 승인하에 처리한다.
기존 migration을 수정하거나 migration 이력만 지워 재실행하지 않는다.

## 로컬 재현

각 테스트는 `flock /tmp/ci0926-db.lock docker exec -i supabase_db_ci0926-int psql ...` 안에서
BEGIN → 합성 fixture → 새 migration → assertions → ROLLBACK을 수행한다. 실패 시 연결 종료로 rollback된다.
기존 데이터는 트랜잭션 안에서만 비우고 복구하며 컨테이너·볼륨·영구 함수/테이블은 변경하지 않는다.
PostgreSQL sequence 값은 ROLLBACK되지 않으므로 writer_epoch의 결번은 생길 수 있다(재사용하지 않는다).
다른 작업도 같은 flock 규칙을 따라야 한다. 운영 URL·--linked·push·배포는 사용하지 않는다.
