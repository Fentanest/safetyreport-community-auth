# 공식 계정 1:1 바인딩 서버 구현 보고 (r2 수동 삭제 반영)

2026-10-06. auth HEAD `66a120e`, map HEAD `0964d90`, 두 worktree의 브랜치 `feat/official-account-binding`에서 구현했다.
커밋·push·운영 Supabase 접근·Edge/Pages/스토어 배포를 하지 않았다. 기존 untracked node_modules 심볼릭 링크는 보존했다.

## 구현

- auth: `private.community_official_account_bindings`의 user PK와 dataset UNIQUE로 양방향 1:1.
  연결 등록 트랜잭션 안에서 생성하고 `official_account_mismatch`/`official_account_taken`을 nonretryable 409로 반환한다.
  mismatch만 본인의 bound_dataset_key를 반환하며 taken은 상대 정보 없이 운영자 문의 문구를 반환한다.
- status에 본인의 official_account 추가. contributions-delete는 기존 fact 삭제·tombstone·삭제 fence·연결 폐기를
  유지하면서 바인딩을 삭제하고 official_account_released=true를 반환한다.
- 운영자 해제 RPC는 service_role 전용. 현재 예상 소유자·작업자/티켓·사유를 받고 선점자의 해당 dataset fact를 삭제한다.
  같은 범위 identity tombstone·단조 증가 삭제 fence·연결 폐기·바인딩 해제·projection 갱신과 감사를 원자적으로 처리한다.
  감사에는 누가·언제·어떤 user/dataset·사유·삭제 fact/신규 tombstone/폐기 연결 건수·deletion_id·fence 시각이 남는다.
- map: 연결 dataset과 바인딩 불일치/미바인딩 시 요청을 거절한다. 다른 dataset에 같은 source_report_key 또는
  report_number의 fact가 있으면 report_owned_elsewhere로 이벤트를 거절하고 receipt별 감사 1건을 남긴다.
  두 종류 식별자의 전역 advisory lock을 정렬해서 획득하며 신고번호 조회 인덱스를 추가했다.
- 기존 최신 ingest(202609281800)의 정상 fact 갱신·재공유·멱등·삭제 처리를 유지했다. 공개 집계 함수는 바꾸지 않았다.

## 계약 결정

1. ingest의 바인딩 없음도 불일치로 간주한다. 요청 HTTP 409 `official_account_mismatch`, retryable=false이며
   사용자 UUID/dataset을 추가로 반환하지 않는다.
2. report_owned_elsewhere는 HTTP 200 배치 안의 이벤트 거절이다. durable=false, receipt_id=null,
   projection_status=not_applicable, retryable=false. 숨겨진/동의 철회 fact도 소유권 검사 대상이다.
   같은 거절 이벤트를 그대로 재전송하면 동일 거절을 반환하고 감사를 중복 생성하지 않는다.
   삭제 fence·tombstone과 기존 event_id 충돌/멱등 판단은 기존 우선순위를 유지한다.
3. backfill은 기존 연결과 현재 fact의 합집합을 사용하며 bound_at은 후보의 가장 이른 시각이다.
   단, 이미 contributions-delete를 완료한 사용자의 fence 이전 비활성 연결은 바인딩을 되살리지 않도록 제외한다.
   활성 연결은 트랜잭션 시작 시각이 fence보다 빠를 수 있어 항상 포함한다. 단순 연결 철회·동의 철회는 해제 사유가 아니다.
   사용자당 dataset 복수 또는 dataset당 사용자 복수면 전체 migration이 실패한다.
4. **r2 사용자 정정 우선:** 운영자 해제는 선점자의 해당 dataset 공유 fact를 삭제하고 활성 연결을 폐기한다.
   기존 사용자 전체 contributions-delete와 범위를 분리하기 위해 private `community_dataset_deletion_fences`는
   `(contributor_id,dataset_key)`, `community_dataset_fact_tombstones`는 `(contributor_id,dataset_key,source_report_key)`를 키로 쓴다.
   기존 전체 삭제 fence/tombstone을 보존하고 ingest에서 둘 다 검사한다. 다른 사용자·dataset은 영향을 받지 않는다.
   identity는 기존 삭제와 같은 source_report_key이며 신고번호 전역 tombstone은 만들지 않는다.
   원시 ingest receipt 이력과 감사는 보존한다. tombstoned_identities는 이번 호출에서 새로 생성한 수이다.
   expected_user는 검토 이후 다른 소유자가 된 바인딩을 해제하지 않도록 하는 보호이다.
   동일 사용자의 재바인딩까지 구분하는 세대 토큰은 없으므로 관리자는 호출 직전 상태를 확인한다.
5. 계정 삭제 감사와 운영자 감사는 service_role SELECT만 허용한다. 직접 INSERT/UPDATE/DELETE 권한은 주지 않고
   security definer RPC가 기록한다. 운영자 참조는 서비스 호출자가 전달하는 티켓/신원 참조이다.

6. 안신 계정은 클라이언트 DB에 저장하지 않는다. 서버 바인딩을 정본으로 현재 로그인 설정과 status를 대조한다.
   서버 원문 ID 저장이나 API DTO 변경은 필요하지 않아 클라이언트 규칙 문서만 정정했다. 양방향 1:1·카카오 필수는 유지한다.
7. 두 신규 migration은 이전 실행부터 미커밋·미배포 상태이므로 그 파일에 r2를 반영하고 composition 해시를 갱신했다.
   이미 배포된 기존 migration은 수정하지 않았다.

## r2에서 추가 수정한 파일

- auth: `supabase/migrations/202610061100_official_account_binding.sql`, `tests/official-binding.integration.test.ts`,
  `tests/account.unit.test.ts`, `docs/account-api.md`, 본 REPORT와 MIGRATION.
- map: `supabase/migrations/202610061101_official_account_ingest.sql`, `tests/integration/official-binding.test.ts`,
  `contracts/community-ingest/{account-api.md,MANIFEST.sha256}`, `docs/product-decisions.md`,
  `docs/integration/community-ingest/migration-manifest.json`, 본 REPORT와 MIGRATION.
- 아래 목록은 직전 실행에서 이어받은 전체 변경 목록이다. 기존 변경 및 node_modules 링크를 보존했다.

## 변경 파일

auth:
- `server/account.ts`
- `supabase/migrations/202610061100_official_account_binding.sql`
- `tests/account.unit.test.ts`, `tests/official-binding.integration.test.ts`
- `tests/support/official-binding-db.ts`, `tests/support/official-binding-fixture.sql`
- `tests/stack/stack.mjs` (전체 map schema가 필요한 migration을 relay-only 스택에서 명시적으로 제외)
- `tests/contracts/community-client/{README.md,MANIFEST.sha256,vectors/account-errors.json}`
- `docs/account-api.md`, `docs/implementation/official-account-binding-20261006/{REPORT.md,MIGRATION.md}`

map:
- `server/ingest/handler.ts`
- `supabase/migrations/202610061101_official_account_ingest.sql`
- `tests/product/ingestHandler.test.ts`, `tests/integration/official-binding.test.ts`
- `contracts/community-ingest/{account-api.md,errors.md,observation.md,MANIFEST.sha256}`
- `docs/product-decisions.md`, `docs/integration/community-ingest/migration-manifest.json`
- `docs/implementation/official-account-binding-20261006/{REPORT.md,MIGRATION.md}`

## 검사 결과

아래 최종 실행들의 서로 다른 테스트 합계는 **160 통과 / 0 실패**다. 단위 검사에서 skip된 DB 테스트는
별도 COMMUNITY_STACK=1 실행 결과로만 통과에 포함했다. 실행하지 않은 legacy relay/browser 35건은 통과가 아니다.

| 위치 | 명령 | 결과 |
|---|---|---|
| auth | `npm test -- --configLoader runner --reporter=dot` | 58 통과, 0 실패, 51 skip(신규 DB 16 + 기존 relay/browser 35) |
| auth | `COMMUNITY_STACK=1 npm test -- --configLoader runner tests/official-binding.integration.test.ts --reporter=dot` | 실제 PostgreSQL 16 통과, 0 실패, 0 skip |
| map | `COMMUNITY_STACK=1 npm test -- --configLoader runner tests/integration/official-binding.test.ts tests/product/ingestHandler.test.ts --reporter=dot` | 실제 PostgreSQL 14 + handler 단위 17 = 31 통과, 0 실패, 0 skip |
| map | `npm test -- --configLoader runner tests/product/communityContract.test.ts --reporter=dot` | 55 통과, 0 실패 |
| 양쪽 | `npx tsc -p tsconfig.json --noEmit` | 각각 exit 0 |
| 양쪽 | `git diff --check` | 각각 exit 0 |
| map | `node scripts/integration/compose_supabase.mjs check --auth /home/better0101/projects/worktree/auth-account-binding` | 53 migrations / 7 functions, exit 0 |

DB 검사는 내부적으로 모든 psql 명령에 `flock /tmp/ci0926-db.lock`을 사용하고 지정 `supabase_db_ci0926-int`만 접근했다.
fixture와 신규 DDL 모두 BEGIN/ROLLBACK 안에서 실행했다. r2 검사 후 기존 연결 1,048건·fact 488건을 확인했으며,
신규 binding/ownership_audit 및 dataset fence/tombstone 테이블이 남지 않은 것을 확인했다. r2 실행 전 건수는 별도 측정하지 않았다. sequence 결번은 PostgreSQL 특성상 남을 수 있다.
서비스/컨테이너/볼륨을 재시작하거나 제거하지 않았다.

검증 범위: 양방향 유일 제약, 충돌 시 backfill 실패, fact-only backfill, 삭제 이력 제외, 본인 상태만 반환,
오류 정보 최소화, same dataset writer 충돌/takeover/rebind, 연결 insert 실패 원자성, 운영자 실제 service_role 호출과 권한,
삭제 해제 반복, source key/신고번호 각각의 충돌, receipt 감사 중복 방지, missing/mismatch binding,
동의 철회/재동의/reshare, 삭제 tombstone/fence, 같은 배치 내 거절+정상 처리, 두 전역 식별자 잠금 획득.

r2 추가 검증: 선점자 해당 범위만 삭제(같은 사용자의 다른 dataset 및 다른 사용자의 같은 dataset fact 보존),
감사 삭제 수/신규 tombstone 수/연결 수, 감사 실패 시 fact·tombstone·fence·binding·연결 전체 rollback,
fence 단조 증가, scoped 삭제 테이블 권한, 사용자 HTTP 경로에 운영자 기능 비노출, 새 소유자 카카오 필수,
진짜 소유자의 동일 dataset·동일 source key/신고번호·삭제 이전 captured_at 업로드 accepted,
선점자 구 연결 거절/재연결 후 tombstone·fence 거절, 다른 dataset 재연결에는 삭제 증거 미전파.

이전 실행 이력(r2 검사 실패 아님): 기본 Vite config loader가 worktree 밖 node_modules/.vite-temp에 쓰려다 EROFS로 시작하지 못했다
(0건 실행, 통과 아님). `--configLoader runner`로 worktree 밖 쓰기를 피했다.
첫 auth 단위 실행에서 registry-dependent migration 목록 검사 1건이 실패하여 stack.mjs의 제외 목록과
전체 composition 전용 분기를 수정했다. 최종 실행은 위 표와 같이 실패 0건이다.

## 미확인·위험

- 운영 현재 충돌 0건은 작업지시서의 사전 확인 정보이며 이번 작업에서 운영 DB를 다시 확인하지 않았다.
  공유 로컬 스택의 과거 fixture에는 전체 연결/fact 기준 복수 dataset 사용자 9명이 있어 영구 migration은 적용하지 않았다.
- 실제 Deno Edge/GoTrue HTTP 배포 E2E 및 여러 DB 세션을 동시에 경쟁시키는 부하 검사는 실행하지 않았다.
  핸들러 단위 + 실제 SQL 트랜잭션/제약/잠금 검증이다. 동시성은 per-user mutex, UNIQUE와 정렬된 advisory lock으로 보호한다.
- 기존 map의 HTTP community-stack 전체 시나리오는 실행하지 않았다. 과거 다중 dataset/타 계정 무제한 기여 fixture는
  이번 계약과 다르므로 전체 배포 E2E를 할 때 현 계약으로 fixture를 갱신해야 한다. 이번에 검증한 정상 경로는 위에 명시했다.
- PC/모바일 UI·주기 점검·로컬 백업/초기화는 별도 담당 범위다. auth의 로컬 client 오류 계약 확장은 upstream 복사본 동기화가 필요하다.
- dataset_key는 기존과 같이 클라이언트 주장 해시이며 공식 계정 소유의 증명은 아니다. 선점 분쟁은 운영자 확인 절차로 처리한다.
- 적용 순서는 SQL 두 개 → Edge이며 쓰기 중지/함수 복구/운영자 런북은 [MIGRATION](MIGRATION.md)에 기록했다.

**커밋하지 않았다.**
