# Auth Supabase 쿼리 감사 · 2026-10-06

기준 `151adfd`에서 제품 SQL·Edge·중앙 페이지는 변경하지 않았다. map/auth 공유 스키마의 현재 함수와 모든 RPC/REST 경로를 기존 `supabase_*_ci0926-int`에서 검사했다. Auth 일반 연결 단계·동의·기기 RPC는 3천 fact 규모에서 100ms 미만이었고, 10배 relay/rate 원장의 cleanup도 약 0.1초였다. 행별 RLS auth.uid 호출은 없으며 내부 RPC는 service_role 경계를 유지한다. 성능을 이유로 capacity lock, 단회 코드 전달, rate·nonce 검사를 제거하지 않았다.

공유 전체 목록·함수 정의·custom/generic 및 3천/3만 전후 표는 map 저장소 `docs/implementation/query-audit-20261006/{INVENTORY,MEASUREMENTS,REPORT}.md`와 `evidence`가 정본이다. Auth의 `internal_safeauth_*`, `internal_account_*`, policy/identity/grant helper, immutable policy trigger도 전부 그 74개 함수/79개 시나리오에 포함된다. frequency는 코드상 발생 시점 추정이며 실제 운영 트래픽이 아니다. 합성 계정 수는 30/300, 동의 이력 120/1,200, 연결 60/600, relay 600/6,000, rate 원장 3천/3만이다.

변경한 테스트 도구는 기존 공유 스택을 읽는 `SAFEAUTH_COMPOSED_STACK=1` 모드를 제공한다. 이 모드에서는 Docker up/down/migrate를 거부하고, 기존 로컬 Auth 컨테이너의 설정을 비밀값 출력 없이 무시된 `composed.env`에 저장한다. 실제 GoTrue/PostgREST 경로와 issuer, OAuth callback, 허용된 사이트/하위 경로 포트를 사용한다. 기본 standalone 모드의 포트·환경 파일은 유지한다. browser 출력 경로를 별도 지정할 수 있으며, 테스트가 기대하던 오래된 문구를 현재 UI의 정확한 문구로 수정했다. assertion을 제거하거나 느슨하게 하지 않았다.

브라우저 증거는 [browser-results.json](evidence/browser/browser-results.json)과 그 파일이 참조하는 25개 screenshot이다. 실제 Chromium에서 PKCE 연결 성공, 대기/취소/만료/중복 claim, 네트워크 오류·새로고침, 여러 화면 크기·테마, 접근성, HTTP host/Referer/token 경계를 검증했다. 390px dark 성공 및 1440px light 대기 screenshot을 열어 가독성·상태를 확인했다. 로컬 mock Kakao이며 실제 Kakao/운영/Pages smoke가 아니다.

SQL 적용은 공유 manifest에 따라 아직 없는 auth `202610050100` 후 map `202610060100` → `060200` → `060300` → `060400` → `060500` 순서다. 이번 Auth 커밋에는 새 migration이 없다. 상세 운영자 명령은 map `MIGRATION.md`를 따른다. Edge·Pages·앱 재배포는 필요 없다. 운영 접속·push·배포를 수행하지 않았다. 재현은 [verification.md](../../verification.md)의 composed 절차를 따른다.

최종 검사: 단위 54개, 실제 GoTrue/PostgREST를 쓰는 relay 24개가 통과했다. 동일 24개를 실제 Deno Edge 엔트리로도 재실행했다. 최초 Deno 재실행의 1개 실패는 authorize URL의 gateway/Kong 주소 기대값 차이였으며, 런타임 구성에 맞는 정확한 주소를 검증하도록 테스트 fixture를 보완했다. caller-supplied URL 거절 assertion은 유지한다. 초기 OAuth 설정·호스트명·문구 fixture 실패도 제품 SQL 실패와 구분했다. 브라우저와 복원 완료 상태는 evidence/tests.json 및 map의 local-restoration.json을 따른다.


최종 결과는 단위 54/54, relay 24/24, Chromium 11/11이며 고유 89개가 통과했다. 실제 Deno Edge 엔트리의 relay 24개도 추가 통과했다. 로그는 [tests.json](evidence/tests.json)을 따른다. 공유 로컬 DB의 원래 auth/private/public 56개 테이블 데이터·함수/권한 카탈로그·relay FK·4개 시퀀스·migration 이력 41개를 복원했고 제공된 6개 Supabase 컨테이너의 실행/상태를 확인했다. Realtime 자체의 미래 날짜 파티션 생성과 만료 파티션 정리는 map 복원 증거에 별도 차이로 기록했다. 추가 테스트 서버는 종료했다.
