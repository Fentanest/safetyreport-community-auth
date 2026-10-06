# Query audit · 2026-10-06

기준 `151adfd`의 계정/동의/연결/relay SQL과 Edge 호출 경로를 map의 공유 DB 감사에 포함했다. 기존 `202610050100_relay_hardening.sql`은 수정하지 않았다. auth의 새 제품 migration과 Edge 변경은 없다.

로컬 통합·브라우저 테스트가 기존 `supabase_*_ci0926-int`를 재사용할 수 있도록 명시적인 `SAFEAUTH_COMPOSED_STACK=1` 모드를 추가했다. 이 모드에서는 Docker up/down/migrate를 거부한다. 기본 독립 스택 모드와 모든 검증 assertion은 유지한다. 테스트용 mock의 Docker 호스트명 해석과 포트·OAuth 경로를 조정하며 호스트 DNS/전역 설정은 바꾸지 않는다. 브라우저 증거 디렉터리는 선택적으로 분리할 수 있다.

상세 목록·측정·SQL 배포 순서는 map 저장소의 `docs/implementation/query-audit-20261006/`가 정본이다. auth의 실제 검사 결과는 REPORT.md에 기록한다.
