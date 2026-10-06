# Auth 적용 범위

이번 Auth 커밋은 테스트 도구·검증 문서·증거만 포함한다. 새 Auth SQL 및 Edge/Pages 배포는 없다.

공유 DB에서 아직 적용되지 않았을 때만 auth `202610050100_relay_hardening.sql`을 먼저 적용하고, map `202610060100` → `202610060200` → `202610060300` → `202610060400` → `202610060500`을 적용한다. 실제 운영 이력은 이번 감사에서 조회하지 않았다. 운영자용 psql 명령, 이력 등록, lock 및 forward rollback 절차는 map 저장소 `docs/implementation/query-audit-20261006/MIGRATION.md`, 파일 해시는 map `docs/integration/community-ingest/migration-manifest.json`이 정본이다.

어떤 운영 접속/배포/push 명령도 이번 작업에서 실행하지 않았다. `tests/stack/configure-composed.mjs`와 composed 테스트는 명시된 로컬 `ci0926-int`만 사용한다.
