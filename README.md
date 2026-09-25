# safetyreport-community-auth

나만의 안전신문고의 **커뮤니티 계정 연결** 중앙 페이지와 기기 연결 중계(relay).
공개 주소 `https://safeauth.worklazy.net/` (콜백 `https://safeauth.worklazy.net/callback.html`).

PC/Docker safetyreport 서버가 PKCE verifier와 Supabase 세션을 소유하고, 이 페이지는 브라우저에서 카카오 로그인 결과(인증 코드)를
원래 기기로 중계만 한다. 중앙 페이지는 토큰을 교환하거나 저장하지 않는다. 모바일 Standalone은 이 중계를 쓰지 않는다.

| 경로 | 내용 |
|---|---|
| `site/` | 정적 MPA (index·callback·help·privacy), Vite + TypeScript, 광고·분석·외부 CDN 없음 |
| `server/` | relay 로직 (프로토콜·검증·HMAC·AES-GCM). Edge 함수·Node 테스트·브라우저가 공유 |
| `supabase/functions/community-auth-relay/` | Supabase Edge 엔트리 (`verify_jwt=false`, 액션별 capability 검증) |
| `supabase/migrations/` | relay 전용 테이블·원자적 상태 전이 함수 (service_role 전용, 독립 SQL) |
| `scripts/verify-artifact.mjs` | 배포 전 산출물 검사 (허용 목록·CSP·비밀·공식 카카오 에셋 해시) |
| `tests/` | 단위, 로컬 Supabase 스택 통합, Playwright 브라우저 검수 |
| `docs/` | protocol, deployment, security-review, verification, acceptance, assets |

```bash
npm ci
npm test                       # 단위 테스트 (스택·브라우저 테스트는 자동 skip)
npm run build && npm run scan  # dist/ (base /)
npm run stack -- up            # 로컬 Supabase Auth/Postgres/PostgREST (docs/verification.md)
```

배포는 수동이다: `.github/workflows/publish-pages.yml` (docs/deployment.md). push만으로 배포되지 않는다.
관련 저장소: `safetyreport`(PC/Docker 서버 쪽), `safetyreport-mobile`(앱), `safetyreport-community-map`(지도, `safemap.worklazy.net`).
