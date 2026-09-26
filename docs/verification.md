# safeauth 로컬 검증 방법

모든 값은 루프백·임시값이다. 운영 Supabase·카카오에 접속하지 않는다.

## 구성

| 구성 | 주소 | 실체 |
|---|---|---|
| Postgres | 127.0.0.1:54432 | `supabase/postgres:17.6.1.011` + 저장소의 모든 migration |
| Supabase Auth | 127.0.0.1:54499 | `supabase/gotrue:v2.197.0` (Kakao provider URL을 모의 서버로 지정) |
| PostgREST | 127.0.0.1:54498 | `postgrest/postgrest:v13.0.7` |
| 게이트웨이(“Supabase URL”) | 127.0.0.1:54400 | `tests/stack/gateway.ts` — `/auth/v1`, `/rest/v1` 프록시 + relay |
| 모의 카카오 | 127.0.0.1:54410 | `tests/stack/mock-kakao.mjs` |
| 중앙 페이지 | 127.0.0.1:8480 (루트 base, `safeauth.worklazy.net` 역할) | GitHub Pages 흉내 정적 서버 |

비밀값(Postgres 비밀번호, JWT 서명키, 모의 카카오 secret, pepper, 암호화 키)은 `stack.mjs up` 때
`.safeauth-stack/stack.env`(0600, gitignore)에 생성된다. 저장소에 하드코딩된 키는 없다.

## 순서

```bash
npm ci
SR_MAP_REPO=../safetyreport-community-map node tests/stack/stack.mjs up   # 컨테이너 + migration(계정 registry 는 map 스키마 선행 필요, 없으면 건너뜀)
npx vitest run tests/unit.test.ts                  # 컨테이너 불필요
SAFEAUTH_STACK=1 npx vitest run tests/relay.integration.test.ts

# Deno Edge 엔트리로 같은 테스트(선택)
docker run -d --name safeauth-deno-relay --network host -v "$PWD":/work:ro -w /work \
  --env-file .safeauth-stack/deno.env --entrypoint deno denoland/deno:2.5.6 \
  run --allow-net --allow-env --allow-read supabase/functions/community-auth-relay/index.ts
SAFEAUTH_STACK=1 SAFEAUTH_RELAY_UPSTREAM=http://127.0.0.1:8000 npx vitest run tests/relay.integration.test.ts

# 브라우저 검수 (relay integration과 포트가 겹치므로 그 테스트가 끝난 뒤 실행)
tests/stack/build-local.sh
node --experimental-strip-types tests/stack/serve-local.ts .safeauth-stack/dist-local &
SAFEAUTH_STACK=1 SAFEAUTH_BROWSER=1 npx vitest run tests/browser.e2e.test.ts --testTimeout 180000

node tests/stack/stack.mjs down
```

`.safeauth-stack/deno.env`는 `stack.env`의 서비스 키·pepper·암호화 키와 `AUTH_RELAY_LOCAL_STACK=loopback-only`,
`AUTH_SITE_URL=http://127.0.0.1:8480/`, `AUTH_BROWSER_ORIGIN=http://127.0.0.1:8480`, `SUPABASE_URL=http://127.0.0.1:54400`,
`AUTH_RELAY_ENABLED=true`로 만든다(권한 0600).

## 한계

- 카카오는 모의 서버다. GoTrue의 Kakao provider 코드 경로(토큰 교환·`/v2/user/me`)는 실제로 실행되지만 카카오 서버 동작은 아니다.
- 로컬 GoTrue는 HS256 서명이다. hosted 프로젝트가 비대칭 서명 키를 쓰면 relay는 여전히 `/auth/v1/user`로 검증하므로 영향은 없어야 하지만 확인하지 않았다.
- 정적 서버는 GitHub Pages의 디렉터리 리다이렉트·404만 흉내 낸다. 실제 헤더·캐시는 다르다.
