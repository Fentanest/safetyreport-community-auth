# safeauth 배포·설정 런북

대상: 운영자(Fentanest). 이 문서의 원격 단계(Supabase, DNS, GitHub 설정, 앱 배포)는 아직 실행되지 않았다.
모두 운영자 승인 후 운영자가 실행한다.

## 1. 확정 주소

| 항목 | 값 |
|---|---|
| 중앙 페이지 | `https://safeauth.worklazy.net/` |
| 웹 콜백 | `https://safeauth.worklazy.net/callback.html` |
| 브라우저 Origin | `https://safeauth.worklazy.net` |
| 모바일 Standalone 복귀 | `com.fentanest.mysafetyreport://auth/callback` |

인증은 **별도 서브도메인(별도 origin)** 이다. `worklazy.net`(WorklazyTools)·`safemap.worklazy.net`(지도)과
브라우저 저장소·스크립트 실행 맥락이 분리된다. 같은 상위 도메인(same-site)이라는 점만 공유한다(보안 검토 §3).

## 2. 저장소와 주소

- 이 저장소(`Fentanest/safetyreport-community-auth`)가 중앙 인증 페이지·relay Edge 함수·relay migration·테스트의 정본이다.
  배포 주소는 이 저장소의 GitHub Pages → `safeauth.worklazy.net` 하나다.
- 커뮤니티 지도는 `Fentanest/safetyreport-community-map` → `safemap.worklazy.net`(그 저장소의 Pages). 두 저장소는 코드·번들·origin을 공유하지 않는다.
  공유하는 것은 같은 Supabase 프로젝트(auth.users)뿐이다.
- **이 저장소는 private이다.** private 저장소의 GitHub Pages는 유료 요금제(Pro 이상)가 필요하다. 요금제는 확인하지 못했다
  (토큰 권한 부족). 무료 요금제라면 저장소를 공개로 바꾸거나 공개 배포 전용 저장소가 필요하다.

### Supabase migration 이력 주의

같은 Supabase 프로젝트에 두 저장소(community-map, 이 저장소)가 각자 `supabase/migrations`를 가진다. Supabase CLI의
`supabase db push`는 원격 이력에 로컬에 없는 버전이 있으면 멈추므로, 한쪽 저장소에서 push한 뒤 다른 쪽에서 그대로 push할 수 없다.
이 저장소의 migration(`202609251200_community_auth_relay.sql`)은 자기 객체만 만드는 독립 SQL이다. 적용 방법은 둘 중 하나를 정한다.

1. (권장, 간단) SQL Editor 또는 `psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f supabase/migrations/202609251200_community_auth_relay.sql`로
   한 번 적용하고, 이 문서에 적용 날짜를 기록한다. `supabase_migrations` 이력에는 남지 않는다.
2. migration 이력을 한 저장소(community-map)만 관리하기로 하고, 배포 때 이 파일을 그 저장소의 migrations에 같은 이름으로 복사해 push한다.

Edge 함수 배포(`supabase functions deploy community-auth-relay`)는 migration 이력과 무관하므로 이 저장소에서 바로 한다.

## 3. DNS와 GitHub Pages (운영자 수동)

1. DNS(Cloudflare, worklazy.net 존): `safeauth` CNAME → `fentanest.github.io`, **DNS 전용**(프록시 끔)으로 두어
   GitHub 인증서 발급을 막지 않는다.)
2. GitHub 계정 Settings → Pages → **Verified domains**에 `worklazy.net`을 인증해 두면 서브도메인 탈취를 막는다.
3. 이 저장소 Settings → Pages: Source = GitHub Actions, Custom domain = `safeauth.worklazy.net`, **Enforce HTTPS** 켬.
4. Settings → Variables: `SAFEAUTH_PUBLIC_SUPABASE_URL`, (선택) `SAFEAUTH_PUBLIC_PUBLISHABLE_KEY`,
   `SAFEAUTH_PUBLIC_PRIVACY_POLICY_URL`, `SAFEAUTH_PUBLIC_OPERATOR_CONTACT`.
5. Actions → `safeauth-pages` → Run workflow (main). 빌드·단위 테스트·산출물 검증 실패 시 배포하지 않는다.

## 4. Supabase Dashboard (운영자 수동)

1. **Authentication → URL Configuration → Redirect URLs**에 두 줄을 **추가**한다. 기존 항목·Site URL은 바꾸지 않는다.
   ```text
   https://safeauth.worklazy.net/callback.html
   com.fentanest.mysafetyreport://auth/callback
   ```
   목록에 없는 `redirect_to`를 받으면 Supabase Auth는 오류 대신 **Site URL로 코드를 보낸다**
   (GoTrue v2.197.0, 로컬 테스트 P05b). 등록 누락은 조용한 실패가 되므로 §8 점검을 반드시 한다.
   이전 안내의 `https://worklazy.net/safeauth/callback.html`을 이미 넣었다면 쓰이지 않으니 지워도 된다.
2. **Sign In / Providers → Kakao**: REST API 키·Client Secret은 여기에만. “Allow users without an email” 켬.
3. **카카오 Developers → Redirect URI**에는 Supabase Kakao Provider 화면의 `https://<PROJECT_REF>.supabase.co/auth/v1/callback`.
4. “Single session per user”는 켜지 않는다.

## 5. 값과 저장 위치

| 값 | 성격 | 넣는 곳 |
|---|---|---|
| `SAFEAUTH_PUBLIC_*` | 공개 | 이 저장소 Actions Variables |
| `AUTH_RELAY_HASH_PEPPER` | **비밀** | Supabase Edge Secrets. `openssl rand -base64 32 \| tr '+/' '-_' \| tr -d '='` |
| `AUTH_RELAY_ENCRYPTION_KEY` | **비밀** | Supabase Edge Secrets. 위와 **별도** 생성(32바이트) |
| `AUTH_RELAY_ENABLED` | 설정 | 검증 전 `false`, 공개 시 `true` |
| `AUTH_SITE_URL=https://safeauth.worklazy.net/` | 설정 | Supabase Edge Secrets |
| `AUTH_BROWSER_ORIGIN=https://safeauth.worklazy.net` | 설정 | Supabase Edge Secrets (경로 금지) |
| `SUPABASE_URL`, 서버 키 | 플랫폼 제공 | Edge 런타임 기본값. 복사 금지 |
| safetyreport `[COMMUNITY] supabase_url`, `publishable_key`, `enabled` | 공개 | 설치별 config.ini 또는 Docker env `SAFETYREPORT_COMMUNITY_*` (`site_url` 기본값이 `https://safeauth.worklazy.net/`) |
| 모바일 `COMMUNITY_SUPABASE_URL`, `COMMUNITY_SUPABASE_PUBLISHABLE_KEY` | 공개 | 앱 빌드 `--dart-define` |
| 사용자 access/refresh token | 비밀 | 각 원래 기기의 암호화 저장소에만 |

빌드는 `sb_secret_`·service_role JWT·이름에 SECRET/SERVICE/PEPPER/PRIVATE/PASSWORD가 들어간 공개 변수를 거부한다.

## 6. 백엔드(Supabase) 배포 — 승인 후

```bash
supabase link --project-ref <PROJECT_REF>
# DB: §2 'migration 이력 주의'의 방법으로 202609251200_community_auth_relay.sql 적용
supabase secrets set AUTH_RELAY_HASH_PEPPER=... AUTH_RELAY_ENCRYPTION_KEY=... \
  AUTH_SITE_URL=https://safeauth.worklazy.net/ AUTH_BROWSER_ORIGIN=https://safeauth.worklazy.net AUTH_RELAY_ENABLED=false
supabase functions deploy community-auth-relay   # config.toml: verify_jwt=false (이 함수만)
```
- community-map의 migration과 `public-analytics` 함수는 건드리지 않는다.
- 청소: pg_cron이 있으면 `select cron.schedule('safeauth-cleanup','23 * * * *','select public.internal_safeauth_cleanup()');`.
  없으면 relay가 요청 생성 때 5% 확률로 정리한다(pg_cron 사용 여부 미확인).

## 7. 갱신·롤백

- 갱신: main에 병합 후 `safeauth-pages` 수동 실행. push만으로는 배포되지 않는다.
- 롤백: 직전 정상 커밋에서 workflow를 다시 실행하거나, GitHub Pages 배포 이력에서 이전 배포로 되돌린다.
- 긴급 차단: Supabase `AUTH_RELAY_ENABLED=false` (새 연결 즉시 중단, 이미 연결된 기기는 영향 없음).

## 8. 배포 후 점검 (운영자, 실제 계정)

1. `curl -sI https://safeauth.worklazy.net/` → 200; 본문에 `<meta name="safeauth-page" content="index">`. `callback.html`도 직접 확인.
2. 브라우저 Network: 광고·분석·외부 CDN 없음, 연결 대상은 Supabase뿐.
3. PC(127.0.0.1:6819)에서 연결 → 비교코드 일치 → 카카오 로그인(본인 직접) → 원래 앱에서 계정 확인 → 중앙 “완료”.
4. Docker(LAN IP/사용자 도메인)에서 반복. Supabase Redirect URLs에 사용자별 주소를 추가하지 않았음을 확인.
5. 모바일 Standalone·Client 각각 반복. 연결 해제 후 다른 기기 로그인이 유지되는지(scope=local).
6. 실패 시 `AUTH_RELAY_ENABLED=false` 후 로그의 `trace`만 공유(코드·토큰·링크 금지).
