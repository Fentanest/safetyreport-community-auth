# safeauth 기기 연결 프로토콜 v1 (정본)

코드 정본: `server/protocol.ts`, `server/relay.ts`,
`supabase/migrations/202609251200_community_auth_relay.sql`. 이 문서와 코드가 다르면 코드가 맞고 이 문서를 고친다.

이 프로토콜은 Supabase가 제공하는 표준 device-code 기능이 아니다. Supabase Auth의 PKCE 흐름
(`/auth/v1/authorize` + `/auth/v1/token?grant_type=pkce`)을 **원래 기기가 verifier를 가진 채**
다른 브라우저에서 로그인하도록 중계하는 사용자 정의 설계다. 확인 기준 버전: Supabase Auth(GoTrue)
`v2.197.0` 소스와 실제 컨테이너 (`tests/relay.integration.test.ts`).

## 1. 주소

| 항목 | 값 |
|---|---|
| 중앙 페이지 | `https://safeauth.worklazy.net/` |
| 웹 콜백 (Supabase Redirect URL) | `https://safeauth.worklazy.net/callback.html` |
| 브라우저 Origin (CORS) | `https://safeauth.worklazy.net` (경로 없음) |
| 중계 API | `POST {SUPABASE_URL}/functions/v1/community-auth-relay/{action}` |
| 모바일 Standalone 복귀 | `com.fentanest.mysafetyreport://auth/callback` (중계를 쓰지 않음) |

## 2. 역할과 비밀값

| 값 | 만드는 쪽 | 형식 | 규칙 |
|---|---|---|---|
| `code_verifier` | 원래 기기 | base64url 32바이트(43자) | 원래 기기 밖으로 나가지 않는다. Supabase `/token` 교환 때만 전송 |
| `code_challenge` | 원래 기기 | base64url(SHA-256(verifier)) 43자 | 요청 생성 때 중계에 보냄 |
| `device_secret` | 원래 기기 | base64url 32바이트 | 요청마다 새로 생성. 같은 값으로 재시도하면 같은 요청(멱등) |
| `delivery_key` | 원래 기기 | base64url 32바이트 | 요청마다 1개, 모든 poll에 같은 값 |
| `installation_id` (선택) | 원래 기기 | base64url 22~64자 | 설치별 동시 대기 요청 상한(기본 3)용. 서버에는 HMAC만 |
| `request_id` | 중계 | UUID | 비밀 아님. 이것만으로 아무것도 못 한다 |
| `ticket` | 중계 | base64url 32바이트 | 연결 링크의 `#` 조각으로만 전달. 첫 claim에 묶임 |
| `browser_secret` | 중앙 브라우저 탭 | base64url 32바이트 | sessionStorage. URL 금지 |
| `display_code` | 중계 | `XXXX-XXXX` (A-Z 중 I/L/O 제외, 2-9) | 사람 비교용. 인증 수단 아님 |
| `auth_code` | Supabase Auth | UUID(현행) | 브라우저→중계(AES-GCM 암호화, 기본 120초)→원래 기기 |
| access/refresh token | Supabase Auth | JWT / 불투명 | 원래 기기의 보안 저장소에만. 중앙·다른 기기 전달 금지 |

서버는 비밀값 원문을 저장하지 않는다. `HMAC-SHA256(pepper, "safeauth|v1|<purpose>|<request_id>|<value>")`만 저장·비교한다.

## 3. 상태

```
created → claimed → oauth_started → code_ready → code_delivered → device_confirmed
   └─ 각 미완료 단계에서 cancelled / expired / failed ─┘
```

- `code_ready`: 중앙이 코드를 받음. **성공 아님.**
- `code_delivered`: 원래 기기가 코드를 가져감. **성공 아님.**
- `device_confirmed`: 원래 기기가 세션을 안전하게 저장하고 사용자가 계정을 확인한 뒤 `/complete` 성공. 이때만 중앙에 완료 표시.
- 만료는 DB 시계(`expires_at`) 기준. 만료·취소 후 어떤 호출도 상태를 되살리지 않는다.
- Supabase Auth의 PKCE flow state는 `/authorize` 호출 시점부터 **300초**(GoTrue 기본값) 유효하다. 카카오 로그인·중계·교환이 그 안에 끝나야 한다.

## 4. 공통 규칙

- 모든 요청: `POST`, `Content-Type: application/json`, 본문 8KB 이하, `"protocol": 1` 필수, **모르는 필드는 거부**.
- 응답: `Cache-Control: no-store`. 오류는 `{ "error": { "code", "message", "requestTraceId", "retryAfterSeconds"? } }`.
- `Origin` 헤더가 있으면 허용 목록(`https://safeauth.worklazy.net`)과 정확히 같아야 한다. 서버·앱은 Origin 없이 호출한다. Origin은 인증이 아니다.
- 429는 `Retry-After` 초를 따른다.

| error.code | HTTP | 의미 / 원래 기기 처리 |
|---|---|---|
| `invalid_request`, `unsupported_protocol` | 400 | 버그. 재시도하지 않음 |
| `not_found` | 404 | 요청 없음 또는 비밀값 불일치(구분하지 않음) |
| `already_claimed` | 409 | 다른 브라우저가 먼저 열었음 |
| `invalid_state`, `code_conflict`, `delivery_conflict`, `request_not_reusable`, `session_mismatch`, `prepare_limit` | 409 | 상태 불일치. 새 요청으로 다시 시작 |
| `already_completed` | 409 | 이미 완료(취소 불가) |
| `cancelled`, `failed` | 409 | 종료됨 |
| `expired` | 410 | 만료 |
| `auth_invalid` | 401 | `/complete`의 JWT를 Supabase Auth가 거부 |
| `rate_limited`, `too_many_pending` | 429 | `retryAfterSeconds` 뒤 재시도 |
| `service_disabled`, `config_missing`, `capacity` | 503 | 운영 측 문제. “설정되지 않음/잠시 후” 표시 |
| `server_error` | 500 | 일시 오류로 취급, 백오프 |

## 5. 액션

### 5.1 `requests` (원래 기기)

요청:
```json
{ "protocol": 1, "client_kind": "pc|docker|mobile_client_server", "device_label": "우리집 NAS",
  "code_challenge": "<43>", "code_challenge_method": "s256", "device_secret": "<43>",
  "installation_id": "<optional>" }
```
- `device_label`: NFC 정규화·공백 축약 후 1~40자. 제어문자·양방향 제어·`<>"'\`\\`·URL 스킴 형태는 400.
- 응답 201(신규) / 200(같은 `device_secret` 재시도, 새 ticket 발급·이전 ticket 무효):
```json
{ "protocol": 1, "request_id": "<uuid>", "bootstrap_url": "https://safeauth.worklazy.net/#r=<uuid>&t=<ticket>",
  "display_code": "ABCD-2345", "expires_at": "<ISO>", "poll_interval_seconds": 5, "code_ttl_seconds": 120 }
```
- `bootstrap_url`은 1회용 민감 링크다. 로그·설정 응답·백업에 넣지 않는다. 화면 표시/새 탭 열기만.

### 5.2 `claim` / `prepare` / `publish` / `browser-status` (중앙 브라우저 전용)

원래 기기는 호출하지 않는다. 상세는 `server/relay.ts`.

### 5.3 `poll` (원래 기기)

요청: `{ "protocol": 1, "request_id", "device_secret", "delivery_key" }`

응답 `status`:
| status | 추가 필드 | 원래 기기 처리 |
|---|---|---|
| `pending` | `phase`(created/claimed/oauth_started), `expires_at`, `poll_after_seconds` | 기본 5초 + 지터로 계속 |
| `code` | `auth_code`, `code_expires_at` | 즉시 한 번만 `/token?grant_type=pkce` 교환 |
| `code_expired` | — | 교환 전이면 실패 처리(새 요청) |
| `completed` | — | 이미 완료 |
| `expired` / `cancelled` / `failed` | `reason`(선택: oauth, browser, device, oauth_error, code_expired) | 중단, 대기 정보 삭제 |

응답이 유실되면 **같은 `delivery_key`**로 다시 poll해 같은 코드를 받는다(코드 유효기간 안). 교환 요청 자체가 실패했다면 코드를 다시 교환하지 말고 새 요청을 시작한다.

### 5.4 `complete` (원래 기기)

헤더 `Authorization: Bearer <이번에 교환한 access_token>`, 본문 `{ "protocol": 1, "request_id", "device_secret" }`.
- 중계는 Supabase Auth `/auth/v1/user`로 토큰을 검증하고, `sub`·`iss`·`aud`·`role`·`session_id`·`iat`를 확인한다. `iat`가 요청 생성보다 60초 이상 이르면 거부.
- 본문에 `user_id` 등을 넣으면 400. 사용자 식별은 검증된 JWT에서만.
- 성공: `{ "protocol": 1, "phase": "device_confirmed" }`. 같은 세션으로 재시도하면 멱등 성공.
- **반드시 세션을 원자적으로 저장하고 사용자가 원래 앱에서 계정을 확인한 뒤** 호출한다.

### 5.5 `cancel`

`{ "protocol": 1, "request_id", "actor": "device", "secret": "<device_secret>" }` → `{ "phase": "cancelled" }`.
완료 후에는 409 `already_completed`. 이미 종료된 요청은 그 phase를 그대로 반환(멱등).

## 6. 원래 기기(PC/Docker 서버)의 Supabase Auth 호출

모든 호출에 `apikey: <publishable key>` 헤더. 확인 기준: GoTrue v2.197.0.

| 목적 | 요청 | 비고 |
|---|---|---|
| 코드 교환 | `POST /auth/v1/token?grant_type=pkce` `{ "auth_code", "code_verifier" }` | 성공 200: `access_token`, `refresh_token`, `expires_in`, `expires_at`, `user`. 잘못된 verifier 400 `bad_code_verifier`, 재사용 404 `flow_state_not_found`, 만료 422 `flow_state_expired` |
| 사용자 확인 | `GET /auth/v1/user` + `Authorization: Bearer <access>` | `id`(UUID, 영구 식별자), `user_metadata`(닉네임 등 표시용), `email`(없을 수 있음) |
| 갱신 | `POST /auth/v1/token?grant_type=refresh_token` `{ "refresh_token" }` | **회전됨**: 새 access+refresh를 함께 원자 저장. 동시 갱신 금지(프로세스 락). 400 `refresh_token_not_found` / `refresh_token_already_used` / `session_not_found` / `session_expired` → “다시 로그인 필요”. 네트워크/5xx → 기존 세션 유지 후 재시도 |
| 연결 해제 | `POST /auth/v1/logout?scope=local` + `Authorization: Bearer <access>` | **scope 생략 시 global(모든 기기 로그아웃)** 이므로 항상 `scope=local` |

## 7. 원래 기기 흐름 요약

1. verifier·challenge·device_secret·delivery_key를 새로 만들고 대기 정보(verifier 포함)를 암호화 저장.
2. `requests` → 비교코드·연결 링크를 로컬 관리자 화면에 표시(링크는 1회용·공유 금지 안내).
3. 5초 간격 `poll`(지터, 429 준수, 전체 만료까지만). 중앙이 사용자의 서버에 접속하지 않는다.
4. `code`를 받으면 즉시 교환 → `/user`로 계정 확인 → 대기 세션으로 암호화 저장 → 화면에 “계정 확인 필요”.
5. 사용자가 “이 계정으로 연결” → 대기 세션을 현재 세션으로 원자 교체 → `complete`(네트워크 오류면 같은 토큰으로 재시도, 코드 재교환 금지).
6. 사용자가 거부 → 대기 세션 `logout?scope=local` 후 삭제, `cancel`. 기존 연결은 그대로.
7. 만료·취소·실패 → 대기 정보 삭제.
