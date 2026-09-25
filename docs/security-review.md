# safeauth 보안 검토 기록

범위: 이 저장소의 중앙 페이지(`site/`), relay(`server/`, Edge 함수, migration),
배포 워크플로. 앱 쪽(safetyreport, mobile) 검토는 각 저장소 문서와 `acceptance.md`를 본다.
검토자는 구현자와 같다(자기 검토). 운영 전 독립 검토를 권한다.

## 1. 핵심 보장과 근거

| 보장 | 구현 | 검증 |
|---|---|---|
| 중앙 브라우저는 PC/Docker용 코드를 교환하지 않는다 | 중앙 번들에 Supabase 세션 클라이언트 없음. `/auth/v1/token` 호출 코드 없음 | 브라우저 E2E: 페이지 발 `/auth/v1/token` 요청 0건 (P02) |
| verifier·refresh token·서버 비밀이 URL/프런트/다른 기기로 가지 않는다 | challenge만 relay로, 토큰은 원래 기기만 | P01, S14 (DB 행·relay 로그에 비밀 원문 없음), 아티팩트 비밀 스캔 |
| 사용자별 도메인 허용/CORS를 인증으로 쓰지 않는다 | Redirect URL은 고정 2개. 모든 액션은 목적별 capability | S01–S05, S17 |
| 원래 기기 저장 확인 전 완료 표시 없음 | `device_confirmed`는 `/complete`(검증된 JWT + device secret)로만 | E2E: 코드 전달·교환 후에도 “원래 기기에서 계정을 확인해 주세요” 유지, complete 후에만 완료 |
| 기존 로그인 대체·공개 동의 자동 처리 없음 | relay는 contributor_profiles를 쓰지 않음. 앱 기능 기본 OFF | migration 검토, S13 |
| 광고·분석·SPA router·지도 앱 미로딩 | 독립 MPA, 허용 목록 아티팩트, CSP `script-src 'self'` | verify-artifact, E2E 요청 호스트 = 사이트·relay·카카오(모의)뿐 |
| 인증 페이지 전용 origin | `safeauth.worklazy.net` 전용 Pages 사이트 | 이 문서 §3 |

## 2. 위협과 대응

- **링크 탈취(ticket)**: fragment로만 전달되어 서버 로그·Referer에 남지 않는다. 첫 claim에 브라우저 비밀로 묶이고,
  다른 브라우저는 `already_claimed`. 생성 재시도 시 이전 ticket은 무효. 수명 10분.
- **피싱(남이 보낸 요청 승인)**: 비교코드와 “본인이 시작한 요청” 확인, 원래 앱에서 최종 계정 확인. 완전 방지는 아니다
  (사용자가 확인 없이 승인하면 공격자 기기가 세션을 얻는다). 화면에 경고를 둔다.
- **코드 가로채기**: 코드 단독으로는 무용(PKCE, verifier는 원래 기기). relay 보관 시 AES-256-GCM(AAD=request id), 120초, 1명 수령자 pin.
- **relay 무차별 대입**: request id만으로 불가(모든 비밀 256비트), 존재/비밀 불일치 구분 없는 404, DB 기반 rate limit(인스턴스 간 공유 S12).
- **상태 경쟁**: 모든 전이는 `select … for update` 한 트랜잭션. 동시 claim/poll 테스트(S08).
- **JWT 위조**: `/complete`는 Supabase Auth `/user`로 검증 후 `sub/iss/aud/role/session_id/iat` 확인, 본문의 사용자 식별값 거부(S06).
- **설정 실수**: pepper/키 누락·placeholder·저엔트로피·동일값, 경로가 붙은 origin, http, TTL>Auth flow → 전체 503(S15, 단위 테스트).
  공개 빌드는 secret key를 거부한다.
- **Redirect allowlist 누락**: Supabase Auth가 Site URL로 조용히 보낸다(P05b). 코드만으로는 무용이지만 사용자에게는 실패로 보인다 → 배포 점검 필수.
- **클릭재킹**: meta CSP는 `frame-ancestors`를 지원하지 않고 GitHub Pages는 응답 헤더를 설정할 수 없다. 대신 스크립트가
  프레임 안에서는 동작을 거부한다(E2E 확인). 헤더 수준 보장은 없음 → 잔여 위험.
- **XSS**: 서버 제공 문자열은 textContent로만, 기기명은 relay에서 제어문자·마크업 문자·URL 스킴 거부, CSP로 인라인 스크립트 차단.

## 3. 별도 서브도메인 (2026-09-25 변경)

중앙 페이지는 `https://safeauth.worklazy.net`이라는 **별도 origin**이다. `worklazy.net`(WorklazyTools)과
`safemap.worklazy.net`(지도, 카카오 지도 SDK 등 외부 스크립트 포함)의 스크립트는 이 origin의 sessionStorage·DOM에
접근할 수 없고, WorklazyTools의 루트 서비스워커도 이 주소를 제어하지 않는다. 이전의 “같은 origin” 잔여 위험은 해소됐다.

남는 것:
- 같은 상위 도메인(same-site)이다. `worklazy.net`이 `Domain=worklazy.net` 쿠키를 설정하면 이 주소로도 전송되지만,
  중앙 페이지는 쿠키를 쓰지 않고 relay 호출은 `credentials: 'omit'`이다.
- 서브도메인 탈취: DNS CNAME이 남은 채 Pages 설정이 사라지면 제3자가 그 이름을 가져갈 수 있다. GitHub의 Verified domains로
  `worklazy.net`을 인증해 두고, 서비스를 내릴 때 DNS부터 지운다.
- `safemap.worklazy.net`(community-map 저장소)과 코드·번들·origin을 공유하지 않는다.

## 4. 헤더와 호스팅

GitHub Pages는 사용자 정의 응답 헤더를 지원하지 않는다. 따라서 CSP는 meta로만(프레임 금지 불가), HSTS·X-Frame-Options
등은 호스팅 기본값에 따른다. 배포 후 실제 응답 헤더는 확인하지 않았다(미배포). GitHub Pages 이용 정책상 민감 거래 서비스에 대한
제약이 있으므로 운영 판단이 필요하다(kit S14).

## 5. 확인하지 못한 것

- 실제 카카오 로그인·hosted Supabase(프로젝트 설정, 비대칭 JWT 서명 키 사용 여부에 따른 issuer 등) — 로컬은 HS256 GoTrue.
- 실제 safeauth.worklazy.net 응답 헤더(미배포).
- 독립 보안 검토, 스크린리더 수동 검수.
