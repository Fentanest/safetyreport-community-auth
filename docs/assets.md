# safeauth 에셋 출처

| 파일 | 출처 | 확인 |
|---|---|---|
| `site/public/kakao/kakao_login_kr_medium.svg` | 카카오 디벨로퍼스 디자인 리소스 “카카오 로그인” 전체 다운로드 (`https://developers.kakao.com/tool/resource/login` → `Kakao Login.zip`, 경로 `Kakao Login/SVG/kakao_login_kr_medium.svg`) | 2026-09-25 다운로드. ZIP SHA-256 `7664a07cdd88ac5219282a4580571a169683468e2efc06c8a962dd87068b5600`, SVG SHA-256 `ab90ab44616f14a671844cd991b3fbb33277f42c5bb2cc5a9422344a854c9398`. 스크립트·외부 참조 없음 |

사용 방식: 완성형(심볼+“카카오 로그인” 라벨) 224×46 SVG를 원본 비율 그대로 표시한다. 버튼 컨테이너는 카카오 노랑
`#FEE500`, 높이 52px로 터치 영역만 넓힌다. 확인란을 선택하기 전(비활성)에는 공식 에셋을 쓰지 않고 중립 회색 텍스트 버튼을
보여 준다 — 브랜드 색을 흐리게 바꾸지 않기 위해서다. 다크 모드에서도 색을 바꾸지 않는다.
런타임 핫링크 없이 같은 origin에서 제공한다. `scripts/verify-artifact.mjs`가 배포 전 해시를 확인한다.

카카오 로그인 디자인 가이드(`https://developers.kakao.com/docs/ko/kakaologin/design-guide`)의 최신 조항을 운영 전 다시 확인한다.

폰트 파일·AI 생성 이미지·정부 로고는 포함하지 않는다. 브랜드는 텍스트 워드마크다.
