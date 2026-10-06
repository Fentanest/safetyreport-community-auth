# community-account 공식 계정 바인딩

정본은 map 레포 `contracts/community-ingest/account-api.md`이다.



카카오 사용자 1명 ↔ 공식 안전신문고 dataset 1개. `dataset_key` 알고리즘은 그대로이며,
서버는 ID 원문을 저장하지 않는다. `connections` 성공과 바인딩 생성은 같은 트랜잭션이다.
같은 사용자의 같은 dataset 재등록에는 기존 writer 충돌·takeover 규칙을 적용한다.
`takeover:true`도 다른 사용자 바인딩이나 본인의 다른 dataset 바인딩을 덮지 못한다.

| 오류 코드 | HTTP / retryable | message (정확한 서버 문구) |
|---|---|---|
| `official_account_mismatch` | 409 / false | `This community account is bound to another official account. Delete shared reports before changing accounts.` |
| `official_account_taken` | 409 / false | `This official account is already bound. Please contact an operator (운영자에게 문의해 주세요).` |

mismatch 응답의 `error.bound_dataset_key`는 본인의 바인딩만 반환한다. taken은 상대 사용자·연결·dataset 정보를 추가하지 않는다.
`status.official_account`는 요청자 자신의 `{dataset_key,bound_at}`이며 미바인딩은 두 값 모두 JSON null이다.
동의 철회·연결 철회·로그아웃은 바인딩을 해제하지 않는다. 공식 계정 변경은 기존
`contributions-delete` 성공(`official_account_released:true`) 이후 새 `connections`로 진행한다.
운영자 함수·감사·backfill·적용 순서는 `docs/implementation/official-account-binding-20261006/MIGRATION.md` 참조.

안신 계정은 클라이언트 DB에 저장하지 않는다. 서버 바인딩을 정본으로 삼고, 클라이언트는 시작·복귀·약 5분마다
현재 로그인 설정에서 계산한 dataset_key와 status의 바인딩을 대조한다. 불일치 시 로그인 설정에서
계정을 맞추거나 경고→개인 DB 백업→초기화→새 시작 절차를 완료해야 한다. 연결 실패 시 클라우드 접속 불가
화면, 20~30초 타임아웃·증가 간격 자동 재시도·수동 재시도를 제공한다. 이 서버 변경에는 클라이언트 UI 구현이 포함되지 않는다.


status: `official_account: {dataset_key: string|null, bound_at: string|null}`.
삭제 응답: `official_account_released: true`.
[적용·운영·롤백](implementation/official-account-binding-20261006/MIGRATION.md).

운영자 수동 선점 해제는 선점자의 해당 dataset 공유 fact 삭제·identity tombstone·사용자/dataset 삭제 fence·
해당 dataset 연결 폐기·바인딩 해제를 원자적으로 수행한다. 삭제 건수와 운영자/사유/시각은 private 감사에 남긴다.
삭제 증거는 선점자 사용자 범위이므로 진짜 주인은 같은 dataset과 같은 신고를 새로 연결·업로드할 수 있다.
