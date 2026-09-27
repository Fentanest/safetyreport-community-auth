-- Consent text served by the central server (user decision 2026-09-27).
-- Apps no longer carry the consent text or its hash: they fetch the current policy (version, hash, text) with the
-- `policy` action, check that the text hashes to the stated hash, show exactly that text and consent with that hash.
-- Every text a policy has ever pointed to is kept here (immutable), so the text behind any grant's hash can be read back.
-- Owner: safetyreport-community-auth. Depends on 202609260100, 202609280200, 202609280400.
--
-- 2026-09-28.1 is still in testing, so its text is replaced in place again (user decision: no version bump until the
-- service opens). The previous text stays in community_policy_texts; grants made on it no longer match the current
-- policy (community_grant_is_current compares the hash), so their status becomes 'outdated' and the app asks again.
-- Once the service opens, a wording change must be a new version instead of an in-place replacement.

begin;

create table private.community_policy_texts (
    consent_text_sha256 text primary key check (consent_text_sha256 ~ '^[0-9a-f]{64}$'),
    consent_text text not null check (length(consent_text) between 1 and 65536),
    created_at timestamptz not null default now(),
    constraint community_policy_texts_hash_matches
        check (encode(pg_catalog.sha256(pg_catalog.convert_to(consent_text, 'UTF8')), 'hex') = consent_text_sha256)
);

create or replace function private.community_policy_texts_immutable()
returns trigger language plpgsql set search_path = '' as $$
begin
    raise exception 'COMMUNITY_POLICY_TEXT_IMMUTABLE';
end;
$$;
create trigger community_policy_texts_no_update before update or delete on private.community_policy_texts
for each row execute function private.community_policy_texts_immutable();

alter table private.community_policy_texts enable row level security;
revoke all on private.community_policy_texts from public, anon, authenticated;
grant select, insert on private.community_policy_texts to service_role;
revoke all on function private.community_policy_texts_immutable() from public, anon, authenticated;

-- 2026-09-26.1
insert into private.community_policy_texts(consent_text_sha256, consent_text) values (
'818703977dbf1596a82df8ff68408d0907280adbda7ce2140879a2ab5fd6a6fa',
$consent_text$# [필수] 신고내용 공유 동의 (정책 버전 2026-09-26.1)

나만의 안전신문고(PC·Docker 서버, 모바일 앱)는 커뮤니티 신고 지도(https://safemap.worklazy.net/)에 신고 처리 결과를 공유합니다.
이 동의는 카카오 로그인과 별개입니다. 동의하지 않으면 앱의 일반 기능을 사용할 수 없습니다.

## 무엇을 보내나요
안전신문고에서 **답변이 완료된** 내 신고를 수집할 때, 내가 앱에서 고치기 전의 원래 값으로 아래 항목을 보냅니다.
- 신고일, 처리완료일(답변일), 신고 분야(교통위반·주정차·기타), 처리 상태(수용·일부수용·불수용 등)와 처분 구분
- 답변에 적힌 과태료·범칙금 금액과 벌점(적혀 있을 때만, 추정 금액은 보내지 않음)
- 처리 기관 이름과 담당자 이름
- 위반 장소 주소와 그 주소로 계산한 좌표
- 차량번호
- 안전신문고 신고 식별번호(중앙에서 중복을 막는 데만 쓰고 공개하지 않음)
사진·첨부파일·신고 본문·처리 내용 원문, 안전신문고 아이디·비밀번호·로그인 정보는 보내지 않습니다.
답변 완료 뒤 공식 상태가 취하·이송·재처리 등으로 바뀐 것을 앱이 확인하면 그 변경도 보냅니다.

## 무엇이 공개되나요
지도와 통계에 누구나 로그인 없이 볼 수 있게 공개됩니다.
- 정확한 좌표와 주소, 처리 기관과 **담당자 전체 이름**, 처리 결과·처분, 신고일·처리완료일
- 차량번호는 지역명을 남기고 뒤 번호 일부를 가린 형태로만 공개(예: 경기76자3623 → 경기7*자*6*3)
- 표본이 1건이어도 공개됩니다.
공개되지 않는 것: 내 카카오 계정 정보, 원래 차량번호, 안전신문고 신고번호, 기기 정보.
가린 차량번호·좌표·주소를 함께 보면 신고를 특정할 수 있을 수 있으며, 이 공개가 법적 익명성을 보장하지는 않습니다.

## 언제 보내나요
- 신고를 수집한 직후 바로
- 앱의 신고 지도 탭에서 "지금 업로드"를 누를 때
- 매일 00:00(한국 시간) 자동으로. 앱 종료·절전·네트워크 상태에 따라 늦어질 수 있으며 다음 실행 기회에 이어서 보냅니다.
이미 수집한 사본만 보내며, 업로드 때문에 안전신문고에 추가 조회를 하지 않습니다.

## 철회와 삭제
- 언제든 설정에서 동의를 철회할 수 있습니다. 철회하면 즉시 이 필수 설정 화면으로 돌아가고, 이 동의로 보낸 자료는 공개 지도에서 빠집니다.
- 다시 동의해도 이전에 보낸 자료가 자동으로 다시 공개되지 않습니다. 원하면 신고 지도 탭에서 "이전 수집 사본 다시 공유"를 직접 눌러야 합니다.
- 이미 보낸 자료의 삭제를 따로 요청할 수 있습니다. 삭제하면 공개 지도와 통계에서 제거되며, 삭제 전에 수집한 사본은 다시 올릴 수 없습니다. 운영 기록(비공개)은 최대 30일 보관 후 정리합니다.
- 안내 문서가 바뀌어 새 버전에 다시 동의하는 경우에는 이미 보낸 자료가 계속 공개됩니다(철회와 다릅니다).
- 로그아웃·기기 연결 해제는 동의 철회와 다릅니다.

## 운영
운영: 나만의 안전신문고 커뮤니티(Fentanest). 문의와 개인정보 처리 안내는 https://safeauth.worklazy.net/privacy.html 를 따릅니다.
$consent_text$);

-- 2026-09-28.1 as published on 2026-09-27 (hash from 202609280400)
insert into private.community_policy_texts(consent_text_sha256, consent_text) values (
'a775cc34a175ac880574976b011f2c16cce3b0d366aa7729c2128cd1f1f38670',
$consent_text$# [필수] 신고내용 공유 동의 (정책 버전 2026-09-28.1)

나만의 안전신문고(PC·Docker 서버, 모바일 앱)는 커뮤니티 신고 지도(https://safemap.worklazy.net/)에 신고 처리 결과를 공유합니다.
이 동의는 카카오 로그인과 별개입니다. 동의하지 않으면 앱의 일반 기능을 사용할 수 없습니다.

## 무엇을 보내나요
안전신문고에서 **답변이 완료된** 내 신고를 수집할 때, 내가 앱에서 고치기 전의 원래 값으로 아래 항목을 보냅니다.
- 신고일, 처리완료일(답변일), 신고 분야(교통위반·주정차·기타), 처리 상태(수용·일부수용·불수용 등)와 처분 구분
- 답변에 적힌 과태료·범칙금 금액과 벌점(적혀 있을 때만, 추정 금액은 보내지 않음)
- 처리 기관 이름과 담당자 이름
- 위반 장소 주소와 그 주소로 계산한 좌표
- 차량번호
- 안전신문고 신고 식별번호(중앙에서 중복을 막는 데만 쓰고 공개하지 않음)
사진·첨부파일·신고 본문·처리 내용 원문, 안전신문고 아이디·비밀번호·로그인 정보는 보내지 않습니다.
답변 완료 뒤 공식 상태가 취하·이송·재처리 등으로 바뀐 것을 앱이 확인하면 그 변경도 보냅니다.

## 무엇이 공개되나요
지도와 통계에 누구나 로그인 없이 볼 수 있게 공개됩니다.
- 정확한 좌표와 주소, 처리 기관과 **담당자 전체 이름**, 처리 결과·처분, 신고일·처리완료일
- 답변에 적힌 과태료 금액의 통계(합계·평균·중앙값, 기간·지역·기관·담당자별). 신고 한 건의 금액을 따로 보여 주지는 않지만, 한 조건에 신고가 1건뿐이면 그 통계가 곧 그 신고의 금액입니다. 범칙금·벌점은 공개하지 않습니다.
- 차량번호는 지역명을 남기고 뒤 번호 일부를 가린 형태로만 공개(예: 경기76자3623 → 경기7*자*6*3)
- 표본이 1건이어도 공개됩니다.
공개되지 않는 것: 내 카카오 계정 정보, 원래 차량번호, 안전신문고 신고번호, 기기 정보.
가린 차량번호·좌표·주소를 함께 보면 신고를 특정할 수 있을 수 있으며, 이 공개가 법적 익명성을 보장하지는 않습니다.

## 언제 보내나요
- 신고를 수집한 직후 바로
- 앱의 신고 지도 탭에서 "지금 업로드"를 누를 때
- 매일 00:00(한국 시간) 자동으로. 앱 종료·절전·네트워크 상태에 따라 늦어질 수 있으며 다음 실행 기회에 이어서 보냅니다.
이미 수집한 사본만 보내며, 업로드 때문에 안전신문고에 추가 조회를 하지 않습니다.

## 철회와 삭제
- 언제든 설정에서 동의를 철회할 수 있습니다. 철회하면 즉시 이 필수 설정 화면으로 돌아가고, 이 동의로 보낸 자료는 공개 지도에서 빠집니다.
- 다시 동의해도 이전에 보낸 자료가 자동으로 다시 공개되지 않습니다. 원하면 신고 지도 탭에서 "이전 수집 사본 다시 공유"를 직접 눌러야 합니다.
- 이미 보낸 자료의 삭제는 https://github.com/Fentanest/safetyreport-community-map/issues 에 요청할 수 있습니다. 이 게시판은 누구나 볼 수 있으니 카카오 계정·차량번호·신고번호 같은 개인정보는 적지 말고 삭제를 원한다는 것만 남겨 주세요. 본인 확인 방법은 운영자가 따로 안내합니다. 삭제하면 공개 지도와 통계에서 제거되며, 삭제 전에 수집한 사본은 다시 올릴 수 없습니다. 운영 기록(비공개)은 최대 30일 보관 후 정리합니다.
- 안내 문서가 바뀌어 새 버전에 다시 동의하는 경우에는 이미 보낸 자료가 계속 공개됩니다(철회와 다릅니다).
- 이 버전(2026-09-28.1)에 동의하면 이전 버전으로 보낸 자료의 과태료 금액도 위 통계에 들어갑니다. 이전 버전 동의만으로는 금액이 공개되지 않습니다.
- 로그아웃·기기 연결 해제는 동의 철회와 다릅니다.

## 운영
운영: 나만의 안전신문고 커뮤니티(Fentanest). 문의는 https://github.com/Fentanest/safetyreport-community-map/issues 로 해 주세요(공개 게시판이므로 개인정보는 적지 마세요). 계정 연결에서 처리하는 정보는 https://safeauth.worklazy.net/privacy.html 에 있습니다.
$consent_text$);

-- 2026-09-28.1 wording edited by the operator on 2026-09-27 (in testing)
insert into private.community_policy_texts(consent_text_sha256, consent_text) values (
'ce460475fb45281ed539af4c01c765adee4d822201891ee058fc66955aba00c3',
$consent_text$# [필수] 신고 결과 공유 동의
정책 버전: 2026-09-28.1

나만의 안전신문고는 **답변이 완료된 신고의 장소와 처리 결과**를 모아, [커뮤니티 신고 지도](https://safemap.worklazy.net/)에서 지역별 신고 현황과 처리 사례를 함께 살펴볼 수 있도록 합니다.

**현재 지도와 통계는 신고 결과를 제공한 이용자만 카카오 로그인 후 볼 수 있습니다.** 사진이나 신고 글 전체를 공유하는 기능은 아닙니다.

이 동의는 PC·서버·모바일 앱에 공통으로 적용되며, 카카오 로그인 동의와는 별개입니다. **앱의 일반 기능을 이용하려면 신고 결과 공유에 동의해야 합니다.**

## 다른 이용자에게 어떤 정보가 보이나요?

동의 후 앱에서 가져오는 **답변 완료 신고**의 다음 정보가 자동으로 공유됩니다.

| 구분 | 다른 이용자에게 보이는 내용 |
| --- | --- |
| 신고와 처리 결과 | 신고일, 답변 완료일, 신고 분야, 수용·일부수용·불수용 등의 처리 결과와 처분 종류 |
| 처리 기관과 담당자 | 신고를 처리한 기관 이름과 해당 기관 담당자의 전체 이름 |
| 신고 장소 | 위반 장소의 주소와 지도상의 상세 위치 |
| 차량번호 | 지역명은 남기고 나머지 번호 일부를 가린 형태. 예: `경기76자3623` → `경기7*자*6*3` |
| 과태료 통계 | 답변에 적힌 과태료 금액을 바탕으로 한 기간·지역·기관·담당자별 합계·평균 등의 통계 |

과태료 금액은 개별 신고 화면에 표시하지 않고 통계에 반영합니다. 앱에서 추정한 금액은 사용하지 않습니다.

공유 정보는 안전신문고에서 가져온 원래 내용을 기준으로 하며, 앱에서 따로 수정한 내용은 공유에 반영되지 않습니다. 이후 처리 결과가 변경된 것을 앱에서 확인하면 지도에도 반영됩니다.

장소와 차량번호 일부가 함께 표시되므로, 이를 통해 어떤 신고인지 알아볼 가능성은 있습니다.

## 공유하지 않는 정보도 있나요?

**사진·첨부파일·신고 글·처리 답변 원문은 지도 서비스로 보내지 않습니다.** 안전신문고 아이디·비밀번호 등 로그인 정보도 보내지 않습니다.

전체 차량번호와 안전신문고 신고번호, 답변에 적힌 범칙금·벌점은 지도 서비스에 전달되지만 **다른 이용자에게는 표시되지 않습니다.**

내 카카오 계정 정보와 기기 정보 역시 다른 이용자에게 보이지 않습니다.

## 공유를 중단하고 싶어요

설정에서 언제든 동의를 철회할 수 있습니다.

철회하면 **이 동의로 공유한 자료가 지도에서 내려가며**, 앱은 동의 화면으로 돌아갑니다. 다시 동의하기 전까지는 앱의 일반 기능을 이용할 수 없습니다.

다시 동의하더라도 이전 자료가 자동으로 다시 공개되지는 않습니다. 이전 자료도 다시 공유할지는 신고 지도 탭에서 직접 선택할 수 있습니다.

로그아웃하거나 기기 연결을 해제하는 것만으로는 동의가 철회되지 않습니다.

## 이미 보낸 자료를 삭제하고 싶어요

[문의 게시판](https://github.com/Fentanest/safetyreport-community-map/issues)에 **“공유한 자료를 삭제하고 싶습니다”**라고 남겨 주세요. 본인 확인 방법은 운영자가 별도로 안내합니다.

이 게시판은 누구나 볼 수 있으므로, **카카오 계정·차량번호·신고번호 등 개인정보는 적지 말아 주세요.**

삭제한 자료는 지도와 통계에서 제거되며, 삭제 전에 앱에 저장해 둔 같은 자료는 다시 공유할 수 없습니다. 비공개 운영 기록은 최대 30일 보관한 뒤 정리합니다.

## 이번 동의가 기존 자료에도 적용되나요?

**이번 버전에 동의하면 이전에 공유한 신고의 과태료 금액도 위 통계에 포함됩니다.** 이전 버전에만 동의한 경우에는 금액이 공개되지 않습니다.

안내문이 바뀌어 새 버전에 다시 동의하는 경우에는 기존 공유 자료가 유지됩니다. 이는 공유를 중단하는 동의 철회와는 다릅니다.

## 운영 및 문의

운영: 나만의 안전신문고 커뮤니티(Fentanest)

문의는 [문의 게시판](https://github.com/Fentanest/safetyreport-community-map/issues)을 이용해 주세요. 공개 게시판이므로 개인정보는 남기지 말아 주세요.

카카오 계정 연결 과정에서 처리하는 정보는 [계정 연결 개인정보 안내](https://safeauth.worklazy.net/privacy.html)에서 확인할 수 있습니다.$consent_text$);

alter table private.community_policies disable trigger community_policies_no_update;
update private.community_policies
   set consent_text_sha256 = 'ce460475fb45281ed539af4c01c765adee4d822201891ee058fc66955aba00c3'
 where version = '2026-09-28.1';
alter table private.community_policies enable trigger community_policies_no_update;

-- A policy row must have its text here before it becomes current. There is no foreign key (test fixtures insert
-- policy rows with placeholder hashes); instead `internal_account_policy` fails closed when the current policy has
-- no text, so no app can show or consent to an unknown wording.

-- Current policy with its text, for the `policy` action.
create or replace function public.internal_account_policy()
returns jsonb language plpgsql volatile security definer set search_path = '' as $$
declare
    v_policy private.community_policies%rowtype := private.community_current_policy(false);
    v_text text;
begin
    select t.consent_text into v_text from private.community_policy_texts t
     where t.consent_text_sha256 = v_policy.consent_text_sha256;
    if v_text is null then
        return jsonb_build_object('error', 'server_error');
    end if;
    return jsonb_build_object('policy', jsonb_build_object(
        'version', v_policy.version,
        'consent_text_sha256', v_policy.consent_text_sha256,
        'consent_text', v_text));
end;
$$;
revoke all on function public.internal_account_policy() from public, anon, authenticated;
grant execute on function public.internal_account_policy() to service_role;

commit;
