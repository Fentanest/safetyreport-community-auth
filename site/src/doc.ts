// Entry for help.html and privacy.html: theme toggle plus build-time operator fields.
import './styles/tokens.css';
import './styles/ui.css';
import { initTheme } from './common.ts';

initTheme();

const policy = import.meta.env.SAFEAUTH_PUBLIC_PRIVACY_POLICY_URL;
const contact = import.meta.env.SAFEAUTH_PUBLIC_OPERATOR_CONTACT;
const policyNode = document.getElementById('policy-link');
if (policyNode) {
  if (typeof policy === 'string' && /^https:\/\//.test(policy)) {
    const a = document.createElement('a');
    a.href = policy;
    a.rel = 'noopener noreferrer';
    a.target = '_blank';
    a.textContent = '나만의 안전신문고 개인정보처리방침';
    policyNode.replaceChildren(a);
  } else {
    policyNode.textContent = '운영자가 아직 게시 위치를 설정하지 않았습니다.';
  }
}
const contactNode = document.getElementById('operator-contact');
if (contactNode) {
  contactNode.textContent = typeof contact === 'string' && contact.trim()
    ? contact.trim()
    : '개인정보처리방침에 적힌 문의처를 이용해 주세요.';
}
