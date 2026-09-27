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
// Deletion requests and questions go to the map repository's public Issues (user decision 2026-09-27).
export const COMMUNITY_ISSUES_URL = 'https://github.com/Fentanest/safetyreport-community-map/issues';
for (const node of document.querySelectorAll('.issues-link')) {
  const a = document.createElement('a');
  a.href = COMMUNITY_ISSUES_URL;
  a.rel = 'noopener noreferrer';
  a.target = '_blank';
  a.textContent = node.textContent;
  node.replaceChildren(a);
}
// Without a configured contact the page keeps its built-in text (pointing to the Issues above).
const contactNode = document.getElementById('operator-contact');
if (contactNode && typeof contact === 'string' && contact.trim()) {
  contactNode.textContent = contact.trim();
}
