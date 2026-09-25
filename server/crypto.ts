// WebCrypto helpers shared by the Edge relay (Deno), Node tests and the browser.
// No custom primitives: HMAC-SHA-256 for purpose-bound digests, AES-256-GCM for the
// short-lived auth code, crypto.getRandomValues for every secret.

import { DISPLAY_CODE_ALPHABET } from './protocol.ts';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new Error('invalid base64url');
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

export function randomSecret(bytes = 32): string {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(bytes)));
}

export function randomDisplayCode(): string {
  // Rejection sampling keeps the 31-letter alphabet uniform.
  const out: string[] = [];
  const limit = 256 - (256 % DISPLAY_CODE_ALPHABET.length);
  while (out.length < 8) {
    for (const byte of crypto.getRandomValues(new Uint8Array(16))) {
      if (byte < limit && out.length < 8) out.push(DISPLAY_CODE_ALPHABET[byte % DISPLAY_CODE_ALPHABET.length]);
    }
  }
  return `${out.slice(0, 4).join('')}-${out.slice(4).join('')}`;
}

export async function s256Challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(verifier));
  return base64UrlEncode(new Uint8Array(digest));
}

function toHex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
}

export class Hasher {
  private readonly key: CryptoKey;
  private constructor(key: CryptoKey) { this.key = key; }

  static async create(pepper: Uint8Array<ArrayBuffer>): Promise<Hasher> {
    const key = await crypto.subtle.importKey('raw', pepper, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Hasher(key);
  }

  // Digest format is fixed: "safeauth|v1|<purpose>|<scope>|<value>". Purposes never
  // overlap, so a browser secret digest can never satisfy a device check.
  async digest(purpose: string, scope: string, value: string): Promise<string> {
    const message = `safeauth|v1|${purpose}|${scope}|${value}`;
    return toHex(await crypto.subtle.sign('HMAC', this.key, encoder.encode(message)));
  }
}

export interface CodeKey { id: string; key: CryptoKey }

export async function importCodeKey(raw: Uint8Array<ArrayBuffer>): Promise<CodeKey> {
  if (raw.length !== 32) throw new Error('code key must be 32 bytes');
  const id = toHex(await crypto.subtle.digest('SHA-256', raw)).slice(0, 12);
  const key = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  return { id, key };
}

// Envelope: "v1.<key id>.<iv>.<ciphertext+tag>", AAD binds it to one request.
export async function sealCode(codeKey: CodeKey, requestId: string, code: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = encoder.encode(`safeauth|v1|code|${requestId}`);
  const sealed = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, codeKey.key, encoder.encode(code));
  return `v1.${codeKey.id}.${base64UrlEncode(iv)}.${base64UrlEncode(new Uint8Array(sealed))}`;
}

export async function openCode(keys: CodeKey[], requestId: string, envelope: string): Promise<string> {
  const parts = envelope.split('.');
  if (parts.length !== 4 || parts[0] !== 'v1') throw new Error('bad envelope');
  const codeKey = keys.find(k => k.id === parts[1]);
  if (!codeKey) throw new Error('unknown key id');
  const aad = encoder.encode(`safeauth|v1|code|${requestId}`);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64UrlDecode(parts[2]), additionalData: aad },
    codeKey.key,
    base64UrlDecode(parts[3]),
  );
  return decoder.decode(plain);
}

export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const value = JSON.parse(decoder.decode(base64UrlDecode(parts[1])));
    return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}
