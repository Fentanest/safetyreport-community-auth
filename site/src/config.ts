// Public, build-time configuration. Nothing here is secret. The relay endpoint and
// callback are derived from these values only; URL parameters can never change them.
import { RELAY_FUNCTION_NAME } from '../../server/protocol.ts';

export interface PublicConfig {
  siteUrl: string;          // https://safeauth.worklazy.net/
  callbackUrl: string;      // https://safeauth.worklazy.net/callback.html
  supabaseUrl: string;      // https://<ref>.supabase.co (origin only)
  relayBase: string;        // <supabaseUrl>/functions/v1/community-auth-relay
  publishableKey: string | null;
  privacyPolicyUrl: string | null;
  operatorContact: string | null;
}

export type ConfigState = { ok: true; config: PublicConfig } | { ok: false; code: 'AUTH_CONFIG_MISSING' | 'AUTH_CONFIG_LOCATION' };

function origin(value: string | undefined, allowLoopback: boolean): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (url.pathname !== '/' || url.search || url.hash || url.username) return null;
    if (url.protocol === 'https:' || (allowLoopback && url.protocol === 'http:' && url.hostname === '127.0.0.1')) return url.origin;
  } catch { /* invalid */ }
  return null;
}

export function readConfig(location: Location = window.location): ConfigState {
  const env = import.meta.env;
  const loopback = env.MODE === 'localtest';
  const siteUrl = String(env.SAFEAUTH_PUBLIC_SITE_URL ?? '');
  if (!siteUrl) return { ok: false, code: 'AUTH_CONFIG_MISSING' };
  const supabaseUrl = origin(env.SAFEAUTH_PUBLIC_SUPABASE_URL, loopback);
  if (!supabaseUrl) return { ok: false, code: 'AUTH_CONFIG_MISSING' };
  // The page must actually be served from the configured site; a copy on another
  // host or path would send users to a callback it does not own.
  const here = `${location.origin}${location.pathname}`;
  if (!here.startsWith(siteUrl)) return { ok: false, code: 'AUTH_CONFIG_LOCATION' };
  const key = env.SAFEAUTH_PUBLIC_PUBLISHABLE_KEY ? String(env.SAFEAUTH_PUBLIC_PUBLISHABLE_KEY) : null;
  return {
    ok: true,
    config: {
      siteUrl,
      callbackUrl: new URL('callback.html', siteUrl).toString(),
      supabaseUrl,
      relayBase: `${supabaseUrl}/functions/v1/${RELAY_FUNCTION_NAME}`,
      publishableKey: key,
      privacyPolicyUrl: env.SAFEAUTH_PUBLIC_PRIVACY_POLICY_URL ? String(env.SAFEAUTH_PUBLIC_PRIVACY_POLICY_URL) : null,
      operatorContact: env.SAFEAUTH_PUBLIC_OPERATOR_CONTACT ? String(env.SAFEAUTH_PUBLIC_OPERATOR_CONTACT) : null,
    },
  };
}
