/// <reference types="vite/client" />

// Public build-time values only (envPrefix SAFEAUTH_PUBLIC_). Never secrets.
interface ImportMetaEnv {
  readonly SAFEAUTH_PUBLIC_SUPABASE_URL?: string;
  readonly SAFEAUTH_PUBLIC_PUBLISHABLE_KEY?: string;
  readonly SAFEAUTH_PUBLIC_SITE_URL?: string;
  readonly SAFEAUTH_PUBLIC_PRIVACY_POLICY_URL?: string;
  readonly SAFEAUTH_PUBLIC_OPERATOR_CONTACT?: string;
}
