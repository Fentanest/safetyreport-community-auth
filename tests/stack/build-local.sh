#!/usr/bin/env bash
# Builds the safeauth variants used by the local browser review (outputs under .safeauth-stack/):
#   dist-local  base /      for http://127.0.0.1:8480/ (gateway :54400)
#   site-sub/sub         base /sub/  for http://127.0.0.1:8481/sub/ (gateway :54401), base-portability check
#   dist                 production shape without configuration (config-missing screen)
set -euo pipefail
cd "$(dirname "$0")/../.."
SAFEAUTH_OUT_DIR=.safeauth-stack/dist-local SAFEAUTH_PUBLIC_SUPABASE_URL=http://127.0.0.1:54400 \
  SAFEAUTH_PUBLIC_SITE_URL=http://127.0.0.1:8480/ npx vite build --mode localtest --config site/vite.config.ts --logLevel warn
node scripts/verify-artifact.mjs --dir .safeauth-stack/dist-local --expect-supabase http://127.0.0.1:54400 --site-origin http://127.0.0.1:8480
rm -rf .safeauth-stack/site-sub
SAFEAUTH_BASE=/sub/ SAFEAUTH_OUT_DIR=.safeauth-stack/site-sub/sub SAFEAUTH_PUBLIC_SUPABASE_URL=http://127.0.0.1:54401 \
  SAFEAUTH_PUBLIC_SITE_URL=http://127.0.0.1:8481/sub/ npx vite build --mode localtest --config site/vite.config.ts --logLevel warn
npx vite build --config site/vite.config.ts --logLevel warn
node scripts/verify-artifact.mjs --dir dist
