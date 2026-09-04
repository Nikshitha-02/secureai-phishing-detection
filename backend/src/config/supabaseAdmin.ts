/**
 * config/supabaseAdmin.ts
 *
 * Singleton Supabase client for the backend, initialised with the
 * SERVICE ROLE key — grants full database access and bypasses RLS.
 *
 * SECURITY RULES:
 *  - This module must NEVER be imported into frontend code.
 *  - The service role key must NEVER be sent to the browser.
 *  - All writes (INSERT scan results) happen through this client.
 *  - All JWT verification (who is calling /api/scan) happens through
 *    supabase.auth.getUser(token) on this same client.
 *
 * The client is created lazily (first call) so that startup does not
 * crash if the env vars are missing — the error surfaces on first use
 * which gives a more useful stack trace.
 */

import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { config } from './env';

let _client: SupabaseClient | null = null;

/**
 * Returns the singleton service-role Supabase client.
 * Throws with a clear message if credentials are not configured.
 */
export function getSupabaseAdmin(): SupabaseClient {
  if (_client) return _client;

  const url = config.SUPABASE_URL;
  const key = config.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !key) {
    throw new Error(
      '[supabaseAdmin] SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set in backend .env. ' +
        'Get the service_role key from Supabase Dashboard → Settings → API.',
    );
  }

  _client = createClient(url, key, {
    auth: {
      // Backend client must never persist sessions or auto-refresh tokens.
      // It uses JWT verification, not session management.
      persistSession: false,
      autoRefreshToken: false,
    },
  });

  return _client;
}
