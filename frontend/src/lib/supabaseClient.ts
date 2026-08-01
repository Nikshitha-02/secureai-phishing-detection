/**
 * supabaseClient.ts
 *
 * Single, shared Supabase client instance for the entire frontend.
 *
 * Why a singleton?
 * - Supabase maintains a real-time WebSocket connection and an in-memory
 *   session cache internally. Creating multiple instances would open
 *   duplicate connections and desync the session state.
 *
 * Environment variables (set in frontend/.env):
 *   VITE_SUPABASE_URL      – your project's REST/Auth base URL
 *   VITE_SUPABASE_ANON_KEY – the public "anon" API key (safe to expose in the browser)
 *
 * Both variables are validated at module load time so the app fails fast with
 * a clear message during development if the .env file is misconfigured.
 */

import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL as string;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY as string;

if (!supabaseUrl || !supabaseAnonKey) {
  throw new Error(
    '[supabaseClient] VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY must be set in your .env file.',
  );
}

/**
 * The singleton Supabase client.
 * Import this wherever you need to interact with Supabase:
 *
 *   import { supabase } from '@/lib/supabaseClient';
 *
 * `persistSession: true` (the default) stores the JWT in localStorage so the
 * user's session survives page refreshes. `autoRefreshToken: true` silently
 * rotates the token before it expires.
 */
export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true, // needed for email-confirmation / OAuth redirect flows
  },
});
