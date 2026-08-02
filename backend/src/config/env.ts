/**
 * env.ts
 * ──────
 * Type-safe environment variable loader.
 *
 * Reads all required and optional variables at startup, emits clear
 * warnings for missing optional ones, and exports a typed `config` object.
 */

const DEFAULT_GEMINI_MODEL = 'gemini-2.0-flash';

function optionalEnv(key: string): string | undefined {
  return process.env[key] || undefined;
}

function warnIfMissing(key: string, feature: string): void {
  if (!process.env[key]) {
    console.warn(
      `[env] Warning: ${key} is not set. "${feature}" feature will be unavailable.`,
    );
  }
}

// ── Supabase warnings ────────────────────────────────────────────────────────
warnIfMissing('SUPABASE_URL', 'Supabase DB / Auth');
warnIfMissing('SUPABASE_SERVICE_ROLE_KEY', 'Supabase DB / Auth');

// ── Gemini startup log ────────────────────────────────────────────────────────
if (process.env.GEMINI_API_KEY) {
  const model = process.env.GEMINI_MODEL || DEFAULT_GEMINI_MODEL;
  console.log(`[env] ✓ Gemini AI enabled`);
  console.log(`[env]   Model: ${model}`);
} else {
  console.warn(`[env] ✗ Gemini AI disabled (GEMINI_API_KEY missing)`);
}

export const config = {
  NODE_ENV: process.env.NODE_ENV ?? 'development',
  PORT: Number(process.env.PORT ?? 5000),
  CORS_ORIGIN: process.env.CORS_ORIGIN ?? 'http://localhost:5173',

  // Optional — Phase 2 (Auth + DB integration)
  SUPABASE_URL: optionalEnv('SUPABASE_URL'),
  SUPABASE_SERVICE_ROLE_KEY: optionalEnv('SUPABASE_SERVICE_ROLE_KEY'),

  // Optional — Phase 3 (AI-powered analysis)
  GEMINI_API_KEY: optionalEnv('GEMINI_API_KEY'),

  /**
   * Gemini model name. Read from GEMINI_MODEL env var.
   * Defaults to gemini-2.5-flash if not set.
   * Change this in .env to switch models without touching source code.
   */
  GEMINI_MODEL: process.env.GEMINI_MODEL || DEFAULT_GEMINI_MODEL,
} as const;

export type Config = typeof config;
