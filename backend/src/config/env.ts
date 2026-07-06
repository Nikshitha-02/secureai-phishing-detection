/**
 * Type-safe environment variable loader.
 * Throws at startup if any required variable is missing.
 */

function requireEnv(key: string): string {
  const value = process.env[key];
  if (!value) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return value;
}

export const config = {
  NODE_ENV: process.env.NODE_ENV ?? 'development',
  PORT: Number(process.env.PORT ?? 5000),
  CORS_ORIGIN: process.env.CORS_ORIGIN ?? 'http://localhost:5173',

  // Supabase
  SUPABASE_URL: requireEnv('SUPABASE_URL'),
  SUPABASE_SERVICE_ROLE_KEY: requireEnv('SUPABASE_SERVICE_ROLE_KEY'),

  // Gemini AI
  GEMINI_API_KEY: requireEnv('GEMINI_API_KEY'),
} as const;

export type Config = typeof config;
