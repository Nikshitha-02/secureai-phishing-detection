/**
 * middlewares/requireAuth.ts
 *
 * Express middleware that verifies the Supabase JWT sent in the
 * Authorization: Bearer <token> header and attaches the user_id
 * to res.locals so downstream handlers can use it.
 *
 * Flow:
 *   1. Extract Bearer token from the Authorization header.
 *   2. Call supabase.auth.getUser(token) — this validates the JWT
 *      signature against the Supabase project's secret and returns
 *      the user object if valid.
 *   3. Attach user.id to res.locals.userId.
 *   4. Call next() on success, return 401 on any failure.
 *
 * Why use getUser(token) instead of decoding the JWT manually?
 *   - Supabase validates the signature server-side.
 *   - It checks expiry automatically.
 *   - It works with both the old JWT format and the new publishable-key format.
 */

import type { Request, Response, NextFunction } from 'express';
import { getSupabaseAdmin } from '../config/supabaseAdmin';

/**
 * Extend Express's res.locals type so TypeScript knows userId is available
 * after this middleware runs.
 */
declare module 'express-serve-static-core' {
  interface Locals {
    userId: string;
  }
}

export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({
      error: 'Unauthorised',
      message: 'Missing or malformed Authorization header. Expected: Bearer <token>',
    });
    return;
  }

  const token = authHeader.slice(7); // strip "Bearer "

  try {
    const supabase = getSupabaseAdmin();
    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data.user) {
      res.status(401).json({
        error: 'Unauthorised',
        message: 'Invalid or expired token. Please sign in again.',
      });
      return;
    }

    // Attach the verified user id — controllers read this via res.locals.userId
    res.locals.userId = data.user.id;
    next();
  } catch (err) {
    // getSupabaseAdmin() throws if credentials are not configured
    console.error('[requireAuth] Supabase admin client error:', err);
    res.status(500).json({
      error: 'Server configuration error',
      message: 'Authentication service is not configured. Contact the server administrator.',
    });
  }
}
