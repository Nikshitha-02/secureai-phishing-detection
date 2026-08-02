/**
 * errorHandler.ts
 * ───────────────
 * Express global error-handling middleware.
 *
 * Must be registered LAST in app.ts (after all routes) so that
 * errors forwarded via next(err) land here.
 *
 * Returns a consistent JSON error envelope:
 * {
 *   "error": "Internal Server Error",
 *   "message": "Something went wrong."   ← sanitised in production
 * }
 */

import { Request, Response, NextFunction } from 'express';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface AppError extends Error {
  status?: number;
  statusCode?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Middleware
// ─────────────────────────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function errorHandler(
  err: AppError,
  _req: Request,
  res: Response,
  _next: NextFunction,
): void {
  const isDev = process.env.NODE_ENV !== 'production';

  // Prefer an explicit status on the error, otherwise default to 500
  const statusCode = err.status ?? err.statusCode ?? 500;

  // In development, surface the real error message for easier debugging.
  // In production, send a generic message to avoid leaking internals.
  const message = isDev
    ? (err.message ?? 'An unexpected error occurred.')
    : 'Something went wrong. Please try again later.';

  // Always log the stack trace on the server side
  console.error('[errorHandler]', err.stack ?? err.message);

  res.status(statusCode).json({
    error: statusCode === 500 ? 'Internal Server Error' : err.name,
    message,
  });
}
