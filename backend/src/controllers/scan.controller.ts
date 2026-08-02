/**
 * scan.controller.ts
 * ──────────────────
 * HTTP boundary layer — the only file that knows about req / res.
 *
 * Responsibilities:
 *  1. Extract and validate the request body
 *  2. Delegate to scan.service for business logic
 *  3. Return a clean JSON response with the correct HTTP status
 *  4. Forward unexpected errors to the global error handler via next()
 */

import { Request, Response, NextFunction } from 'express';
import { scanUrl, InvalidUrlError } from '../services/scan.service';
import { ScanRequest } from '../models/scan.model';

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/scan
// ─────────────────────────────────────────────────────────────────────────────

export async function scanUrlController(
  req: Request<object, object, ScanRequest>,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const { url } = req.body;

    // ── Input validation ────────────────────────────────────────────────────
    if (!url || typeof url !== 'string') {
      res.status(400).json({
        error: 'Validation error',
        message: 'Request body must include a "url" string field.',
      });
      return;
    }

    const trimmed = url.trim();

    if (trimmed.length === 0) {
      res.status(400).json({
        error: 'Validation error',
        message: '"url" must not be an empty string.',
      });
      return;
    }

    if (trimmed.length > 2048) {
      res.status(400).json({
        error: 'Validation error',
        message: '"url" must not exceed 2048 characters.',
      });
      return;
    }

    // ── Business logic ──────────────────────────────────────────────────────
    const result = await scanUrl(trimmed);

    res.status(200).json(result);
  } catch (err) {
    // InvalidUrlError → 400 Bad Request (user input problem)
    if (err instanceof InvalidUrlError) {
      res.status(400).json({
        error: 'Invalid URL',
        message: (err as Error).message,
      });
      return;
    }

    // Everything else → 500 (pass to global error handler)
    next(err);
  }
}
