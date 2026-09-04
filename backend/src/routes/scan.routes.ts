/**
 * scan.routes.ts
 * ──────────────
 * Express router for all /api/scan endpoints.
 *
 * POST /api/scan  →  scanRateLimiter  →  requireAuth  →  scanUrlController
 *
 * scanRateLimiter: 30 requests per 15 minutes per IP — tighter than the global
 * API limiter (100/15min) to protect the scan engine specifically.
 *
 * requireAuth validates the Supabase JWT and attaches res.locals.userId.
 * scanUrlController then passes userId into the scan service for persistence.
 */

import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { requireAuth } from '../middlewares/requireAuth';
import { scanUrlController } from '../controllers/scan.controller';

/** Tighter rate limit specifically for the scan endpoint */
const scanRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30,                   // 30 scan requests per IP per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many scan requests',
    message: 'You have exceeded the scan rate limit. Please wait 15 minutes before scanning again.',
  },
});

const scanRouter = Router();

// POST /api/scan  — rate-limited + protected: valid Supabase JWT required
scanRouter.post('/', scanRateLimiter, requireAuth, scanUrlController);

export default scanRouter;
