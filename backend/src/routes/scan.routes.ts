/**
 * scan.routes.ts
 * ──────────────
 * Express router for all /api/scan endpoints.
 *
 * Currently exposes:
 *   POST /api/scan   →  scanUrlController
 *
 * This file stays thin — no logic, just wiring.
 * Mount it in app.ts with:  app.use('/api/scan', scanRouter);
 */

import { Router } from 'express';
import { scanUrlController } from '../controllers/scan.controller';

const scanRouter = Router();

// POST /api/scan
scanRouter.post('/', scanUrlController);

export default scanRouter;
