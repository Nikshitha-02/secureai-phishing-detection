/**
 * hooks/useAuth.ts
 *
 * Convenience re-export of the useAuth hook.
 *
 * WHY THIS EXISTS
 * ────────────────
 * The hook's implementation lives next to the context that backs it
 * (features/auth/AuthContext.tsx), which is where it belongs architecturally.
 *
 * However, the project's established convention places shared hooks in
 * src/hooks/ so that consumers always know where to look:
 *
 *   import { useAuth } from '@/hooks/useAuth';
 *
 * This file is purely a re-export — one line of code — so there is no
 * maintenance burden and no circular dependency risk.
 */

export { useAuth } from '@/features/auth/AuthContext';
