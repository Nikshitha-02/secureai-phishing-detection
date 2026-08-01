/**
 * types/auth.ts
 *
 * Shared TypeScript types for the authentication layer.
 *
 * Keeping them in one file means every component, context, hook, and service
 * imports from the same source of truth. If Supabase's underlying type shapes
 * change in a future SDK upgrade you only fix things in one place.
 */

import type { Session, User } from '@supabase/supabase-js';

// ─── Re-exports ──────────────────────────────────────────────────────────────
// Surface Supabase's own types so the rest of the codebase never imports from
// @supabase/supabase-js directly; they always go through @/types/auth.
export type { Session, User };

// ─── Auth context value ───────────────────────────────────────────────────────
/**
 * The shape of the value provided by AuthContext.
 * Components consume this via the `useAuth` hook.
 */
export interface AuthContextValue {
  /** The currently authenticated Supabase user, or null when logged out. */
  user: User | null;

  /** The full session object (contains the JWT, refresh token, expiry, etc.).
   *  Null until the first `onAuthStateChange` event fires. */
  session: Session | null;

  /**
   * True while the context is restoring the session from localStorage on first
   * mount. Components should render a loading state or nothing until this is
   * false to avoid a flash of "logged out" UI.
   */
  loading: boolean;

  /** Signs the current user out and removes the local session. */
  signOut: () => Promise<void>;
}

// ─── Form payload types ───────────────────────────────────────────────────────
/** Fields submitted on the Login form. */
export interface LoginCredentials {
  email: string;
  password: string;
}

/** Fields submitted on the Register form. */
export interface RegisterCredentials {
  email: string;
  password: string;
  confirmPassword: string;
}

/** Fields submitted on the Forgot Password form. */
export interface ForgotPasswordPayload {
  email: string;
}
