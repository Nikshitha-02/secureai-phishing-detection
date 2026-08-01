/**
 * features/auth/AuthContext.tsx
 *
 * Provides authentication state to the entire React tree via Context.
 *
 * HOW IT WORKS
 * ─────────────
 * 1. On mount, `supabase.auth.getSession()` loads the persisted session from
 *    localStorage synchronously-ish. We call it inside useEffect to keep the
 *    component mount cheap.
 *
 * 2. `supabase.auth.onAuthStateChange` subscribes to every auth event
 *    (SIGNED_IN, SIGNED_OUT, TOKEN_REFRESHED, PASSWORD_RECOVERY, etc.) and
 *    keeps `user` and `session` up to date for the lifetime of the app.
 *
 * 3. `loading` is true until the first event fires. ProtectedRoute and any
 *    page that branches on auth state must wait for loading === false.
 *
 * USAGE
 * ─────
 * Wrap your router in <AuthProvider> (done in App.tsx), then call useAuth()
 * in any descendant component.
 */

import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  type ReactNode,
} from 'react';
import type { Session, User } from '@supabase/supabase-js';
import { supabase } from '@/lib/supabaseClient';
import type { AuthContextValue } from '@/types/auth';

// ─── Context ─────────────────────────────────────────────────────────────────

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

// ─── Provider ────────────────────────────────────────────────────────────────

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  // Start as true so children never flash as "logged out" on page load.
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // 1. Restore the session that Supabase already persisted in localStorage.
    //    This fires once synchronously before any network call.
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      setUser(session?.user ?? null);
      setLoading(false);
    });

    // 2. Subscribe to all subsequent auth state changes.
    //    The subscription fires immediately with the current state so that
    //    SIGNED_IN / SIGNED_OUT always updates the context in real time.
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
      setUser(session?.user ?? null);
      setLoading(false);
    });

    // Cleanup: unsubscribe when the provider unmounts (never in practice, but
    // good hygiene and keeps React StrictMode from leaking subscriptions).
    return () => {
      subscription.unsubscribe();
    };
  }, []);

  // ── signOut ────────────────────────────────────────────────────────────────
  // Wrapped in useCallback so consumers that pass it as a prop do not trigger
  // unnecessary re-renders.
  const signOut = useCallback(async () => {
    await supabase.auth.signOut();
    // onAuthStateChange will set user/session to null automatically.
  }, []);

  const value: AuthContextValue = { user, session, loading, signOut };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

/**
 * useAuth
 *
 * Returns the current AuthContextValue.
 * Throws if called outside of <AuthProvider> so misconfigured trees fail fast.
 */
export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (ctx === undefined) {
    throw new Error('useAuth must be used inside <AuthProvider>');
  }
  return ctx;
}
