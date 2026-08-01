/**
 * routes/ProtectedRoute.tsx
 *
 * A wrapper component that guards routes requiring authentication.
 *
 * BEHAVIOUR
 * ──────────
 * | loading | user  | result                                      |
 * |---------|-------|---------------------------------------------|
 * | true    | any   | Render a full-screen loading spinner        |
 * | false   | null  | Redirect to /login, preserving the `from`   |
 * | false   | set   | Render the protected children               |
 *
 * The `state={{ from: location }}` on the redirect lets the Login page
 * read `location.state.from` and send the user back to where they
 * originally tried to go after a successful sign-in.
 *
 * USAGE
 * ──────
 * In your router config:
 *
 *   <Route element={<ProtectedRoute />}>
 *     <Route path="/dashboard" element={<DashboardPage />} />
 *     <Route path="/history"   element={<HistoryPage />}   />
 *   </Route>
 *
 * Or for a single route:
 *
 *   <Route
 *     path="/dashboard"
 *     element={<ProtectedRoute><DashboardPage /></ProtectedRoute>}
 *   />
 *
 * Both patterns are supported because the component returns <Outlet /> when
 * no explicit `children` are passed, and renders `children` otherwise.
 */

import { type ReactNode } from 'react';
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { Loader2 } from 'lucide-react';
import { useAuth } from '@/features/auth/AuthContext';

interface ProtectedRouteProps {
  /** Optional: wrap a single route directly instead of using Outlet */
  children?: ReactNode;
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { user, loading } = useAuth();
  const location = useLocation();

  // 1. Still restoring the session — show a neutral full-screen spinner.
  //    This prevents a flash of the login page on hard refreshes.
  if (loading) {
    return (
      <div
        className="min-h-screen flex items-center justify-center bg-gray-950"
        role="status"
        aria-label="Loading your session"
      >
        <Loader2 className="h-10 w-10 text-cyan-400 animate-spin" />
      </div>
    );
  }

  // 2. Session restored and no user — redirect to login.
  if (!user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // 3. Authenticated — render the child route or the wrapped component.
  return children ? <>{children}</> : <Outlet />;
}
