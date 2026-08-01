/**
 * pages/VerifyEmailPage.tsx
 *
 * Landing page for the email-confirmation redirect from Supabase.
 *
 * HOW SUPABASE EMAIL CONFIRMATION WORKS
 * ──────────────────────────────────────
 * When a user clicks the confirmation link in their inbox, Supabase
 * redirects them to the URL you specified in `emailRedirectTo` (we used
 * `${window.location.origin}/verify-email`).
 *
 * The URL arrives with a `?token_hash=…&type=signup` query string.
 * The Supabase JS SDK's `detectSessionInUrl: true` option (set in
 * supabaseClient.ts) automatically exchanges that token for a real session
 * and fires onAuthStateChange with event = 'SIGNED_IN'.
 *
 * This component therefore just:
 * 1. Shows a spinner while `loading` is still true (session exchange is pending).
 * 2. Redirects to /dashboard once a user is present in the AuthContext.
 * 3. Shows an error state if the URL parameters are missing or invalid.
 *
 * It also handles the case where the user navigates to /verify-email
 * directly without a token (e.g., they book-marked it). In that case we
 * just show a "check your inbox" placeholder.
 */

import { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Loader2, CheckCircle2, XCircle } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useAuth } from '@/features/auth/AuthContext';
import { AuthCard } from '@/features/auth/components/AuthCard';
import { Button } from '@/components/ui/Button';

// ─── Component ───────────────────────────────────────────────────────────────

export function VerifyEmailPage() {
  const { user, loading } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  // When the SDK has finished exchanging the token and we have a user,
  // forward them to the dashboard.
  useEffect(() => {
    if (!loading && user) {
      navigate('/dashboard', { replace: true });
    }
  }, [loading, user, navigate]);

  // Determine what kind of URL this is.
  const hasToken = searchParams.has('token_hash') || searchParams.has('access_token');
  const isError =
    searchParams.get('error') !== null ||
    searchParams.get('error_description') !== null;
  const errorDescription =
    searchParams.get('error_description') ?? 'The verification link is invalid or has expired.';

  // ── States ─────────────────────────────────────────────────────────────────

  // 1. Token exchange in progress
  if (loading && hasToken) {
    return (
      <AuthCard title="Verifying your email…">
        <div className="flex flex-col items-center gap-4 py-6">
          <Loader2 className="h-12 w-12 text-cyan-400 animate-spin" aria-label="Loading" />
          <p className="text-sm text-gray-400">Please wait while we verify your email address.</p>
        </div>
      </AuthCard>
    );
  }

  // 2. Supabase returned an error in the URL (expired link, already used, etc.)
  if (isError) {
    return (
      <AuthCard title="Verification failed">
        <div className="flex flex-col items-center gap-6 py-4">
          <XCircle className="h-14 w-14 text-red-400" aria-hidden="true" />
          <p className="text-sm text-gray-400 text-center">{decodeURIComponent(errorDescription)}</p>
          <div className="flex flex-col gap-3 w-full">
            <Link to="/register">
              <Button variant="primary" fullWidth>
                Register again
              </Button>
            </Link>
            <Link to="/login">
              <Button variant="outline" fullWidth>
                Sign in
              </Button>
            </Link>
          </div>
        </div>
      </AuthCard>
    );
  }

  // 3. No token in URL — user landed here directly (e.g. bookmarked the page)
  if (!hasToken) {
    return (
      <AuthCard
        title="Verify your email"
        subtitle="Check your inbox for the confirmation link we sent you."
      >
        <div className="flex flex-col items-center gap-6 py-4">
          <CheckCircle2 className="h-14 w-14 text-cyan-400" aria-hidden="true" />
          <p className="text-sm text-gray-400 text-center">
            Once you click the link in your email your account will be activated and you&apos;ll be
            redirected to the dashboard automatically.
          </p>
          <p className="text-center text-sm text-gray-500">
            Already confirmed?{' '}
            <Link
              to="/login"
              className="text-cyan-400 hover:text-cyan-300 font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-500 rounded"
            >
              Sign in
            </Link>
          </p>
        </div>
      </AuthCard>
    );
  }

  // 4. Token present but still loading (fallback spinner)
  return (
    <AuthCard title="Verifying your email…">
      <div className="flex flex-col items-center gap-4 py-6">
        <Loader2 className="h-12 w-12 text-cyan-400 animate-spin" aria-label="Loading" />
        <p className="text-sm text-gray-400">Finalising your account…</p>
      </div>
    </AuthCard>
  );
}
