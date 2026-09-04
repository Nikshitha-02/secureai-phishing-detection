/**
 * pages/SettingsPage.tsx
 *
 * User account settings page, rendered at /settings inside DashboardLayout.
 *
 * Displays:
 *   - User email and account info from Supabase auth session
 *   - Session metadata (last sign in, account created)
 *   - Sign out button
 *
 * No Supabase service-role keys or secrets are exposed here.
 * All data comes from the already-authenticated user session via useAuth().
 */

import { useState, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Settings, User, Mail, Calendar, LogIn, LogOut, Loader2, Shield } from 'lucide-react';

import { useAuth } from '@/hooks/useAuth';
import { DashboardCard } from '@/features/dashboard/components/DashboardCard';
import { Button } from '@/components/ui/Button';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getUserInitial(email: string | undefined): string {
  if (!email) return '?';
  return email[0].toUpperCase();
}

function formatDate(isoString: string | undefined): string {
  if (!isoString) return '–';
  return new Date(isoString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

// ─── Component ────────────────────────────────────────────────────────────────

export function SettingsPage() {
  const { user, session, signOut } = useAuth();
  const [signingOut, setSigningOut] = useState(false);

  const handleSignOut = useCallback(async () => {
    setSigningOut(true);
    await signOut();
    // ProtectedRoute redirects to /login once user becomes null
  }, [signOut]);

  return (
    <div className="px-4 py-6 sm:px-6 lg:px-8 space-y-6 max-w-2xl w-full mx-auto">

      {/* Page header */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35 }}
        className="flex items-start gap-4"
      >
        <div className="flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-2xl bg-cyan-500/15 border border-cyan-500/25">
          <Settings className="h-6 w-6 text-cyan-400" aria-hidden="true" />
        </div>
        <div>
          <h2 className="text-xl font-bold text-white">Settings</h2>
          <p className="mt-0.5 text-sm text-gray-400">
            Your account information and session details.
          </p>
        </div>
      </motion.div>

      {/* ── Account Information ─────────────────────────────────────────── */}
      <DashboardCard title="Account" delay={0.1} ariaLabel="Account information">
        <div className="flex items-center gap-4 mb-6">
          {/* Avatar */}
          <div
            className={[
              'flex h-16 w-16 flex-shrink-0 items-center justify-center rounded-2xl',
              'bg-gradient-to-br from-cyan-500/30 to-cyan-600/20',
              'border border-cyan-500/30 text-2xl font-bold text-cyan-400',
            ].join(' ')}
            aria-hidden="true"
          >
            {getUserInitial(user?.email)}
          </div>
          <div>
            <p className="text-lg font-semibold text-white">
              {user?.email?.split('@')[0] ?? 'User'}
            </p>
            <p className="text-sm text-gray-400">{user?.email ?? '–'}</p>
          </div>
        </div>

        {/* Info rows */}
        <dl className="space-y-4">
          <div className="flex items-center gap-3 py-3 border-t border-white/8">
            <User className="h-4 w-4 text-gray-500 flex-shrink-0" aria-hidden="true" />
            <div className="flex-1 min-w-0">
              <dt className="text-xs text-gray-500 uppercase tracking-wider">User ID</dt>
              <dd className="mt-0.5 text-sm text-gray-300 font-mono truncate">
                {user?.id ?? '–'}
              </dd>
            </div>
          </div>

          <div className="flex items-center gap-3 py-3 border-t border-white/8">
            <Mail className="h-4 w-4 text-gray-500 flex-shrink-0" aria-hidden="true" />
            <div className="flex-1 min-w-0">
              <dt className="text-xs text-gray-500 uppercase tracking-wider">Email address</dt>
              <dd className="mt-0.5 text-sm text-gray-300 truncate">{user?.email ?? '–'}</dd>
            </div>
            {user?.email_confirmed_at && (
              <span className="inline-flex items-center gap-1 rounded-full border border-green-500/30 bg-green-500/10 px-2 py-0.5 text-xs font-medium text-green-400 flex-shrink-0">
                <Shield className="h-3 w-3" aria-hidden="true" />
                Verified
              </span>
            )}
          </div>

          <div className="flex items-center gap-3 py-3 border-t border-white/8">
            <Calendar className="h-4 w-4 text-gray-500 flex-shrink-0" aria-hidden="true" />
            <div className="flex-1 min-w-0">
              <dt className="text-xs text-gray-500 uppercase tracking-wider">Account created</dt>
              <dd className="mt-0.5 text-sm text-gray-300">
                {formatDate(user?.created_at)}
              </dd>
            </div>
          </div>

          <div className="flex items-center gap-3 py-3 border-t border-white/8">
            <LogIn className="h-4 w-4 text-gray-500 flex-shrink-0" aria-hidden="true" />
            <div className="flex-1 min-w-0">
              <dt className="text-xs text-gray-500 uppercase tracking-wider">Last sign in</dt>
              <dd className="mt-0.5 text-sm text-gray-300">
                {formatDate(user?.last_sign_in_at)}
              </dd>
            </div>
          </div>
        </dl>
      </DashboardCard>

      {/* ── Session ─────────────────────────────────────────────────────── */}
      <DashboardCard title="Session" delay={0.2} ariaLabel="Session information">
        <dl className="space-y-4">
          <div className="flex items-center gap-3 py-3">
            <div className="flex-1 min-w-0">
              <dt className="text-xs text-gray-500 uppercase tracking-wider">Session status</dt>
              <dd className="mt-0.5 flex items-center gap-2">
                {session ? (
                  <span className="inline-flex items-center gap-1.5 text-sm text-green-400">
                    <span className="h-2 w-2 rounded-full bg-green-400 animate-pulse" aria-hidden="true" />
                    Active
                  </span>
                ) : (
                  <span className="text-sm text-gray-500">No active session</span>
                )}
              </dd>
            </div>
          </div>

          {session?.expires_at && (
            <div className="flex items-center gap-3 py-3 border-t border-white/8">
              <Calendar className="h-4 w-4 text-gray-500 flex-shrink-0" aria-hidden="true" />
              <div className="flex-1 min-w-0">
                <dt className="text-xs text-gray-500 uppercase tracking-wider">Session expires</dt>
                <dd className="mt-0.5 text-sm text-gray-300">
                  {formatDate(new Date(session.expires_at * 1000).toISOString())}
                </dd>
              </div>
            </div>
          )}
        </dl>
      </DashboardCard>

      {/* ── Danger Zone ─────────────────────────────────────────────────── */}
      <DashboardCard delay={0.3} ariaLabel="Account actions">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-medium text-white">Sign out</h3>
            <p className="mt-0.5 text-sm text-gray-500">
              End your current session and return to the login page.
            </p>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={handleSignOut}
            disabled={signingOut}
            aria-label="Sign out of SecureAI"
            className="flex-shrink-0 border-red-500/30 text-red-400 hover:bg-red-500/10 hover:border-red-500/50"
          >
            {signingOut ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            ) : (
              <LogOut className="h-4 w-4" aria-hidden="true" />
            )}
            {signingOut ? 'Signing out…' : 'Sign out'}
          </Button>
        </div>
      </DashboardCard>

    </div>
  );
}
