/**
 * layouts/DashboardLayout.tsx
 *
 * Shared layout wrapper for all authenticated dashboard routes.
 *
 * Responsibilities:
 *  - Renders the Sidebar + top header shell
 *  - Derives `activeItem` from the current URL via useLocation
 *  - Calls useNavigate on sidebar nav clicks (no state-based routing)
 *  - Renders child routes via <Outlet />
 *
 * All five routes (/dashboard, /scanner, /history, /reports, /settings)
 * use this layout. The Sidebar component itself is NOT modified.
 */

import { useState, useCallback } from 'react';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, Menu, LogOut, Loader2 } from 'lucide-react';

import { useAuth } from '@/hooks/useAuth';
import { Button } from '@/components/ui/Button';
import { Sidebar, type NavItemId } from '@/features/dashboard/components/Sidebar';

// ─── Route → NavItemId mapping ────────────────────────────────────────────────

const PATH_TO_NAV: Record<string, NavItemId> = {
  '/dashboard': 'dashboard',
  '/scanner':   'scanner',
  '/history':   'history',
  '/reports':   'reports',
  '/settings':  'settings',
};

const NAV_TO_PATH: Record<NavItemId, string> = {
  dashboard: '/dashboard',
  scanner:   '/scanner',
  history:   '/history',
  reports:   '/reports',
  settings:  '/settings',
};

const SECTION_TITLE: Record<NavItemId, string> = {
  dashboard: 'Overview',
  scanner:   'URL Scanner',
  history:   'Scan History',
  reports:   'Reports',
  settings:  'Settings',
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getUserInitial(email: string | undefined): string {
  if (!email) return '?';
  return email[0].toUpperCase();
}

/** Derive the active nav item from the current pathname. */
function pathToNavItem(pathname: string): NavItemId {
  return PATH_TO_NAV[pathname] ?? 'dashboard';
}

// ─── Component ────────────────────────────────────────────────────────────────

export function DashboardLayout() {
  const { user, signOut } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  // Sidebar UI state (no nav state — that comes from the URL)
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [signingOut, setSigningOut] = useState(false);

  // Derive active nav item from URL — no useState needed
  const activeNav = pathToNavItem(location.pathname);

  // ── Handlers ──────────────────────────────────────────────────────────────

  const handleNavChange = useCallback(
    (id: NavItemId) => {
      navigate(NAV_TO_PATH[id]);
    },
    [navigate],
  );

  const handleSignOut = useCallback(async () => {
    setSigningOut(true);
    await signOut();
    // ProtectedRoute will redirect to /login once user becomes null
  }, [signOut]);

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="flex min-h-screen bg-gray-950 text-white">
      {/* Skip to main content (accessibility) */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-cyan-500 focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-gray-950"
      >
        Skip to main content
      </a>

      {/* ── Sidebar ───────────────────────────────────────────────────────── */}
      <Sidebar
        activeItem={activeNav}
        onNavChange={handleNavChange}
        mobileOpen={mobileSidebarOpen}
        onMobileClose={() => setMobileSidebarOpen(false)}
        collapsed={sidebarCollapsed}
        onToggleCollapsed={() => setSidebarCollapsed((v) => !v)}
        onSignOut={handleSignOut}
      />

      {/* ── Main content area ─────────────────────────────────────────────── */}
      <div className="flex flex-1 flex-col min-w-0">

        {/* Top header bar */}
        <header className="sticky top-0 z-30 border-b border-white/8 bg-gray-950/80 backdrop-blur-sm">
          <div className="flex items-center justify-between px-4 py-3 sm:px-6">
            {/* Mobile hamburger */}
            <button
              className="lg:hidden rounded-lg p-2 text-gray-400 hover:bg-white/5 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500"
              aria-label="Open navigation menu"
              onClick={() => setMobileSidebarOpen(true)}
            >
              <Menu className="h-5 w-5" aria-hidden="true" />
            </button>

            {/* Page title (desktop) */}
            <div className="hidden lg:flex items-center gap-2">
              <Shield className="h-5 w-5 text-cyan-400" aria-hidden="true" />
              <motion.h1
                key={activeNav}
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.2 }}
                className="text-base font-semibold text-white"
              >
                {SECTION_TITLE[activeNav]}
              </motion.h1>
            </div>

            {/* Right: user info + signout */}
            <div className="flex items-center gap-3 ml-auto">
              <div className="flex items-center gap-2.5">
                <div
                  className="flex h-8 w-8 items-center justify-center rounded-full bg-cyan-500/20 border border-cyan-500/30 text-sm font-bold text-cyan-400"
                  aria-hidden="true"
                >
                  {getUserInitial(user?.email)}
                </div>
                <span className="hidden sm:block text-sm text-gray-400 max-w-[180px] truncate">
                  {user?.email}
                </span>
              </div>

              <Button
                variant="outline"
                size="sm"
                onClick={handleSignOut}
                disabled={signingOut}
                aria-label="Sign out"
              >
                {signingOut ? (
                  <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                ) : (
                  <LogOut className="h-4 w-4" aria-hidden="true" />
                )}
                <span className="hidden sm:inline">
                  {signingOut ? 'Signing out…' : 'Sign out'}
                </span>
              </Button>
            </div>
          </div>
        </header>

        {/* ── Child route renders here ───────────────────────────────────── */}
        <main id="main-content" className="flex-1">
          <Outlet />
        </main>

        {/* Footer */}
        <footer className="border-t border-white/5 py-4 px-6 text-center">
          <p className="text-xs text-gray-600">
            SecureAI — AI-powered phishing detection &amp; security analysis
          </p>
        </footer>
      </div>
    </div>
  );
}
