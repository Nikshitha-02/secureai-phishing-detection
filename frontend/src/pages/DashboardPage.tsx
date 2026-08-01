/**
 * pages/DashboardPage.tsx
 *
 * Full dashboard layout for authenticated users.
 *
 * Layout:
 *   ┌──────────┬────────────────────────────────┐
 *   │ Sidebar  │  Header (topbar)                │
 *   │          ├────────────────────────────────┤
 *   │          │  Welcome + Stats                │
 *   │          │  Scanner Card                   │
 *   │          │  Recent Scans                   │
 *   └──────────┴────────────────────────────────┘
 *
 * Authentication: consumed via useAuth() — DO NOT modify the auth system.
 */

import { useState, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  Activity,
  CheckCircle,
  AlertTriangle,
  ShieldAlert,
  Menu,
  LogOut,
  Loader2,
  Calendar,
} from 'lucide-react';

import { useAuth } from '@/hooks/useAuth';
import { Button } from '@/components/ui/Button';

import { Sidebar, type NavItemId } from '@/features/dashboard/components/Sidebar';
import { DashboardCard } from '@/features/dashboard/components/DashboardCard';
import { StatCard } from '@/features/dashboard/components/StatCard';
import { SecurityTip } from '@/features/dashboard/components/SecurityTip';
import { RecentScansTable } from '@/features/dashboard/components/RecentScansTable';
import { ScannerCard } from '@/features/url-scanner/components/ScannerCard';

import {
  MOCK_STATS,
  MOCK_RECENT_SCANS,
  getDailyTip,
} from '@/features/dashboard/mockData';
import type { RecentScan, ScanResult, StatCardConfig } from '@/types/dashboard';

// ─── Stat card definitions ────────────────────────────────────────────────────

const STAT_CARDS: StatCardConfig[] = [
  { label: 'Total Scans', value: MOCK_STATS.totalScans, colour: 'cyan-400', icon: Activity },
  { label: 'Safe URLs', value: MOCK_STATS.safeUrls, colour: 'green-400', icon: CheckCircle },
  { label: 'Suspicious URLs', value: MOCK_STATS.suspiciousUrls, colour: 'yellow-400', icon: AlertTriangle },
  { label: 'High Risk URLs', value: MOCK_STATS.highRiskUrls, colour: 'red-400', icon: ShieldAlert },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getGreeting(): string {
  const hour = new Date().getHours();
  if (hour < 12) return 'Good morning';
  if (hour < 18) return 'Good afternoon';
  return 'Good evening';
}

function formatCurrentDate(): string {
  return new Date().toLocaleDateString('en-US', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}

function getUserInitial(email: string | undefined): string {
  if (!email) return '?';
  return email[0].toUpperCase();
}

function getUserName(email: string | undefined): string {
  if (!email) return 'User';
  return email.split('@')[0];
}

/** Convert a full ScanResult into a RecentScan history row. */
function toRecentScan(result: ScanResult): RecentScan {
  return {
    id: crypto.randomUUID(),
    url: result.url,
    riskScore: result.riskScore,
    riskLevel: result.riskLevel,
    scannedAt: result.scannedAt,
  };
}

// ─── Component ────────────────────────────────────────────────────────────────

export function DashboardPage() {
  const { user, signOut } = useAuth();

  // Sidebar state
  const [activeNav, setActiveNav] = useState<NavItemId>('dashboard');
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  // Sign-out loading state
  const [signingOut, setSigningOut] = useState(false);

  // Recent scans — starts with mock data, prepends new results on scan
  const [recentScans, setRecentScans] = useState<RecentScan[]>(MOCK_RECENT_SCANS);

  // ── Handlers ──────────────────────────────────────────────────────────────

  const handleSignOut = useCallback(async () => {
    setSigningOut(true);
    await signOut();
    // ProtectedRoute redirects once user becomes null — no need to navigate here.
  }, [signOut]);

  const handleScanComplete = useCallback((result: ScanResult) => {
    setRecentScans((prev) => [toRecentScan(result), ...prev].slice(0, 50));
  }, []);

  // ── Section title based on active nav ─────────────────────────────────────

  const sectionTitle: Record<NavItemId, string> = {
    dashboard: 'Overview',
    scanner: 'URL Scanner',
    history: 'Scan History',
    reports: 'Reports',
    settings: 'Settings',
  };

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="flex min-h-screen bg-gray-950 text-white">
      {/* Skip to main content (accessibility) */}
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>

      {/* ── Sidebar ─────────────────────────────────────────────────────── */}
      <Sidebar
        activeItem={activeNav}
        onNavChange={setActiveNav}
        mobileOpen={mobileSidebarOpen}
        onMobileClose={() => setMobileSidebarOpen(false)}
        collapsed={sidebarCollapsed}
        onToggleCollapsed={() => setSidebarCollapsed((v) => !v)}
        onSignOut={handleSignOut}
      />

      {/* ── Main content ─────────────────────────────────────────────────── */}
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
              <h1 className="text-base font-semibold text-white">
                {sectionTitle[activeNav]}
              </h1>
            </div>

            {/* Right: user + signout */}
            <div className="flex items-center gap-3 ml-auto">
              {/* User avatar + email */}
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

              {/* Sign out button */}
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

        {/* ── Page body ──────────────────────────────────────────────────── */}
        <main
          id="main-content"
          className="flex-1 px-4 py-6 sm:px-6 lg:px-8 space-y-6 max-w-5xl w-full mx-auto"
        >

          {/* ── Welcome Section ──────────────────────────────────────────── */}
          <motion.section
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4 }}
            aria-label="Welcome section"
          >
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              {/* Left: avatar + greeting */}
              <div className="flex items-center gap-4">
                {/* Large avatar */}
                <div
                  className={[
                    'flex h-14 w-14 items-center justify-center rounded-2xl',
                    'bg-gradient-to-br from-cyan-500/30 to-cyan-600/20',
                    'border border-cyan-500/30 text-2xl font-bold text-cyan-400',
                    'shadow-lg shadow-cyan-500/10',
                  ].join(' ')}
                  aria-hidden="true"
                >
                  {getUserInitial(user?.email)}
                </div>

                <div>
                  <h2 className="text-xl font-bold text-white leading-tight">
                    {getGreeting()}, {getUserName(user?.email)}!
                  </h2>
                  <p className="mt-0.5 text-sm text-gray-400 flex items-center gap-1.5">
                    <Calendar className="h-3.5 w-3.5" aria-hidden="true" />
                    {formatCurrentDate()}
                  </p>
                </div>
              </div>

              {/* Right: status pill */}
              <div className="flex items-center gap-2 self-start sm:self-auto">
                <span
                  className="inline-flex items-center gap-1.5 rounded-full border border-green-500/30 bg-green-500/10 px-3 py-1 text-xs font-medium text-green-400"
                  aria-label="System status: all systems operational"
                >
                  <span className="h-1.5 w-1.5 rounded-full bg-green-400 animate-pulse" aria-hidden="true" />
                  All systems operational
                </span>
              </div>
            </div>

            {/* Daily security tip */}
            <div className="mt-4">
              <SecurityTip tip={getDailyTip()} />
            </div>
          </motion.section>

          {/* ── Quick Statistics ─────────────────────────────────────────── */}
          <section aria-label="Quick statistics">
            <h2 className="sr-only">Quick Statistics</h2>
            <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
              {STAT_CARDS.map((card, i) => (
                <StatCard
                  key={card.label}
                  label={card.label}
                  value={card.value}
                  colour={card.colour}
                  icon={card.icon}
                  delay={0.05 * i}
                />
              ))}
            </div>
          </section>

          {/* ── URL Scanner ──────────────────────────────────────────────── */}
          <DashboardCard
            title="AI Phishing URL Scanner"
            subtitle="Analyse any URL for phishing attacks using AI and security heuristics."
            delay={0.2}
            ariaLabel="URL Phishing Scanner"
          >
            <ScannerCard onScanComplete={handleScanComplete} />
          </DashboardCard>

          {/* ── Recent Scans ─────────────────────────────────────────────── */}
          <DashboardCard
            title="Recent Scans"
            subtitle="Your latest URL analyses."
            delay={0.3}
            ariaLabel="Recent scan history"
          >
            <RecentScansTable scans={recentScans} />
          </DashboardCard>

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
