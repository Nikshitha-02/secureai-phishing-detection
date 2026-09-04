/**
 * pages/DashboardPage.tsx
 *
 * Dashboard overview page — rendered at /dashboard inside DashboardLayout.
 *
 * Displays:
 *   - Welcome greeting + date
 *   - Daily security tip
 *   - Quick statistics (from real scan history or fallback mock)
 *   - URL Scanner card (calls the backend /api/scan)
 *   - Recent scans table (updates on new scan + shows history from Supabase)
 *
 * The sidebar, header, and footer are provided by DashboardLayout.
 * Authentication is enforced by ProtectedRoute.
 */

import { useState, useCallback, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Activity,
  CheckCircle,
  AlertTriangle,
  ShieldAlert,
  Calendar,
} from 'lucide-react';

import { useAuth } from '@/hooks/useAuth';
import { DashboardCard } from '@/features/dashboard/components/DashboardCard';
import { StatCard } from '@/features/dashboard/components/StatCard';
import { SecurityTip } from '@/features/dashboard/components/SecurityTip';
import { RecentScansTable } from '@/features/dashboard/components/RecentScansTable';
import { ScannerCard } from '@/features/url-scanner/components/ScannerCard';

import { getDailyTip } from '@/features/dashboard/mockData';
import { fetchScanHistory, computeStats } from '@/services/scanHistoryService';
import type { RecentScan, ScanResult, StatCardConfig, DashboardStats } from '@/types/dashboard';

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

function toRecentScan(result: ScanResult): RecentScan {
  return {
    id: crypto.randomUUID(),
    url: result.url,
    riskScore: result.riskScore,
    riskLevel: result.riskLevel,
    scannedAt: result.scannedAt,
  };
}

function buildStatCards(stats: DashboardStats): StatCardConfig[] {
  return [
    { label: 'Total Scans',      value: stats.totalScans,      colour: 'cyan-400',   icon: Activity },
    { label: 'Safe URLs',        value: stats.safeUrls,        colour: 'green-400',  icon: CheckCircle },
    { label: 'Suspicious URLs',  value: stats.suspiciousUrls,  colour: 'yellow-400', icon: AlertTriangle },
    { label: 'High Risk URLs',   value: stats.highRiskUrls,    colour: 'red-400',    icon: ShieldAlert },
  ];
}

const EMPTY_STATS: DashboardStats = {
  totalScans: 0,
  safeUrls: 0,
  suspiciousUrls: 0,
  highRiskUrls: 0,
};

// ─── Component ────────────────────────────────────────────────────────────────

export function DashboardPage() {
  const { user } = useAuth();

  const [recentScans, setRecentScans]   = useState<RecentScan[]>([]);
  const [stats, setStats]               = useState<DashboardStats>(EMPTY_STATS);
  const [loadingHistory, setLoadingHistory] = useState(true);

  // Load history from Supabase on mount
  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const history = await fetchScanHistory(50);
        if (!cancelled) {
          setRecentScans(history);
          setStats(computeStats(history));
        }
      } catch {
        // History unavailable — leave empty state, don't crash
      } finally {
        if (!cancelled) setLoadingHistory(false);
      }
    }

    load();
    return () => { cancelled = true; };
  }, []);

  const handleScanComplete = useCallback((result: ScanResult) => {
    const newScan = toRecentScan(result);
    setRecentScans((prev) => [newScan, ...prev].slice(0, 50));
    setStats((prev) => ({
      totalScans:      prev.totalScans + 1,
      safeUrls:        prev.safeUrls        + (result.riskLevel === 'safe'        ? 1 : 0),
      suspiciousUrls:  prev.suspiciousUrls  + (result.riskLevel === 'suspicious'  ? 1 : 0),
      highRiskUrls:    prev.highRiskUrls    + (result.riskLevel === 'dangerous'   ? 1 : 0),
    }));
  }, []);

  const statCards = buildStatCards(stats);

  return (
    <div className="px-4 py-6 sm:px-6 lg:px-8 space-y-6 max-w-5xl w-full mx-auto">

      {/* ── Welcome Section ─────────────────────────────────────────────── */}
      <motion.section
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        aria-label="Welcome section"
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
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

        <div className="mt-4">
          <SecurityTip tip={getDailyTip()} />
        </div>
      </motion.section>

      {/* ── Quick Statistics ─────────────────────────────────────────────── */}
      <section aria-label="Quick statistics">
        <h2 className="sr-only">Quick Statistics</h2>
        <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
          {statCards.map((card, i) => (
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

      {/* ── URL Scanner ──────────────────────────────────────────────────── */}
      <DashboardCard
        title="AI Phishing URL Scanner"
        subtitle="Analyse any URL for phishing attacks using AI and security heuristics."
        delay={0.2}
        ariaLabel="URL Phishing Scanner"
      >
        <ScannerCard onScanComplete={handleScanComplete} />
      </DashboardCard>

      {/* ── Recent Scans ─────────────────────────────────────────────────── */}
      <DashboardCard
        title="Recent Scans"
        subtitle="Your latest URL analyses."
        delay={0.3}
        ariaLabel="Recent scan history"
      >
        {loadingHistory ? (
          <div className="py-8 text-center text-gray-500 text-sm">
            Loading scan history…
          </div>
        ) : (
          <RecentScansTable scans={recentScans} />
        )}
      </DashboardCard>

    </div>
  );
}
