/**
 * pages/ReportsPage.tsx
 *
 * Security reports page, rendered at /reports inside DashboardLayout.
 *
 * Pulls real scan history from Supabase and computes statistics using
 * the existing computeStats() helper. No hardcoded data.
 */

import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
  BarChart2,
  Activity,
  CheckCircle,
  AlertTriangle,
  ShieldAlert,
  RefreshCw,
  AlertCircle,
} from 'lucide-react';

import { DashboardCard } from '@/features/dashboard/components/DashboardCard';
import { StatCard } from '@/features/dashboard/components/StatCard';
import { RiskBadge } from '@/features/dashboard/components/RiskBadge';
import { fetchScanHistory, computeStats } from '@/services/scanHistoryService';
import type { DashboardStats, RecentScan, StatCardConfig } from '@/types/dashboard';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function buildStatCards(stats: DashboardStats): StatCardConfig[] {
  return [
    { label: 'Total Scans',     value: stats.totalScans,     colour: 'cyan-400',   icon: Activity },
    { label: 'Safe URLs',       value: stats.safeUrls,       colour: 'green-400',  icon: CheckCircle },
    { label: 'Suspicious URLs', value: stats.suspiciousUrls, colour: 'yellow-400', icon: AlertTriangle },
    { label: 'High Risk URLs',  value: stats.highRiskUrls,   colour: 'red-400',    icon: ShieldAlert },
  ];
}

/** Percentage of total, returns "–" when total is 0. */
function pct(part: number, total: number): string {
  if (total === 0) return '–';
  return `${Math.round((part / total) * 100)}%`;
}

/** Width percentage for the bar, clamped to 100. */
function barWidth(part: number, total: number): string {
  if (total === 0) return '0%';
  return `${Math.min(100, Math.round((part / total) * 100))}%`;
}

const EMPTY_STATS: DashboardStats = {
  totalScans: 0,
  safeUrls: 0,
  suspiciousUrls: 0,
  highRiskUrls: 0,
};

// ─── Component ────────────────────────────────────────────────────────────────

type LoadState = 'loading' | 'success' | 'error';

export function ReportsPage() {
  const [stats, setStats]         = useState<DashboardStats>(EMPTY_STATS);
  const [scans, setScans]         = useState<RecentScan[]>([]);
  const [loadState, setLoadState] = useState<LoadState>('loading');
  const [errorMsg, setErrorMsg]   = useState('');

  async function load() {
    setLoadState('loading');
    setErrorMsg('');
    try {
      const data = await fetchScanHistory(500);
      setScans(data);
      setStats(computeStats(data));
      setLoadState('success');
    } catch (err) {
      setErrorMsg(typeof err === 'string' ? err : 'Failed to load report data.');
      setLoadState('error');
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const statCards = buildStatCards(stats);

  // Most recent 5 scans for the quick summary table
  const latestScans = scans.slice(0, 5);

  return (
    <div className="px-4 py-6 sm:px-6 lg:px-8 space-y-6 max-w-5xl w-full mx-auto">

      {/* Page header */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35 }}
        className="flex items-start justify-between gap-4"
      >
        <div className="flex items-start gap-4">
          <div className="flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-2xl bg-cyan-500/15 border border-cyan-500/25">
            <BarChart2 className="h-6 w-6 text-cyan-400" aria-hidden="true" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">Reports</h2>
            <p className="mt-0.5 text-sm text-gray-400">
              Aggregated statistics from your real scan history.
            </p>
          </div>
        </div>

        <button
          onClick={load}
          disabled={loadState === 'loading'}
          aria-label="Refresh reports"
          className={[
            'flex items-center gap-2 rounded-xl border border-white/10 bg-gray-900/60',
            'px-3 py-2 text-sm text-gray-400 transition-colors',
            'hover:bg-white/5 hover:text-white',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500',
            'disabled:opacity-50 disabled:cursor-not-allowed',
          ].join(' ')}
        >
          <RefreshCw
            className={`h-4 w-4 ${loadState === 'loading' ? 'animate-spin' : ''}`}
            aria-hidden="true"
          />
          <span className="hidden sm:inline">Refresh</span>
        </button>
      </motion.div>

      {/* Loading state */}
      {loadState === 'loading' && (
        <div className="flex flex-col items-center justify-center py-20 gap-3">
          <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" aria-hidden="true" />
          <p className="text-sm text-gray-500">Loading report data…</p>
        </div>
      )}

      {/* Error state */}
      {loadState === 'error' && (
        <div className="flex flex-col items-center justify-center py-20 gap-3">
          <AlertCircle className="h-8 w-8 text-red-400" aria-hidden="true" />
          <p className="text-sm text-red-400">{errorMsg}</p>
          <button
            onClick={load}
            className="text-sm text-cyan-400 hover:text-cyan-300 underline underline-offset-2 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 rounded"
          >
            Try again
          </button>
        </div>
      )}

      {/* Success state */}
      {loadState === 'success' && (
        <>
          {/* ── Stat Cards ──────────────────────────────────────────────── */}
          <section aria-label="Report statistics">
            <h3 className="sr-only">Statistics</h3>
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

          {/* ── Risk breakdown bar ───────────────────────────────────────── */}
          <DashboardCard
            title="Risk Breakdown"
            subtitle="Distribution of your scan results by risk level."
            delay={0.2}
            ariaLabel="Risk level breakdown"
          >
            {stats.totalScans === 0 ? (
              <p className="py-6 text-center text-sm text-gray-500">
                No scan data yet. Run some scans first.
              </p>
            ) : (
              <div className="space-y-4">
                {/* Safe */}
                <div className="space-y-1">
                  <div className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-2">
                      <RiskBadge level="safe" compact />
                    </div>
                    <span className="text-gray-400 tabular-nums">
                      {stats.safeUrls} &nbsp;
                      <span className="text-gray-600">({pct(stats.safeUrls, stats.totalScans)})</span>
                    </span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-white/5 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: barWidth(stats.safeUrls, stats.totalScans) }}
                      transition={{ duration: 0.8, ease: 'easeOut', delay: 0.1 }}
                      className="h-full rounded-full bg-green-400"
                      aria-hidden="true"
                    />
                  </div>
                </div>

                {/* Suspicious */}
                <div className="space-y-1">
                  <div className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-2">
                      <RiskBadge level="suspicious" compact />
                    </div>
                    <span className="text-gray-400 tabular-nums">
                      {stats.suspiciousUrls} &nbsp;
                      <span className="text-gray-600">({pct(stats.suspiciousUrls, stats.totalScans)})</span>
                    </span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-white/5 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: barWidth(stats.suspiciousUrls, stats.totalScans) }}
                      transition={{ duration: 0.8, ease: 'easeOut', delay: 0.2 }}
                      className="h-full rounded-full bg-yellow-400"
                      aria-hidden="true"
                    />
                  </div>
                </div>

                {/* Dangerous */}
                <div className="space-y-1">
                  <div className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-2">
                      <RiskBadge level="dangerous" compact />
                    </div>
                    <span className="text-gray-400 tabular-nums">
                      {stats.highRiskUrls} &nbsp;
                      <span className="text-gray-600">({pct(stats.highRiskUrls, stats.totalScans)})</span>
                    </span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-white/5 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: barWidth(stats.highRiskUrls, stats.totalScans) }}
                      transition={{ duration: 0.8, ease: 'easeOut', delay: 0.3 }}
                      className="h-full rounded-full bg-red-400"
                      aria-hidden="true"
                    />
                  </div>
                </div>
              </div>
            )}
          </DashboardCard>

          {/* ── Most recent scans (mini summary) ────────────────────────── */}
          {latestScans.length > 0 && (
            <DashboardCard
              title="Most Recent Scans"
              subtitle="Your 5 latest scans."
              delay={0.3}
              ariaLabel="Most recent scans summary"
            >
              <ul className="divide-y divide-white/5">
                {latestScans.map((scan) => (
                  <li
                    key={scan.id}
                    className="flex items-center justify-between gap-3 py-3 text-sm"
                  >
                    <span
                      className="font-mono text-gray-300 text-xs truncate flex-1 min-w-0"
                      title={scan.url}
                    >
                      {scan.url}
                    </span>
                    <div className="flex items-center gap-3 flex-shrink-0">
                      <span
                        className={[
                          'tabular-nums font-bold text-xs',
                          scan.riskScore < 30
                            ? 'text-green-400'
                            : scan.riskScore < 65
                              ? 'text-yellow-400'
                              : 'text-red-400',
                        ].join(' ')}
                      >
                        {scan.riskScore}/100
                      </span>
                      <RiskBadge level={scan.riskLevel} compact />
                    </div>
                  </li>
                ))}
              </ul>
            </DashboardCard>
          )}
        </>
      )}
    </div>
  );
}
