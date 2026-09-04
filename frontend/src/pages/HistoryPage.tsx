/**
 * pages/HistoryPage.tsx
 *
 * Full scan history for the authenticated user, rendered at /history.
 *
 * Fetches scans from Supabase (scan_results table filtered by user_id)
 * using the existing scanHistoryService. Shows loading, empty, and error states.
 */

import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { History, RefreshCw, AlertCircle, ClipboardList } from 'lucide-react';

import { DashboardCard } from '@/features/dashboard/components/DashboardCard';
import { RecentScansTable } from '@/features/dashboard/components/RecentScansTable';
import { fetchScanHistory } from '@/services/scanHistoryService';
import type { RecentScan } from '@/types/dashboard';

type LoadState = 'loading' | 'success' | 'error';

export function HistoryPage() {
  const [scans, setScans]         = useState<RecentScan[]>([]);
  const [loadState, setLoadState] = useState<LoadState>('loading');
  const [errorMsg, setErrorMsg]   = useState<string>('');

  async function load() {
    setLoadState('loading');
    setErrorMsg('');
    try {
      const data = await fetchScanHistory(200);
      setScans(data);
      setLoadState('success');
    } catch (err) {
      setErrorMsg(typeof err === 'string' ? err : 'Failed to load history.');
      setLoadState('error');
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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
            <History className="h-6 w-6 text-cyan-400" aria-hidden="true" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">Scan History</h2>
            <p className="mt-0.5 text-sm text-gray-400">
              All URLs you have previously scanned, newest first.
            </p>
          </div>
        </div>

        {/* Refresh button */}
        <button
          onClick={load}
          disabled={loadState === 'loading'}
          aria-label="Refresh scan history"
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

      {/* Content */}
      <DashboardCard
        title={
          loadState === 'success'
            ? `${scans.length} scan${scans.length !== 1 ? 's' : ''} found`
            : 'Your scan history'
        }
        delay={0.1}
        ariaLabel="Scan history table"
      >
        {/* Loading */}
        {loadState === 'loading' && (
          <div className="flex flex-col items-center justify-center py-16 gap-3">
            <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" aria-hidden="true" />
            <p className="text-sm text-gray-500">Loading your scan history…</p>
          </div>
        )}

        {/* Error */}
        {loadState === 'error' && (
          <div className="flex flex-col items-center justify-center py-16 gap-3">
            <AlertCircle className="h-8 w-8 text-red-400" aria-hidden="true" />
            <p className="text-sm text-red-400 font-medium">
              {errorMsg || 'Failed to load history.'}
            </p>
            <button
              onClick={load}
              className="mt-2 text-sm text-cyan-400 hover:text-cyan-300 underline underline-offset-2 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 rounded"
            >
              Try again
            </button>
          </div>
        )}

        {/* Empty */}
        {loadState === 'success' && scans.length === 0 && (
          <div className="flex flex-col items-center justify-center py-16 gap-3">
            <ClipboardList className="h-8 w-8 text-gray-600" aria-hidden="true" />
            <p className="text-sm text-gray-500">No scans yet.</p>
            <p className="text-xs text-gray-600">
              Head to the Scanner page and scan your first URL.
            </p>
          </div>
        )}

        {/* Data */}
        {loadState === 'success' && scans.length > 0 && (
          <RecentScansTable scans={scans} />
        )}
      </DashboardCard>
    </div>
  );
}
