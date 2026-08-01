/**
 * features/dashboard/components/RecentScansTable.tsx
 *
 * Table displaying the most recent URL scans.
 * Responsive: collapses to a card list on mobile.
 */

import { motion } from 'framer-motion';
import { Clock } from 'lucide-react';
import { RiskBadge } from './RiskBadge';
import type { RecentScan } from '@/types/dashboard';

interface RecentScansTableProps {
  scans: RecentScan[];
}

/** Format an ISO timestamp to a human-readable relative date. */
function formatDate(iso: string): string {
  const date = new Date(iso);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffHours = diffMs / (1000 * 60 * 60);
  const diffDays = diffHours / 24;

  if (diffHours < 1) return 'Just now';
  if (diffHours < 24) return `${Math.floor(diffHours)}h ago`;
  if (diffDays < 7) return `${Math.floor(diffDays)}d ago`;
  return date.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
}

/** Truncate a URL for display in the table. */
function truncateUrl(url: string, maxLength = 48): string {
  try {
    const { hostname, pathname } = new URL(url);
    const short = hostname + pathname;
    return short.length > maxLength ? short.slice(0, maxLength) + '…' : short;
  } catch {
    return url.length > maxLength ? url.slice(0, maxLength) + '…' : url;
  }
}

/** Score colour for the numeric value */
function scoreClass(score: number): string {
  if (score < 30) return 'text-green-400';
  if (score < 65) return 'text-yellow-400';
  return 'text-red-400';
}

export function RecentScansTable({ scans }: RecentScansTableProps) {
  if (scans.length === 0) {
    return (
      <div className="py-12 text-center text-gray-500 text-sm">
        No scans yet. Enter a URL above to get started.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto -mx-1">
      {/* Desktop table */}
      <table className="hidden md:table w-full text-sm" aria-label="Recent scans">
        <thead>
          <tr className="border-b border-white/8">
            <th className="text-left py-3 px-4 text-xs font-medium uppercase tracking-wider text-gray-500 w-full">URL</th>
            <th className="text-center py-3 px-4 text-xs font-medium uppercase tracking-wider text-gray-500 whitespace-nowrap">Risk Score</th>
            <th className="text-center py-3 px-4 text-xs font-medium uppercase tracking-wider text-gray-500 whitespace-nowrap">Status</th>
            <th className="text-right py-3 px-4 text-xs font-medium uppercase tracking-wider text-gray-500 whitespace-nowrap">Date</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan, i) => (
            <motion.tr
              key={scan.id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3, delay: 0.04 * i }}
              className="border-b border-white/5 hover:bg-white/[0.02] transition-colors"
            >
              <td className="py-3 px-4">
                <span
                  className="font-mono text-gray-300 text-xs"
                  title={scan.url}
                >
                  {truncateUrl(scan.url)}
                </span>
              </td>
              <td className="py-3 px-4 text-center">
                <span className={`font-bold tabular-nums ${scoreClass(scan.riskScore)}`}>
                  {scan.riskScore}
                </span>
                <span className="text-gray-600">/100</span>
              </td>
              <td className="py-3 px-4 text-center">
                <RiskBadge level={scan.riskLevel} compact />
              </td>
              <td className="py-3 px-4 text-right">
                <span className="text-gray-500 text-xs whitespace-nowrap flex items-center justify-end gap-1">
                  <Clock className="h-3 w-3" aria-hidden="true" />
                  {formatDate(scan.scannedAt)}
                </span>
              </td>
            </motion.tr>
          ))}
        </tbody>
      </table>

      {/* Mobile card list */}
      <ul className="flex flex-col gap-3 md:hidden" aria-label="Recent scans">
        {scans.map((scan, i) => (
          <motion.li
            key={scan.id}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3, delay: 0.04 * i }}
            className="rounded-xl border border-white/8 bg-white/[0.02] px-4 py-3 space-y-2"
          >
            <p
              className="font-mono text-xs text-gray-300 truncate"
              title={scan.url}
            >
              {scan.url}
            </p>
            <div className="flex items-center justify-between">
              <RiskBadge level={scan.riskLevel} compact />
              <div className="flex items-center gap-3 text-xs text-gray-500">
                <span className={`font-bold tabular-nums ${scoreClass(scan.riskScore)}`}>
                  {scan.riskScore}/100
                </span>
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3" aria-hidden="true" />
                  {formatDate(scan.scannedAt)}
                </span>
              </div>
            </div>
          </motion.li>
        ))}
      </ul>
    </div>
  );
}
