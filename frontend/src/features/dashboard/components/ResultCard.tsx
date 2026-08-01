/**
 * features/dashboard/components/ResultCard.tsx
 *
 * Displays the full result of a URL phishing scan:
 *   • Risk score dial
 *   • Risk level badge
 *   • Security checks table
 *   • Overall verdict
 */

import { motion } from 'framer-motion';
import { CheckCircle2, XCircle, Globe } from 'lucide-react';
import { RiskBadge } from './RiskBadge';
import type { ScanResult } from '@/types/dashboard';

interface ResultCardProps {
  result: ScanResult;
}

/** Colour classes for the score circle based on risk level */
const scoreColour: Record<ScanResult['riskLevel'], string> = {
  safe: 'text-green-400',
  suspicious: 'text-yellow-400',
  dangerous: 'text-red-400',
};

const scoreBg: Record<ScanResult['riskLevel'], string> = {
  safe: 'border-green-500/40 shadow-green-500/20',
  suspicious: 'border-yellow-500/40 shadow-yellow-500/20',
  dangerous: 'border-red-500/40 shadow-red-500/20',
};

export function ResultCard({ result }: ResultCardProps) {
  const { url, riskScore, riskLevel, verdict, checks } = result;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45, ease: 'easeOut' }}
      className="rounded-2xl border border-white/10 bg-gray-900/80 backdrop-blur-sm p-6 space-y-6"
      role="region"
      aria-label="Scan result"
    >
      {/* ── Header: score + badge ─────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center gap-5">
        {/* Score circle */}
        <div
          className={[
            'flex-shrink-0 flex flex-col items-center justify-center',
            'h-24 w-24 rounded-full border-4 shadow-lg',
            scoreBg[riskLevel],
          ].join(' ')}
          aria-label={`Risk score: ${riskScore} out of 100`}
        >
          <span className={`text-3xl font-bold tabular-nums leading-none ${scoreColour[riskLevel]}`}>
            {riskScore}
          </span>
          <span className="text-xs text-gray-400 mt-0.5">/ 100</span>
        </div>

        <div className="space-y-2">
          <RiskBadge level={riskLevel} />
          <div className="flex items-center gap-1.5 min-w-0">
            <Globe className="h-3.5 w-3.5 flex-shrink-0 text-gray-500" aria-hidden="true" />
            <p
              className="text-sm text-gray-400 truncate max-w-xs sm:max-w-sm md:max-w-md"
              title={url}
            >
              {url}
            </p>
          </div>
        </div>
      </div>

      {/* ── Security Checks Table ──────────────────────────────────────── */}
      <div>
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-gray-500">
          Security Checks
        </h3>
        <div
          className="rounded-xl overflow-hidden border border-white/8"
          role="table"
          aria-label="Security checks"
        >
          {/* Table head */}
          <div
            className="grid grid-cols-3 bg-white/5 px-4 py-2"
            role="row"
          >
            <span className="text-xs font-medium uppercase tracking-wider text-gray-500" role="columnheader">Check</span>
            <span className="text-xs font-medium uppercase tracking-wider text-gray-500" role="columnheader">Result</span>
            <span className="text-xs font-medium uppercase tracking-wider text-gray-500 text-right" role="columnheader">Status</span>
          </div>

          {/* Rows */}
          {checks.map((check, i) => (
            <motion.div
              key={check.label}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.25, delay: 0.05 * i }}
              className={[
                'grid grid-cols-3 items-center px-4 py-3',
                i % 2 === 0 ? 'bg-transparent' : 'bg-white/[0.02]',
                'border-t border-white/5',
              ].join(' ')}
              role="row"
            >
              <span className="text-sm text-gray-300" role="cell">{check.label}</span>
              <span className="text-sm text-gray-400" role="cell">{check.value}</span>
              <span className="flex justify-end" role="cell">
                {check.passed ? (
                  <CheckCircle2
                    className="h-4.5 w-4.5 text-green-400"
                    aria-label="Passed"
                  />
                ) : (
                  <XCircle
                    className="h-4.5 w-4.5 text-red-400"
                    aria-label="Failed"
                  />
                )}
              </span>
            </motion.div>
          ))}
        </div>
      </div>

      {/* ── Overall Verdict ────────────────────────────────────────────── */}
      <div
        className={[
          'rounded-xl border px-4 py-3',
          riskLevel === 'safe'
            ? 'border-green-500/20 bg-green-500/5'
            : riskLevel === 'suspicious'
              ? 'border-yellow-500/20 bg-yellow-500/5'
              : 'border-red-500/20 bg-red-500/5',
        ].join(' ')}
        role="status"
        aria-live="polite"
      >
        <p className="text-sm font-medium text-gray-300">
          <span className="font-semibold text-white">Overall verdict: </span>
          {verdict}
        </p>
      </div>
    </motion.div>
  );
}
