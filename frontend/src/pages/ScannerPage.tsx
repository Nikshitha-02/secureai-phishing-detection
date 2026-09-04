/**
 * pages/ScannerPage.tsx
 *
 * Full-page URL scanner, rendered at /scanner inside DashboardLayout.
 *
 * Uses the existing ScannerCard (which already calls the backend /api/scan
 * via urlScannerService) and displays the ResultCard on completion.
 * No scanning logic is duplicated here.
 */

import { useState, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Scan, ShieldCheck } from 'lucide-react';

import { DashboardCard } from '@/features/dashboard/components/DashboardCard';
import { ScannerCard } from '@/features/url-scanner/components/ScannerCard';
import type { ScanResult } from '@/types/dashboard';

export function ScannerPage() {
  const [lastResult, setLastResult] = useState<ScanResult | null>(null);

  const handleScanComplete = useCallback((result: ScanResult) => {
    setLastResult(result);
  }, []);

  return (
    <div className="px-4 py-6 sm:px-6 lg:px-8 space-y-6 max-w-3xl w-full mx-auto">

      {/* Page header */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35 }}
        className="flex items-start gap-4"
      >
        <div className="flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-2xl bg-cyan-500/15 border border-cyan-500/25">
          <Scan className="h-6 w-6 text-cyan-400" aria-hidden="true" />
        </div>
        <div>
          <h2 className="text-xl font-bold text-white">URL Scanner</h2>
          <p className="mt-0.5 text-sm text-gray-400">
            Paste any URL to check it for phishing indicators using AI and security heuristics.
          </p>
        </div>
      </motion.div>

      {/* Scanner card */}
      <DashboardCard
        title="Analyse a URL"
        subtitle="Enter a full URL starting with http:// or https://"
        delay={0.1}
        ariaLabel="URL scanner input"
      >
        <ScannerCard onScanComplete={handleScanComplete} />
      </DashboardCard>

      {/* Informational note if no scan yet */}
      {!lastResult && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.4, delay: 0.2 }}
          className="rounded-2xl border border-white/8 bg-gray-900/40 p-5 flex items-start gap-3"
        >
          <ShieldCheck className="h-5 w-5 text-cyan-400 flex-shrink-0 mt-0.5" aria-hidden="true" />
          <div className="text-sm text-gray-400 space-y-1">
            <p className="font-medium text-gray-300">How it works</p>
            <ul className="list-disc list-inside space-y-0.5 text-gray-500">
              <li>Checks for HTTPS, suspicious keywords, known phishing patterns</li>
              <li>Analyses domain age, URL structure, and encoded characters</li>
              <li>AI (Gemini) explains why a URL may be suspicious</li>
              <li>Returns a risk score from 0 (safe) to 100 (dangerous)</li>
            </ul>
          </div>
        </motion.div>
      )}
    </div>
  );
}
