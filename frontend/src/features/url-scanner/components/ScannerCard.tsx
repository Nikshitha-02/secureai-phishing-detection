/**
 * features/url-scanner/components/ScannerCard.tsx
 *
 * The primary URL Phishing Scanner card.
 *
 * State machine:
 *   idle → scanning → result
 *       ↑_______________|  (via "Scan Another URL" / "Clear")
 *
 * Backend integration: uses urlScannerService.scanUrl() to POST to
 * the Express API and maps the response through to ResultCard.
 * All errors (network, timeout, 4xx, 5xx) are surfaced in the
 * existing error state so the UI never needs to change.
 */

import { useState, useRef, useId } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { Search, X, Scan, AlertCircle } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { LoadingSpinner } from '@/features/dashboard/components/LoadingSpinner';
import { ResultCard } from '@/features/dashboard/components/ResultCard';
import { scanUrl } from '@/services/urlScannerService';
import type { ScanResult } from '@/types/dashboard';

type ScanState = 'idle' | 'scanning' | 'result';

interface ScannerCardProps {
  /** Called after a successful scan — lets the parent update the history list */
  onScanComplete?: (result: ScanResult) => void;
}

/** Validates that a string is an absolute HTTP/HTTPS URL. */
function isValidUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

export function ScannerCard({ onScanComplete }: ScannerCardProps) {
  const [url, setUrl] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [scanState, setScanState] = useState<ScanState>('idle');
  const [result, setResult] = useState<ScanResult | null>(null);

  const inputRef = useRef<HTMLInputElement>(null);
  const inputId = useId();
  const errorId = useId();

  // ── Handlers ──────────────────────────────────────────────────────────────

  function handleUrlChange(e: React.ChangeEvent<HTMLInputElement>) {
    setUrl(e.target.value);
    if (error) setError(null); // clear error on typing
  }

  function validate(): boolean {
    const trimmed = url.trim();
    if (!trimmed) {
      setError('Please enter a URL to scan.');
      return false;
    }
    if (!isValidUrl(trimmed)) {
      setError('Invalid URL. Make sure it starts with http:// or https://');
      return false;
    }
    return true;
  }

  async function handleScan() {
    if (!validate()) {
      inputRef.current?.focus();
      return;
    }

    setScanState('scanning');
    setError(null);

    try {
      // Real API call — replaces the former simulateScan / generateMockScanResult
      const scanResult = await scanUrl(url.trim());
      setResult(scanResult);
      setScanState('result');
      onScanComplete?.(scanResult);
    } catch (err) {
      // scanUrl() always throws a plain user-friendly string on failure
      setError(typeof err === 'string' ? err : 'An unexpected error occurred. Please try again.');
      setScanState('idle');
    }
  }

  function handleClear() {
    setUrl('');
    setError(null);
    setResult(null);
    setScanState('idle');
    setTimeout(() => inputRef.current?.focus(), 50);
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter' && scanState === 'idle') {
      handleScan();
    }
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-4">
      {/* Input area — always visible */}
      <div className="space-y-3">
        <div className="relative">
          {/* Leading icon */}
          <Search
            className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500"
            aria-hidden="true"
          />

          <input
            ref={inputRef}
            id={inputId}
            type="url"
            value={url}
            onChange={handleUrlChange}
            onKeyDown={handleKeyDown}
            placeholder="https://example.com"
            disabled={scanState === 'scanning'}
            aria-label="URL to scan"
            aria-describedby={error ? errorId : undefined}
            aria-invalid={error ? 'true' : 'false'}
            className={[
              'w-full rounded-xl border bg-gray-800/60 py-3 pl-10 pr-4',
              'text-sm text-white placeholder:text-gray-500',
              'transition-all duration-200 outline-none',
              'focus:ring-2 focus:ring-cyan-500 focus:ring-offset-1 focus:ring-offset-transparent',
              'disabled:opacity-50 disabled:cursor-not-allowed',
              error
                ? 'border-red-500/60 focus:ring-red-500'
                : 'border-white/10 hover:border-white/20 focus:border-cyan-500/50',
            ].join(' ')}
            autoComplete="url"
            spellCheck={false}
          />
        </div>

        {/* Validation / API error */}
        <AnimatePresence>
          {error && (
            <motion.p
              id={errorId}
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.2 }}
              className="flex items-center gap-2 text-sm text-red-400"
              role="alert"
            >
              <AlertCircle className="h-3.5 w-3.5 flex-shrink-0" aria-hidden="true" />
              {error}
            </motion.p>
          )}
        </AnimatePresence>

        {/* Action buttons */}
        <div className="flex gap-3">
          <Button
            variant="primary"
            size="md"
            onClick={handleScan}
            disabled={scanState === 'scanning'}
            aria-busy={scanState === 'scanning'}
            className="flex-1 sm:flex-none gap-2"
          >
            <Scan className="h-4 w-4" aria-hidden="true" />
            {scanState === 'scanning' ? 'Scanning…' : 'Scan URL'}
          </Button>
          <Button
            variant="ghost"
            size="md"
            onClick={handleClear}
            disabled={scanState === 'scanning'}
            aria-label="Clear URL input and reset"
          >
            <X className="h-4 w-4" aria-hidden="true" />
            Clear
          </Button>
        </div>
      </div>

      {/* Dynamic content area */}
      <AnimatePresence mode="wait">
        {scanState === 'scanning' && (
          <LoadingSpinner key="loading" />
        )}

        {scanState === 'result' && result && (
          <motion.div
            key="result"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.3 }}
          >
            <ResultCard result={result} />
            {/* Scan another URL link */}
            <button
              onClick={handleClear}
              className="mt-3 text-sm text-cyan-400 hover:text-cyan-300 underline underline-offset-2 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 rounded"
            >
              ← Scan another URL
            </button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
