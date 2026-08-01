/**
 * features/dashboard/components/LoadingSpinner.tsx
 *
 * Animated scanning/loading state displayed while a URL is being analysed.
 * Shows a pulsing spinner, an indeterminate progress bar, and a status message.
 */

import { motion } from 'framer-motion';
import { Loader2 } from 'lucide-react';

interface LoadingSpinnerProps {
  message?: string;
}

export function LoadingSpinner({ message = 'Analysing website…' }: LoadingSpinnerProps) {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.95 }}
      transition={{ duration: 0.25 }}
      className="flex flex-col items-center justify-center gap-5 py-10"
      role="status"
      aria-live="polite"
      aria-label={message}
    >
      {/* Spinning shield rings */}
      <div className="relative flex items-center justify-center">
        {/* Outer pulsing ring */}
        <motion.div
          animate={{ scale: [1, 1.15, 1], opacity: [0.3, 0.6, 0.3] }}
          transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
          className="absolute h-20 w-20 rounded-full border border-cyan-500/30"
          aria-hidden="true"
        />
        {/* Middle ring */}
        <motion.div
          animate={{ scale: [1, 1.08, 1], opacity: [0.4, 0.7, 0.4] }}
          transition={{ duration: 1.6, repeat: Infinity, ease: 'easeInOut', delay: 0.2 }}
          className="absolute h-14 w-14 rounded-full border border-cyan-400/40"
          aria-hidden="true"
        />
        {/* Inner spinner */}
        <Loader2
          className="h-9 w-9 animate-spin text-cyan-400"
          aria-hidden="true"
        />
      </div>

      {/* Status text */}
      <div className="text-center">
        <p className="text-base font-medium text-white">{message}</p>
        <p className="mt-1 text-sm text-gray-400">Running AI and heuristic checks…</p>
      </div>

      {/* Indeterminate progress bar */}
      <div
        className="w-64 h-1.5 rounded-full bg-gray-800 overflow-hidden"
        aria-hidden="true"
      >
        <motion.div
          className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-cyan-300"
          animate={{ x: ['-100%', '150%'] }}
          transition={{ duration: 1.4, repeat: Infinity, ease: 'easeInOut' }}
        />
      </div>
    </motion.div>
  );
}
