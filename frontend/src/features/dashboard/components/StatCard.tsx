/**
 * features/dashboard/components/StatCard.tsx
 *
 * A single statistic card shown in the quick-stats row.
 * Renders an icon, a numeric value (with count-up animation), and a label.
 */

import { useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import type { StatCardConfig } from '@/types/dashboard';

interface StatCardProps extends Omit<StatCardConfig, 'icon'> {
  icon: React.ComponentType<{ className?: string }>;
  delay?: number;
}

/** Simple count-up hook that animates from 0 to `target` over `duration` ms. */
function useCountUp(target: number, duration = 1200, startDelay = 0) {
  const [current, setCurrent] = useState(0);
  const raf = useRef<number | null>(null);
  const timeout = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    timeout.current = setTimeout(() => {
      const start = performance.now();

      const tick = (now: number) => {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        // Ease-out cubic
        const eased = 1 - Math.pow(1 - progress, 3);
        setCurrent(Math.round(eased * target));

        if (progress < 1) {
          raf.current = requestAnimationFrame(tick);
        }
      };

      raf.current = requestAnimationFrame(tick);
    }, startDelay);

    return () => {
      if (raf.current !== null) cancelAnimationFrame(raf.current);
      if (timeout.current !== null) clearTimeout(timeout.current);
    };
  }, [target, duration, startDelay]);

  return current;
}

// Map colour token → Tailwind classes (avoids dynamic class purge issues)
const colourMap: Record<string, { icon: string; glow: string; border: string }> = {
  'cyan-400': {
    icon: 'text-cyan-400',
    glow: 'shadow-cyan-500/20',
    border: 'border-cyan-500/20',
  },
  'green-400': {
    icon: 'text-green-400',
    glow: 'shadow-green-500/20',
    border: 'border-green-500/20',
  },
  'yellow-400': {
    icon: 'text-yellow-400',
    glow: 'shadow-yellow-500/20',
    border: 'border-yellow-500/20',
  },
  'red-400': {
    icon: 'text-red-400',
    glow: 'shadow-red-500/20',
    border: 'border-red-500/20',
  },
};

export function StatCard({ label, value, colour, icon: Icon, delay = 0 }: StatCardProps) {
  const displayValue = useCountUp(value, 1000, delay * 1000 + 200);
  const colours = colourMap[colour] ?? colourMap['cyan-400'];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: 'easeOut', delay }}
      className={[
        'relative rounded-2xl border bg-gray-900/60 backdrop-blur-sm p-5',
        'shadow-lg flex flex-col gap-3',
        colours.border,
        colours.glow,
      ].join(' ')}
      role="figure"
      aria-label={`${label}: ${value}`}
    >
      {/* Icon bubble */}
      <div
        className={[
          'flex h-10 w-10 items-center justify-center rounded-xl',
          'bg-white/5 border border-white/10',
        ].join(' ')}
        aria-hidden="true"
      >
        <Icon className={`h-5 w-5 ${colours.icon}`} />
      </div>

      {/* Value */}
      <div>
        <p className="text-3xl font-bold tabular-nums text-white" aria-hidden="true">
          {displayValue.toLocaleString()}
        </p>
        <p className="mt-1 text-sm text-gray-400">{label}</p>
      </div>
    </motion.div>
  );
}
