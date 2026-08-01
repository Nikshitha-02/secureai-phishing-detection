/**
 * features/dashboard/components/DashboardCard.tsx
 *
 * Generic card wrapper for dashboard sections.
 * Provides consistent dark-glass styling, optional title/subtitle, and
 * a Framer Motion fade-in-up entrance animation.
 */

import { type ReactNode } from 'react';
import { motion } from 'framer-motion';

interface DashboardCardProps {
  /** Card heading */
  title?: string;
  /** Optional subtitle rendered beneath the title */
  subtitle?: string;
  /** Card body content */
  children: ReactNode;
  /** Extra Tailwind classes applied to the outer wrapper */
  className?: string;
  /** Stagger delay in seconds (for list animations) */
  delay?: number;
  /** Accessible landmark role — defaults to "region" if a title is provided */
  role?: string;
  /** aria-label override (used when role is set but title is not visible) */
  ariaLabel?: string;
}

export function DashboardCard({
  title,
  subtitle,
  children,
  className = '',
  delay = 0,
  role,
  ariaLabel,
}: DashboardCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: 'easeOut', delay }}
      role={role ?? (title ? 'region' : undefined)}
      aria-label={ariaLabel ?? title}
      className={[
        'rounded-2xl border border-white/10 bg-gray-900/60 backdrop-blur-sm',
        'shadow-xl shadow-black/20 p-6',
        className,
      ]
        .filter(Boolean)
        .join(' ')}
    >
      {(title || subtitle) && (
        <div className="mb-5">
          {title && (
            <h2 className="text-lg font-semibold text-white leading-tight">{title}</h2>
          )}
          {subtitle && (
            <p className="mt-1 text-sm text-gray-400">{subtitle}</p>
          )}
        </div>
      )}
      {children}
    </motion.div>
  );
}
