/**
 * features/dashboard/components/RiskBadge.tsx
 *
 * Coloured pill badge that shows a scan's risk level.
 * Supports three variants: safe | suspicious | dangerous.
 */

import { Shield, AlertTriangle, ShieldAlert } from 'lucide-react';
import type { RiskLevel } from '@/types/dashboard';

interface RiskBadgeProps {
  level: RiskLevel;
  /** Show just the colour dot without text (for compact table cells) */
  compact?: boolean;
}

const config: Record<
  RiskLevel,
  { label: string; classes: string; Icon: React.ComponentType<{ className?: string }> }
> = {
  safe: {
    label: 'Safe',
    classes:
      'bg-green-500/15 text-green-400 border border-green-500/30',
    Icon: Shield,
  },
  suspicious: {
    label: 'Suspicious',
    classes:
      'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
    Icon: AlertTriangle,
  },
  dangerous: {
    label: 'Dangerous',
    classes:
      'bg-red-500/15 text-red-400 border border-red-500/30',
    Icon: ShieldAlert,
  },
};

export function RiskBadge({ level, compact = false }: RiskBadgeProps) {
  const { label, classes, Icon } = config[level];

  if (compact) {
    return (
      <span
        className={[
          'inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium',
          classes,
        ].join(' ')}
        aria-label={`Risk level: ${label}`}
      >
        <Icon className="h-3 w-3" aria-hidden="true" />
        {label}
      </span>
    );
  }

  return (
    <span
      className={[
        'inline-flex items-center gap-2 rounded-full px-4 py-1.5 text-sm font-semibold',
        classes,
      ].join(' ')}
      aria-label={`Risk level: ${label}`}
    >
      <Icon className="h-4 w-4" aria-hidden="true" />
      {label}
    </span>
  );
}
