/**
 * features/dashboard/components/SecurityTip.tsx
 *
 * Displays a daily security tip in a styled callout banner.
 */

import { Lightbulb } from 'lucide-react';
import { motion } from 'framer-motion';

interface SecurityTipProps {
  tip: string;
}

export function SecurityTip({ tip }: SecurityTipProps) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.4, ease: 'easeOut', delay: 0.2 }}
      className={[
        'flex items-start gap-3 rounded-xl',
        'border border-cyan-500/20 bg-cyan-500/5',
        'px-4 py-3',
      ].join(' ')}
      role="complementary"
      aria-label="Daily security tip"
    >
      <Lightbulb
        className="mt-0.5 h-4 w-4 flex-shrink-0 text-cyan-400"
        aria-hidden="true"
      />
      <p className="text-sm text-gray-300 leading-relaxed">
        <span className="font-semibold text-cyan-400">Tip: </span>
        {tip}
      </p>
    </motion.div>
  );
}
