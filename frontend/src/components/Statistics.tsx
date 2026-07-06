import { useEffect, useRef, useState } from 'react';
import { motion, useInView } from 'framer-motion';
import { TrendingUp, Users, ShieldAlert, Clock } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

interface Stat {
  icon: LucideIcon;
  value: number;
  suffix: string;
  label: string;
  description: string;
  accent: string;
}

const stats: Stat[] = [
  {
    icon: ShieldAlert,
    value: 98,
    suffix: '%',
    label: 'Detection Accuracy',
    description: 'Phishing attempts correctly flagged',
    accent: 'text-cyan-400',
  },
  {
    icon: Clock,
    value: 200,
    suffix: 'ms',
    label: 'Avg. Scan Time',
    description: 'From submission to result',
    accent: 'text-violet-400',
  },
  {
    icon: TrendingUp,
    value: 1,
    suffix: 'M+',
    label: 'Scans Completed',
    description: 'URLs and emails analysed',
    accent: 'text-emerald-400',
  },
  {
    icon: Users,
    value: 50,
    suffix: 'K+',
    label: 'Active Users',
    description: 'Individuals and teams protected',
    accent: 'text-amber-400',
  },
];

/** Counts from 0 to `end` once the element enters the viewport. */
function AnimatedCounter({
  end,
  suffix,
  duration = 1800,
}: {
  end: number;
  suffix: string;
  duration?: number;
}) {
  const [count, setCount] = useState(0);
  const ref = useRef<HTMLSpanElement>(null);
  const inView = useInView(ref, { once: true, amount: 0.5 });

  useEffect(() => {
    if (!inView) return;

    const startTime = performance.now();
    const step = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setCount(Math.floor(eased * end));
      if (progress < 1) requestAnimationFrame(step);
    };

    requestAnimationFrame(step);
  }, [inView, end, duration]);

  return (
    <span ref={ref}>
      {count}
      {suffix}
    </span>
  );
}

export function Statistics() {
  return (
    <section
      id="statistics"
      className="relative py-24 px-4 sm:px-6 lg:px-8"
      aria-labelledby="statistics-heading"
    >
      {/* Background accent */}
      <div
        className="pointer-events-none absolute inset-0 -z-10"
        aria-hidden="true"
      >
        <div className="absolute left-1/2 top-1/2 h-[500px] w-[800px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-violet-600/8 blur-[100px]" />
      </div>

      {/* Divider line */}
      <div className="mx-auto max-w-7xl">
        <div className="h-px w-full bg-gradient-to-r from-transparent via-white/10 to-transparent mb-16" aria-hidden="true" />
      </div>

      {/* Section header */}
      <div className="mx-auto max-w-7xl text-center mb-16">
        <p className="text-xs font-semibold uppercase tracking-widest text-cyan-400 mb-3">
          By The Numbers
        </p>
        <h2
          id="statistics-heading"
          className="text-3xl font-bold text-white sm:text-4xl"
        >
          Built for scale,{' '}
          <span className="text-cyan-400">trusted by teams</span>
        </h2>
      </div>

      {/* Stats grid */}
      <ul
        className="mx-auto grid max-w-5xl gap-8 sm:grid-cols-2 lg:grid-cols-4"
        role="list"
      >
        {stats.map((stat, i) => (
          <motion.li
            key={stat.label}
            initial={{ opacity: 0, y: 24 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, amount: 0.3 }}
            transition={{ duration: 0.5, delay: i * 0.1, ease: 'easeOut' }}
            className="flex flex-col items-center text-center gap-3 rounded-2xl border border-white/5 bg-white/[0.03] p-8"
          >
            <div
              className={`inline-flex h-12 w-12 items-center justify-center rounded-xl bg-white/5 ${stat.accent}`}
              aria-hidden="true"
            >
              <stat.icon className="h-5 w-5" />
            </div>

            <p
              className={`text-4xl font-extrabold tabular-nums ${stat.accent}`}
              aria-label={`${stat.value}${stat.suffix} ${stat.label}`}
            >
              <AnimatedCounter end={stat.value} suffix={stat.suffix} />
            </p>

            <div>
              <p className="text-sm font-semibold text-white">{stat.label}</p>
              <p className="mt-1 text-xs text-gray-500">{stat.description}</p>
            </div>
          </motion.li>
        ))}
      </ul>

      {/* Bottom divider */}
      <div className="mx-auto max-w-7xl">
        <div className="h-px w-full bg-gradient-to-r from-transparent via-white/10 to-transparent mt-16" aria-hidden="true" />
      </div>
    </section>
  );
}
