import type { LucideIcon } from 'lucide-react';
import { Link2, Mail, BrainCircuit, BarChart3 } from 'lucide-react';
import { motion } from 'framer-motion';
import type { Variants } from 'framer-motion';

interface Feature {
  icon: LucideIcon;
  title: string;
  description: string;
  accent: string;
}

const features: Feature[] = [
  {
    icon: Link2,
    title: 'URL Phishing Detection',
    description:
      'Paste any URL and get an instant AI-generated risk assessment. SecureAI dissects domain age, redirect chains, SSL certificates, and known phishing patterns.',
    accent: 'text-cyan-400',
  },
  {
    icon: Mail,
    title: 'Email Phishing Detection',
    description:
      'Analyse suspicious email content for social engineering tactics, spoofed sender addresses, urgent language traps, and malicious attachment indicators.',
    accent: 'text-violet-400',
  },
  {
    icon: BrainCircuit,
    title: 'AI Threat Analysis',
    description:
      'Powered by Google Gemini. Not just a score — you get a plain-language explanation of every suspicious signal so you understand the threat, not just the verdict.',
    accent: 'text-emerald-400',
  },
  {
    icon: BarChart3,
    title: 'Security Reports',
    description:
      'Every scan is stored in your personal history. Track threats over time, export reports, and spot patterns across the URLs and emails you analyse.',
    accent: 'text-amber-400',
  },
];

/** Viewport-triggered fade-up for each card */
const cardVariants: Variants = {
  hidden: { opacity: 0, y: 32 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.5, ease: [0.25, 0.1, 0.25, 1] },
  },
};

export function FeatureCards() {
  return (
    <section
      id="features"
      className="relative py-24 px-4 sm:px-6 lg:px-8"
      aria-labelledby="features-heading"
    >
      {/* Section header */}
      <div className="mx-auto max-w-7xl text-center mb-16">
        <p className="text-xs font-semibold uppercase tracking-widest text-cyan-400 mb-3">
          What We Do
        </p>
        <h2
          id="features-heading"
          className="text-3xl font-bold text-white sm:text-4xl"
        >
          Everything you need to stay{' '}
          <span className="text-cyan-400">one step ahead</span>
        </h2>
        <p className="mx-auto mt-4 max-w-xl text-gray-400">
          Four core capabilities built for individuals and security teams who
          need fast, explainable threat intelligence.
        </p>
      </div>

      {/* Card grid */}
      <ul
        className="mx-auto grid max-w-7xl gap-6 sm:grid-cols-2 lg:grid-cols-4"
        role="list"
      >
        {features.map((feature, i) => (
          <motion.li
            key={feature.title}
            variants={cardVariants}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, amount: 0.2 }}
            transition={{ delay: i * 0.1 }}
            className="group relative flex flex-col gap-4 rounded-2xl border border-white/5 bg-white/[0.03] p-6 backdrop-blur-sm
              hover:border-cyan-500/30 hover:bg-white/[0.06] transition-all duration-300"
          >
            {/* Hover glow blob */}
            <div
              className="pointer-events-none absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500"
              style={{
                background:
                  'radial-gradient(circle at top left, rgba(6,182,212,0.07), transparent 60%)',
              }}
              aria-hidden="true"
            />

            {/* Icon */}
            <div
              className={`inline-flex h-11 w-11 items-center justify-center rounded-xl bg-white/5 ${feature.accent}`}
              aria-hidden="true"
            >
              <feature.icon className="h-5 w-5" />
            </div>

            {/* Text */}
            <div>
              <h3 className="text-base font-semibold text-white">
                {feature.title}
              </h3>
              <p className="mt-2 text-sm leading-relaxed text-gray-400">
                {feature.description}
              </p>
            </div>
          </motion.li>
        ))}
      </ul>
    </section>
  );
}
