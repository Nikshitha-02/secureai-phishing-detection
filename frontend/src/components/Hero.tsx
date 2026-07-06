import { ArrowRight, ShieldCheck, Play } from 'lucide-react';
import { motion } from 'framer-motion';
import type { Variants } from 'framer-motion';
import { Button } from '@/components/ui/Button';

/** Staggered fade-up animation for hero children */
const container: Variants = {
  hidden: {},
  show: {
    transition: {
      staggerChildren: 0.12,
    },
  },
};

const item: Variants = {
  hidden: { opacity: 0, y: 24 },
  show: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.5, ease: [0.25, 0.1, 0.25, 1] },
  },
};

export function Hero() {
  return (
    <section
      className="relative flex min-h-screen flex-col items-center justify-center overflow-hidden px-4 pt-24 pb-16 text-center sm:px-6 lg:px-8"
      aria-labelledby="hero-heading"
    >
      {/* Ambient background glow */}
      <div
        className="pointer-events-none absolute inset-0 -z-10"
        aria-hidden="true"
      >
        {/* Top-centre radial */}
        <div className="absolute left-1/2 top-0 h-[600px] w-[900px] -translate-x-1/2 -translate-y-1/3 rounded-full bg-cyan-500/10 blur-[120px]" />
        {/* Bottom-left accent */}
        <div className="absolute -bottom-32 -left-32 h-72 w-72 rounded-full bg-violet-600/10 blur-[80px]" />
        {/* Dot-grid overlay */}
        <div
          className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage:
              'radial-gradient(circle, #fff 1px, transparent 1px)',
            backgroundSize: '32px 32px',
          }}
        />
      </div>

      <motion.div
        className="mx-auto max-w-4xl"
        variants={container}
        initial="hidden"
        animate="show"
      >
        {/* Badge */}
        <motion.div variants={item} className="mb-6 inline-flex">
          <span className="flex items-center gap-2 rounded-full border border-cyan-500/30 bg-cyan-500/10 px-4 py-1.5 text-xs font-semibold uppercase tracking-widest text-cyan-400">
            <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
            AI-Powered Cybersecurity
          </span>
        </motion.div>

        {/* Headline */}
        <motion.h1
          id="hero-heading"
          variants={item}
          className="text-4xl font-extrabold leading-tight tracking-tight text-white sm:text-5xl lg:text-6xl xl:text-7xl"
        >
          AI-Powered{' '}
          <span className="bg-gradient-to-r from-cyan-400 to-violet-400 bg-clip-text text-transparent">
            Phishing Detection
          </span>{' '}
          &amp; Security Assistant
        </motion.h1>

        {/* Subtitle */}
        <motion.p
          variants={item}
          className="mx-auto mt-6 max-w-2xl text-base leading-relaxed text-gray-400 sm:text-lg"
        >
          Protect yourself and your organisation from phishing attacks.
          SecureAI uses Google Gemini to analyse URLs and emails in real time,
          delivers an instant risk score, and explains exactly why a threat is
          suspicious — so you always know what to do next.
        </motion.p>

        {/* CTA buttons */}
        <motion.div
          variants={item}
          className="mt-10 flex flex-col items-center gap-4 sm:flex-row sm:justify-center"
        >
          <Button
            variant="primary"
            size="lg"
            aria-label="Start scanning for phishing threats"
          >
            Scan Now
            <ArrowRight className="h-4 w-4" aria-hidden="true" />
          </Button>
          <Button
            variant="outline"
            size="lg"
            aria-label="Learn more about SecureAI features"
          >
            <Play className="h-4 w-4" aria-hidden="true" />
            Learn More
          </Button>
        </motion.div>

        {/* Social proof strip */}
        <motion.p variants={item} className="mt-8 text-xs text-gray-600">
          Trusted by security teams &nbsp;·&nbsp; No credit card required
          &nbsp;·&nbsp; Free tier available
        </motion.p>
      </motion.div>

      {/* Scroll-down indicator */}
      <motion.div
        className="absolute bottom-8 left-1/2 -translate-x-1/2"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.2, duration: 0.6 }}
        aria-hidden="true"
      >
        <motion.div
          className="flex h-10 w-6 items-start justify-center rounded-full border-2 border-white/20 pt-1.5"
          animate={{ y: [0, 4, 0] }}
          transition={{ duration: 1.6, repeat: Infinity, ease: 'easeInOut' }}
        >
          <div className="h-2 w-1 rounded-full bg-cyan-400/70" />
        </motion.div>
      </motion.div>
    </section>
  );
}
