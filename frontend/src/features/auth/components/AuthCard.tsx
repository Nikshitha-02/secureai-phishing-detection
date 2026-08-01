/**
 * features/auth/components/AuthCard.tsx
 *
 * The centred card shell shared by all auth pages (Login, Register,
 * Forgot Password, Email Verification).
 *
 * Renders:
 *   • Full-screen background with a subtle gradient that matches the landing page.
 *   • A centred frosted-glass card with the SecureAI shield logo + title.
 *   • An optional subtitle / tagline beneath the title.
 *   • A slot (`children`) for the form body.
 *
 * All auth pages import this instead of duplicating the layout.
 */

import type { ReactNode } from 'react';
import { Shield } from 'lucide-react';
import { Link } from 'react-router-dom';

interface AuthCardProps {
  /** Main heading inside the card, e.g. "Welcome back" */
  title: string;
  /** Optional secondary line beneath the title */
  subtitle?: string;
  /** The form content */
  children: ReactNode;
}

export function AuthCard({ title, subtitle, children }: AuthCardProps) {
  return (
    <div
      className="
        min-h-screen flex items-center justify-center
        bg-gray-950
        bg-[radial-gradient(ellipse_at_top,_rgba(6,182,212,0.08)_0%,_transparent_60%)]
        px-4 py-12
      "
    >
      <div
        className="
          w-full max-w-md
          rounded-2xl border border-white/10
          bg-gray-900/60 backdrop-blur-sm
          shadow-2xl shadow-black/50
          p-8
        "
        role="main"
      >
        {/* Brand logo + name */}
        <Link
          to="/"
          className="flex items-center justify-center gap-2 mb-6 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 rounded-md"
          aria-label="SecureAI – back to home"
        >
          <Shield className="h-8 w-8 text-cyan-400" aria-hidden="true" />
          <span className="text-2xl font-bold tracking-tight text-white">
            Secure<span className="text-cyan-400">AI</span>
          </span>
        </Link>

        {/* Card heading */}
        <div className="text-center mb-8">
          <h1 className="text-2xl font-bold text-white">{title}</h1>
          {subtitle && <p className="mt-2 text-sm text-gray-400">{subtitle}</p>}
        </div>

        {/* Form slot */}
        {children}
      </div>
    </div>
  );
}
