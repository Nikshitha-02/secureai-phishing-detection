/**
 * pages/ForgotPasswordPage.tsx
 *
 * Initiates Supabase's password-reset flow.
 *
 * FLOW
 * ─────
 * 1. User enters their email address and submits.
 * 2. We call `supabase.auth.resetPasswordForEmail()`.
 * 3. Supabase sends a password-reset email containing a link to
 *    `/reset-password` (configured in `redirectTo` below). That link
 *    includes a one-time token that Supabase exchanges for a session when
 *    the user arrives on `/reset-password`.
 * 4. We show a success message regardless of whether the email exists in
 *    Supabase — this is intentional to prevent user enumeration attacks.
 *
 * RESET PASSWORD PAGE
 * ────────────────────
 * The actual "enter new password" form lives at pages/ResetPasswordPage.tsx
 * (not part of this task; scaffold it when implementing that flow).
 * The `emailRedirectTo` below must match a URL configured in:
 *   Supabase Dashboard → Auth → URL Configuration → Redirect URLs
 */

import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { Loader2, ArrowLeft } from 'lucide-react';
import { supabase } from '@/lib/supabaseClient';
import { AuthCard } from '@/features/auth/components/AuthCard';
import { FormInput } from '@/features/auth/components/FormInput';
import { AuthAlert } from '@/features/auth/components/AuthAlert';
import { Button } from '@/components/ui/Button';

// ─── Component ───────────────────────────────────────────────────────────────

export function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [emailError, setEmailError] = useState('');
  const [alert, setAlert] = useState<{ variant: 'error' | 'success'; message: string } | null>(
    null,
  );
  const [isLoading, setIsLoading] = useState(false);
  const [sent, setSent] = useState(false);

  function validate(): boolean {
    if (!email.trim()) {
      setEmailError('Email is required.');
      return false;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setEmailError('Enter a valid email address.');
      return false;
    }
    setEmailError('');
    return true;
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setAlert(null);
    if (!validate()) return;

    setIsLoading(true);
    try {
      const { error } = await supabase.auth.resetPasswordForEmail(email.trim(), {
        redirectTo: `${window.location.origin}/reset-password`,
      });

      if (error) {
        // Surface unexpected SDK errors, but don't reveal "email not found".
        setAlert({ variant: 'error', message: error.message });
        return;
      }

      // Always show success to prevent user enumeration.
      setSent(true);
    } catch {
      setAlert({ variant: 'error', message: 'Something went wrong. Please try again.' });
    } finally {
      setIsLoading(false);
    }
  }

  // ── Success state ──────────────────────────────────────────────────────────
  if (sent) {
    return (
      <AuthCard
        title="Check your inbox"
        subtitle="We've sent a password reset link to your email address."
      >
        <div className="flex flex-col gap-5 mt-2">
          <AuthAlert
            variant="success"
            message={`A reset link was sent to ${email}. It expires in 1 hour. Check your spam folder if you don't see it.`}
          />
          <Button
            variant="outline"
            fullWidth
            onClick={() => {
              setSent(false);
              setEmail('');
            }}
          >
            Send another link
          </Button>
          <p className="text-center text-sm text-gray-400">
            <Link
              to="/login"
              className="text-cyan-400 hover:text-cyan-300 font-medium transition-colors inline-flex items-center gap-1 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-500 rounded"
            >
              <ArrowLeft className="h-3 w-3" aria-hidden="true" />
              Back to sign in
            </Link>
          </p>
        </div>
      </AuthCard>
    );
  }

  // ── Request form ───────────────────────────────────────────────────────────
  return (
    <AuthCard
      title="Forgot your password?"
      subtitle="Enter your email and we'll send you a reset link."
    >
      <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-5">
        {alert && <AuthAlert variant={alert.variant} message={alert.message} />}

        <FormInput
          label="Email address"
          type="email"
          name="email"
          value={email}
          onChange={(e) => {
            setEmail(e.target.value);
            if (emailError) setEmailError('');
          }}
          error={emailError}
          autoComplete="email"
          placeholder="you@example.com"
          disabled={isLoading}
        />

        <Button type="submit" fullWidth disabled={isLoading} className="mt-1">
          {isLoading ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
              Sending link…
            </>
          ) : (
            'Send reset link'
          )}
        </Button>

        <p className="text-center text-sm text-gray-400">
          <Link
            to="/login"
            className="text-cyan-400 hover:text-cyan-300 font-medium transition-colors inline-flex items-center gap-1 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-500 rounded"
          >
            <ArrowLeft className="h-3 w-3" aria-hidden="true" />
            Back to sign in
          </Link>
        </p>
      </form>
    </AuthCard>
  );
}
