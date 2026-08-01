/**
 * pages/RegisterPage.tsx
 *
 * New-user registration screen.
 *
 * FLOW
 * ─────
 * 1. User fills email, password, and confirms password.
 * 2. Client validates: non-empty, valid email, password ≥ 8 chars, passwords match.
 * 3. We call `supabase.auth.signUp()`.
 * 4. Supabase sends a confirmation email. We show a success message telling
 *    the user to check their inbox rather than immediately navigating to /dashboard
 *    (email confirmation is enabled by default in Supabase).
 * 5. On Supabase error: display it in an AuthAlert.
 *
 * EMAIL CONFIRMATION NOTE
 * ────────────────────────
 * If you disable "Confirm email" in your Supabase Auth settings,
 * `signUp` immediately returns a live session. In that case, remove the
 * success-state early return and replace it with `navigate('/dashboard', { replace: true })`.
 */

import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { Loader2 } from 'lucide-react';
import { supabase } from '@/lib/supabaseClient';
import { AuthCard } from '@/features/auth/components/AuthCard';
import { FormInput } from '@/features/auth/components/FormInput';
import { AuthAlert } from '@/features/auth/components/AuthAlert';
import { Button } from '@/components/ui/Button';
import type { RegisterCredentials } from '@/types/auth';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function validate(fields: RegisterCredentials): Partial<RegisterCredentials> {
  const errors: Partial<RegisterCredentials> = {};
  if (!fields.email.trim()) errors.email = 'Email is required.';
  else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fields.email))
    errors.email = 'Enter a valid email address.';
  if (!fields.password) errors.password = 'Password is required.';
  else if (fields.password.length < 8) errors.password = 'Password must be at least 8 characters.';
  if (!fields.confirmPassword) errors.confirmPassword = 'Please confirm your password.';
  else if (fields.password !== fields.confirmPassword)
    errors.confirmPassword = 'Passwords do not match.';
  return errors;
}

// ─── Component ───────────────────────────────────────────────────────────────

export function RegisterPage() {
  const [fields, setFields] = useState<RegisterCredentials>({
    email: '',
    password: '',
    confirmPassword: '',
  });
  const [fieldErrors, setFieldErrors] = useState<Partial<RegisterCredentials>>({});
  const [alert, setAlert] = useState<{ variant: 'error' | 'success'; message: string } | null>(
    null,
  );
  const [isLoading, setIsLoading] = useState(false);
  // Tracks whether sign-up succeeded (shows confirmation UI instead of form)
  const [registered, setRegistered] = useState(false);

  function handleChange(e: React.ChangeEvent<HTMLInputElement>) {
    const { name, value } = e.target;
    setFields((prev) => ({ ...prev, [name]: value }));
    if (fieldErrors[name as keyof RegisterCredentials]) {
      setFieldErrors((prev) => ({ ...prev, [name]: undefined }));
    }
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setAlert(null);

    const errors = validate(fields);
    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }

    setIsLoading(true);
    try {
      const { error } = await supabase.auth.signUp({
        email: fields.email.trim(),
        password: fields.password,
        options: {
          // Redirect back to the app after the user clicks the confirmation link.
          emailRedirectTo: `${window.location.origin}/verify-email`,
        },
      });

      if (error) {
        setAlert({ variant: 'error', message: error.message });
        return;
      }

      // Supabase sent a confirmation email.
      setRegistered(true);
    } catch {
      setAlert({ variant: 'error', message: 'Something went wrong. Please try again.' });
    } finally {
      setIsLoading(false);
    }
  }

  // ── Post-registration success state ────────────────────────────────────────
  if (registered) {
    return (
      <AuthCard
        title="Check your inbox"
        subtitle="We've sent you a confirmation email. Click the link inside to activate your account."
      >
        <div className="flex flex-col gap-4 mt-2">
          <AuthAlert
            variant="success"
            message={`A confirmation link was sent to ${fields.email}. Check your spam folder if you don't see it.`}
          />
          <p className="text-center text-sm text-gray-400">
            Already confirmed?{' '}
            <Link
              to="/login"
              className="text-cyan-400 hover:text-cyan-300 font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-500 rounded"
            >
              Sign in
            </Link>
          </p>
        </div>
      </AuthCard>
    );
  }

  // ── Registration form ───────────────────────────────────────────────────────
  return (
    <AuthCard title="Create your account" subtitle="Start protecting yourself with AI-powered security">
      <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-5">
        {alert && <AuthAlert variant={alert.variant} message={alert.message} />}

        <FormInput
          label="Email address"
          type="email"
          name="email"
          value={fields.email}
          onChange={handleChange}
          error={fieldErrors.email}
          autoComplete="email"
          placeholder="you@example.com"
          disabled={isLoading}
        />

        <FormInput
          label="Password"
          type="password"
          name="password"
          value={fields.password}
          onChange={handleChange}
          error={fieldErrors.password}
          autoComplete="new-password"
          placeholder="Min. 8 characters"
          disabled={isLoading}
        />

        <FormInput
          label="Confirm password"
          type="password"
          name="confirmPassword"
          value={fields.confirmPassword}
          onChange={handleChange}
          error={fieldErrors.confirmPassword}
          autoComplete="new-password"
          placeholder="••••••••"
          disabled={isLoading}
        />

        <Button type="submit" fullWidth disabled={isLoading} className="mt-1">
          {isLoading ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
              Creating account…
            </>
          ) : (
            'Create account'
          )}
        </Button>

        <p className="text-center text-sm text-gray-400">
          Already have an account?{' '}
          <Link
            to="/login"
            className="text-cyan-400 hover:text-cyan-300 font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-500 rounded"
          >
            Sign in
          </Link>
        </p>
      </form>
    </AuthCard>
  );
}
