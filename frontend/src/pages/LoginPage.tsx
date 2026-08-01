/**
 * pages/LoginPage.tsx
 *
 * The user-facing login screen for SecureAI.
 *
 * FLOW
 * ─────
 * 1. User fills email + password and submits.
 * 2. We call `supabase.auth.signInWithPassword()`.
 * 3. On success: AuthContext.onAuthStateChange fires → sets user → React
 *    Router's ProtectedRoute sees an authenticated user and allows access.
 *    We also do a `navigate('/dashboard')` for an instant redirect.
 * 4. On error: The Supabase error message is shown in an AuthAlert.
 *
 * FORM STATE
 * ──────────
 * Controlled with plain React state (no form library dependency). If the
 * project adds React Hook Form later, the controlled inputs are straightforward
 * to swap.
 *
 * CLIENT-SIDE VALIDATION
 * ──────────────────────
 * We validate on submit (not on blur) to avoid premature error messages.
 * The back-end / Supabase does its own authoritative validation.
 */

import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Loader2 } from 'lucide-react';
import { supabase } from '@/lib/supabaseClient';
import { AuthCard } from '@/features/auth/components/AuthCard';
import { FormInput } from '@/features/auth/components/FormInput';
import { AuthAlert } from '@/features/auth/components/AuthAlert';
import { Button } from '@/components/ui/Button';
import type { LoginCredentials } from '@/types/auth';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function validate(fields: LoginCredentials): Partial<LoginCredentials> {
  const errors: Partial<LoginCredentials> = {};
  if (!fields.email.trim()) errors.email = 'Email is required.';
  else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fields.email))
    errors.email = 'Enter a valid email address.';
  if (!fields.password) errors.password = 'Password is required.';
  return errors;
}

// ─── Component ───────────────────────────────────────────────────────────────

export function LoginPage() {
  const navigate = useNavigate();

  // Form fields
  const [fields, setFields] = useState<LoginCredentials>({ email: '', password: '' });
  // Per-field validation errors
  const [fieldErrors, setFieldErrors] = useState<Partial<LoginCredentials>>({});
  // Top-level API error / success
  const [alert, setAlert] = useState<{ variant: 'error' | 'success'; message: string } | null>(
    null,
  );
  // Loading state while the Supabase request is in-flight
  const [isLoading, setIsLoading] = useState(false);

  function handleChange(e: React.ChangeEvent<HTMLInputElement>) {
    const { name, value } = e.target;
    setFields((prev) => ({ ...prev, [name]: value }));
    // Clear the error for this field as the user types
    if (fieldErrors[name as keyof LoginCredentials]) {
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
      const { error } = await supabase.auth.signInWithPassword({
        email: fields.email.trim(),
        password: fields.password,
      });

      if (error) {
        setAlert({ variant: 'error', message: error.message });
        return;
      }

      // AuthContext will update via onAuthStateChange automatically.
      // Navigate immediately for a snappy UX.
      navigate('/dashboard', { replace: true });
    } catch {
      setAlert({ variant: 'error', message: 'Something went wrong. Please try again.' });
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <AuthCard title="Welcome back" subtitle="Sign in to your SecureAI account">
      <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-5">
        {/* Top-level alert */}
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

        <div className="flex flex-col gap-1.5">
          <div className="flex items-center justify-between">
            {/* The actual label is inside FormInput; we layer Forgot above */}
            <span className="sr-only">Password</span>
          </div>
          <FormInput
            label="Password"
            type="password"
            name="password"
            value={fields.password}
            onChange={handleChange}
            error={fieldErrors.password}
            autoComplete="current-password"
            placeholder="••••••••"
            disabled={isLoading}
          />
          <div className="flex justify-end mt-0.5">
            <Link
              to="/forgot-password"
              className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-500 rounded"
            >
              Forgot password?
            </Link>
          </div>
        </div>

        <Button type="submit" fullWidth disabled={isLoading} className="mt-1">
          {isLoading ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
              Signing in…
            </>
          ) : (
            'Sign in'
          )}
        </Button>

        <p className="text-center text-sm text-gray-400">
          Don&apos;t have an account?{' '}
          <Link
            to="/register"
            className="text-cyan-400 hover:text-cyan-300 font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-500 rounded"
          >
            Create one
          </Link>
        </p>
      </form>
    </AuthCard>
  );
}
