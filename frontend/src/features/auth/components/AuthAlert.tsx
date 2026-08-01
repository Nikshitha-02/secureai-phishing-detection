/**
 * features/auth/components/AuthAlert.tsx
 *
 * A small accessible alert banner for auth forms.
 * Used to display top-level API errors (e.g. "Invalid credentials") and
 * success messages (e.g. "Check your email for a reset link").
 *
 * Uses role="alert" so screen readers announce the message as soon as it
 * appears, without requiring user focus.
 *
 * Two variants:
 *   error   – red tint, used for sign-in/sign-up failures
 *   success – green tint, used for post-action confirmations
 */

import { AlertCircle, CheckCircle2 } from 'lucide-react';

interface AuthAlertProps {
  variant: 'error' | 'success';
  message: string;
}

export function AuthAlert({ variant, message }: AuthAlertProps) {
  const isError = variant === 'error';

  return (
    <div
      role="alert"
      aria-live="assertive"
      className={[
        'flex items-start gap-3 rounded-lg px-4 py-3 text-sm',
        isError
          ? 'bg-red-500/10 border border-red-500/30 text-red-400'
          : 'bg-green-500/10 border border-green-500/30 text-green-400',
      ].join(' ')}
    >
      {isError ? (
        <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" aria-hidden="true" />
      ) : (
        <CheckCircle2 className="h-4 w-4 mt-0.5 shrink-0" aria-hidden="true" />
      )}
      <span>{message}</span>
    </div>
  );
}
