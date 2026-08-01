/**
 * features/auth/components/FormInput.tsx
 *
 * A fully-accessible, styled text/email/password input for auth forms.
 *
 * FEATURES
 * ─────────
 * • Forwards a ref so React Hook Form (if added later) can register it.
 * • Wraps the native <input> in a labelled container — label is always
 *   rendered (never a placeholder-only input) for screen reader compliance.
 * • Accepts an optional `error` string. When present it renders an
 *   aria-live error message and sets aria-invalid on the input so
 *   screen readers announce the validation failure immediately.
 * • Password fields include a show/hide toggle button.
 * • Accepts all native InputHTMLAttributes so callers can pass onChange,
 *   onBlur, value, autoComplete, etc. without any extra wiring.
 */

import { forwardRef, useState, useId, type InputHTMLAttributes } from 'react';
import { Eye, EyeOff } from 'lucide-react';

interface FormInputProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  error?: string;
}

export const FormInput = forwardRef<HTMLInputElement, FormInputProps>(
  ({ label, error, type = 'text', className = '', ...rest }, ref) => {
    const id = useId();
    const errorId = `${id}-error`;
    const [showPassword, setShowPassword] = useState(false);

    const isPassword = type === 'password';
    const resolvedType = isPassword ? (showPassword ? 'text' : 'password') : type;

    return (
      <div className="flex flex-col gap-1.5">
        {/* Label */}
        <label htmlFor={id} className="text-sm font-medium text-gray-300">
          {label}
        </label>

        {/* Input wrapper */}
        <div className="relative">
          <input
            ref={ref}
            id={id}
            type={resolvedType}
            aria-invalid={!!error}
            aria-describedby={error ? errorId : undefined}
            className={[
              // Layout & typography
              'w-full rounded-lg px-4 py-2.5 text-sm text-white',
              // Background / border
              'bg-gray-900 border',
              error ? 'border-red-500/70' : 'border-white/10',
              // Focus ring
              'outline-none focus:ring-2',
              error ? 'focus:ring-red-500/50' : 'focus:ring-cyan-500/50',
              // Placeholder colour
              'placeholder:text-gray-600',
              // Password field needs right padding for the toggle button
              isPassword ? 'pr-11' : '',
              // Disabled state
              'disabled:opacity-50 disabled:cursor-not-allowed',
              // Transition
              'transition-colors duration-150',
              className,
            ]
              .filter(Boolean)
              .join(' ')}
            {...rest}
          />

          {/* Show / hide toggle for password fields */}
          {isPassword && (
            <button
              type="button"
              tabIndex={-1} // don't interrupt tab flow for the form
              aria-label={showPassword ? 'Hide password' : 'Show password'}
              onClick={() => setShowPassword((v) => !v)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
            >
              {showPassword ? (
                <EyeOff className="h-4 w-4" aria-hidden="true" />
              ) : (
                <Eye className="h-4 w-4" aria-hidden="true" />
              )}
            </button>
          )}
        </div>

        {/* Inline validation error */}
        {error && (
          <p
            id={errorId}
            role="alert"
            aria-live="polite"
            className="text-xs text-red-400 mt-0.5"
          >
            {error}
          </p>
        )}
      </div>
    );
  },
);

FormInput.displayName = 'FormInput';
