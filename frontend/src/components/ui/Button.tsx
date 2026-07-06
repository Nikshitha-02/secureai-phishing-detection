import type { ButtonHTMLAttributes, ReactNode } from 'react';

type Variant = 'primary' | 'outline' | 'ghost';
type Size = 'sm' | 'md' | 'lg';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  children: ReactNode;
  /** Renders a full-width block button */
  fullWidth?: boolean;
}

const base =
  'inline-flex items-center justify-center gap-2 rounded-lg font-semibold transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 focus-visible:ring-offset-2 focus-visible:ring-offset-gray-950 disabled:pointer-events-none disabled:opacity-50 cursor-pointer';

const variants: Record<Variant, string> = {
  primary:
    'bg-cyan-500 text-gray-950 hover:bg-cyan-400 active:scale-[0.98] shadow-lg shadow-cyan-500/25',
  outline:
    'border border-cyan-500/60 text-cyan-400 hover:bg-cyan-500/10 active:scale-[0.98]',
  ghost: 'text-gray-300 hover:text-white hover:bg-white/5 active:scale-[0.98]',
};

const sizes: Record<Size, string> = {
  sm: 'h-8 px-3 text-sm',
  md: 'h-10 px-5 text-sm',
  lg: 'h-12 px-7 text-base',
};

export function Button({
  variant = 'primary',
  size = 'md',
  fullWidth = false,
  className = '',
  children,
  ...props
}: ButtonProps) {
  return (
    <button
      className={[base, variants[variant], sizes[size], fullWidth ? 'w-full' : '', className]
        .filter(Boolean)
        .join(' ')}
      {...props}
    >
      {children}
    </button>
  );
}
