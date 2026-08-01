/**
 * features/dashboard/components/Sidebar.tsx
 *
 * Responsive sidebar navigation for the dashboard.
 *
 * Behaviour:
 *   Desktop (lg+): always-visible vertical sidebar, collapsed to icon-only
 *                  if `collapsed` is true.
 *   Mobile (<lg): hidden by default, slides in as an overlay when `open`.
 *
 * The active item is driven by `activeItem` prop so the parent controls state.
 */

import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  LayoutDashboard,
  Scan,
  History,
  BarChart2,
  Settings,
  X,
  LogOut,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

// ─── Types ────────────────────────────────────────────────────────────────────

export type NavItemId = 'dashboard' | 'scanner' | 'history' | 'reports' | 'settings';

interface NavItem {
  id: NavItemId;
  label: string;
  Icon: LucideIcon;
}

interface SidebarProps {
  activeItem: NavItemId;
  onNavChange: (id: NavItemId) => void;
  /** Mobile open state */
  mobileOpen: boolean;
  onMobileClose: () => void;
  /** Desktop collapsed (icon-only) state */
  collapsed: boolean;
  onToggleCollapsed: () => void;
  onSignOut: () => void;
}

// ─── Nav items ────────────────────────────────────────────────────────────────

const NAV_ITEMS: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', Icon: LayoutDashboard },
  { id: 'scanner', label: 'Scanner', Icon: Scan },
  { id: 'history', label: 'History', Icon: History },
  { id: 'reports', label: 'Reports', Icon: BarChart2 },
  { id: 'settings', label: 'Settings', Icon: Settings },
];

// ─── Sub-components ───────────────────────────────────────────────────────────

interface NavButtonProps {
  item: NavItem;
  active: boolean;
  collapsed: boolean;
  onClick: () => void;
}

function NavButton({ item, active, collapsed, onClick }: NavButtonProps) {
  const { Icon, label } = item;

  return (
    <button
      onClick={onClick}
      aria-label={label}
      aria-current={active ? 'page' : undefined}
      title={collapsed ? label : undefined}
      className={[
        'group relative flex w-full items-center gap-3 rounded-xl px-3 py-2.5',
        'text-sm font-medium transition-all duration-200 text-left',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500',
        active
          ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/20'
          : 'text-gray-400 hover:bg-white/5 hover:text-white border border-transparent',
      ].join(' ')}
    >
      {/* Active indicator */}
      {active && (
        <span
          className="absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-cyan-400"
          aria-hidden="true"
        />
      )}

      <Icon
        className={`h-4.5 w-4.5 flex-shrink-0 transition-colors ${active ? 'text-cyan-400' : 'text-gray-500 group-hover:text-white'}`}
        aria-hidden="true"
      />

      <AnimatePresence>
        {!collapsed && (
          <motion.span
            initial={{ opacity: 0, width: 0 }}
            animate={{ opacity: 1, width: 'auto' }}
            exit={{ opacity: 0, width: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden whitespace-nowrap"
          >
            {label}
          </motion.span>
        )}
      </AnimatePresence>
    </button>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export function Sidebar({
  activeItem,
  onNavChange,
  mobileOpen,
  onMobileClose,
  collapsed,
  onToggleCollapsed,
  onSignOut,
}: SidebarProps) {
  const sidebarContent = (isMobile = false) => (
    <nav
      className={[
        'flex h-full flex-col',
        isMobile ? 'p-4' : 'px-3 py-5',
      ].join(' ')}
      aria-label="Dashboard navigation"
    >
      {/* Brand + close (mobile) / collapse toggle (desktop) */}
      <div className={`flex items-center ${collapsed && !isMobile ? 'justify-center' : 'justify-between'} mb-6 px-1`}>
        {(!collapsed || isMobile) && (
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-cyan-400" aria-hidden="true" />
            <span className="text-lg font-bold tracking-tight text-white">
              Secure<span className="text-cyan-400">AI</span>
            </span>
          </div>
        )}

        {isMobile ? (
          <button
            onClick={onMobileClose}
            aria-label="Close navigation"
            className="rounded-lg p-1.5 text-gray-400 hover:bg-white/5 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500"
          >
            <X className="h-5 w-5" aria-hidden="true" />
          </button>
        ) : (
          <button
            onClick={onToggleCollapsed}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            className="rounded-lg p-1.5 text-gray-500 hover:bg-white/5 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500"
          >
            {collapsed ? (
              <ChevronRight className="h-4 w-4" aria-hidden="true" />
            ) : (
              <ChevronLeft className="h-4 w-4" aria-hidden="true" />
            )}
          </button>
        )}
      </div>

      {/* Nav items */}
      <ul className="flex flex-col gap-1 flex-1" role="list">
        {NAV_ITEMS.map((item) => (
          <li key={item.id}>
            <NavButton
              item={item}
              active={activeItem === item.id}
              collapsed={collapsed && !isMobile}
              onClick={() => {
                onNavChange(item.id);
                if (isMobile) onMobileClose();
              }}
            />
          </li>
        ))}
      </ul>

      {/* Sign out */}
      <button
        onClick={onSignOut}
        aria-label="Sign out"
        title={collapsed && !isMobile ? 'Sign out' : undefined}
        className={[
          'flex w-full items-center gap-3 rounded-xl px-3 py-2.5',
          'text-sm font-medium text-gray-500 hover:bg-red-500/10 hover:text-red-400',
          'transition-all duration-200 border border-transparent hover:border-red-500/20',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500',
          collapsed && !isMobile ? 'justify-center' : '',
        ].join(' ')}
      >
        <LogOut className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
        <AnimatePresence>
          {(!collapsed || isMobile) && (
            <motion.span
              initial={{ opacity: 0, width: 0 }}
              animate={{ opacity: 1, width: 'auto' }}
              exit={{ opacity: 0, width: 0 }}
              transition={{ duration: 0.2 }}
              className="overflow-hidden whitespace-nowrap"
            >
              Sign out
            </motion.span>
          )}
        </AnimatePresence>
      </button>
    </nav>
  );

  return (
    <>
      {/* ── Desktop Sidebar ─────────────────────────────────────────────── */}
      <motion.aside
        animate={{ width: collapsed ? 64 : 220 }}
        transition={{ duration: 0.25, ease: 'easeInOut' }}
        className={[
          'hidden lg:flex flex-col flex-shrink-0',
          'border-r border-white/10 bg-gray-900/80 backdrop-blur-sm',
          'sticky top-0 h-screen overflow-hidden',
        ].join(' ')}
        aria-label="Desktop sidebar"
      >
        {sidebarContent(false)}
      </motion.aside>

      {/* ── Mobile Overlay ───────────────────────────────────────────────── */}
      <AnimatePresence>
        {mobileOpen && (
          <>
            {/* Backdrop */}
            <motion.div
              key="backdrop"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden"
              onClick={onMobileClose}
              aria-hidden="true"
            />

            {/* Drawer */}
            <motion.div
              key="drawer"
              initial={{ x: '-100%' }}
              animate={{ x: 0 }}
              exit={{ x: '-100%' }}
              transition={{ duration: 0.25, ease: 'easeInOut' }}
              className={[
                'fixed left-0 top-0 z-50 h-full w-64',
                'border-r border-white/10 bg-gray-900 shadow-2xl lg:hidden',
              ].join(' ')}
              role="dialog"
              aria-modal="true"
              aria-label="Mobile navigation menu"
            >
              {sidebarContent(true)}
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </>
  );
}
