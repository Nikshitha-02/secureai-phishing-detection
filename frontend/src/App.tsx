/**
 * App.tsx
 *
 * Application root. Sets up:
 *   1. BrowserRouter — React Router v7 declarative routing.
 *   2. AuthProvider  — makes the Supabase session available to the whole tree.
 *   3. Route table   — maps paths to pages, wraps protected paths in
 *                      <ProtectedRoute>.
 *
 * ROUTE TABLE
 * ────────────
 * Public routes (no auth required):
 *   /                 → LandingPage
 *   /login            → LoginPage
 *   /register         → RegisterPage
 *   /forgot-password  → ForgotPasswordPage
 *   /verify-email     → VerifyEmailPage
 *
 * Protected routes (redirect to /login if not authenticated):
 *   All rendered inside DashboardLayout which provides sidebar + header.
 *   /dashboard  → DashboardPage   (default authenticated page)
 *   /scanner    → ScannerPage
 *   /history    → HistoryPage
 *   /reports    → ReportsPage
 *   /settings   → SettingsPage
 */

import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from '@/features/auth/AuthContext';
import { ProtectedRoute } from '@/routes/ProtectedRoute';
import { DashboardLayout } from '@/layouts/DashboardLayout';

// Pages — public
import { LandingPage } from '@/pages/LandingPage';
import { LoginPage } from '@/pages/LoginPage';
import { RegisterPage } from '@/pages/RegisterPage';
import { ForgotPasswordPage } from '@/pages/ForgotPasswordPage';
import { VerifyEmailPage } from '@/pages/VerifyEmailPage';

// Pages — protected (rendered inside DashboardLayout)
import { DashboardPage } from '@/pages/DashboardPage';
import { ScannerPage } from '@/pages/ScannerPage';
import { HistoryPage } from '@/pages/HistoryPage';
import { ReportsPage } from '@/pages/ReportsPage';
import { SettingsPage } from '@/pages/SettingsPage';

function App() {
  return (
    <BrowserRouter>
      {/*
        AuthProvider must sit INSIDE BrowserRouter because:
        - AuthCard (rendered by auth pages) uses <Link> from react-router-dom.
        - ProtectedRoute uses useNavigate / useLocation.
        Both hooks require a Router ancestor.
      */}
      <AuthProvider>
        <Routes>
          {/* ── Public ── */}
          <Route path="/" element={<LandingPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/forgot-password" element={<ForgotPasswordPage />} />
          <Route path="/verify-email" element={<VerifyEmailPage />} />

          {/* ── Protected (all inside DashboardLayout) ── */}
          <Route element={<ProtectedRoute />}>
            <Route element={<DashboardLayout />}>
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="/scanner"   element={<ScannerPage />} />
              <Route path="/history"   element={<HistoryPage />} />
              <Route path="/reports"   element={<ReportsPage />} />
              <Route path="/settings"  element={<SettingsPage />} />
            </Route>
          </Route>

          {/* ── Fallback ── */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
