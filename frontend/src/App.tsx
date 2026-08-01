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
 *   /verify-email     → VerifyEmailPage   (Supabase email-confirm redirect)
 *   /reset-password   → (scaffold later)
 *
 * Protected routes (redirect to /login if not authenticated):
 *   /dashboard        → DashboardPage
 *   (future: /history, /scan/url, /scan/email …)
 *
 * The <ProtectedRoute> wrapper handles two concerns automatically:
 *   • Shows a full-screen spinner while the session is being restored on
 *     a hard refresh (loading === true).
 *   • Redirects to /login preserving the attempted URL in location.state.from
 *     so LoginPage can send the user back after successful sign-in.
 */

import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from '@/features/auth/AuthContext';
import { ProtectedRoute } from '@/routes/ProtectedRoute';

// Pages
import { LandingPage } from '@/pages/LandingPage';
import { LoginPage } from '@/pages/LoginPage';
import { RegisterPage } from '@/pages/RegisterPage';
import { ForgotPasswordPage } from '@/pages/ForgotPasswordPage';
import { VerifyEmailPage } from '@/pages/VerifyEmailPage';
import { DashboardPage } from '@/pages/DashboardPage';

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
          {/* /reset-password is handled by Supabase's email link;
              scaffold the "enter new password" page in a follow-up task */}

          {/* ── Protected ── */}
          <Route element={<ProtectedRoute />}>
            <Route path="/dashboard" element={<DashboardPage />} />
            {/* Add more protected routes here as features are built:
                <Route path="/history"   element={<HistoryPage />}   />
                <Route path="/scan/url"  element={<UrlScanPage />}   />
                <Route path="/scan/email" element={<EmailScanPage />} />
            */}
          </Route>

          {/* ── Fallback ── */}
          {/* Unknown paths redirect to the landing page */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
