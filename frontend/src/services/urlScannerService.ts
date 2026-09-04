/**
 * services/urlScannerService.ts
 * ─────────────────────────────
 * HTTP client layer between the React app and the Express backend.
 *
 * Responsibilities:
 *  1. Attach the Supabase JWT as Authorization: Bearer <token>
 *  2. POST the URL to /api/scan
 *  3. Normalise the backend response shape into the ScanResult type
 *  4. Classify every failure into a user-friendly error message
 *
 * Token injection:
 *   A request interceptor reads the current Supabase session before each
 *   request and sets the Authorization header. This means the token is
 *   always fresh (Supabase auto-refreshes it) and no manual token passing
 *   is needed from any React component.
 *
 * The backend and frontend agree on the contract but differ in two details:
 *  - riskLevel:  backend → "Safe"|"Suspicious"|"Dangerous"  (title-case)
 *                frontend → "safe"|"suspicious"|"dangerous"  (lower-case)
 *  - checks:     backend → PhishingChecks object with named boolean/number fields
 *                frontend → SecurityCheck[] array with {label, value, passed}
 *  - verdict:    backend → "recommendation" field
 *                frontend → "verdict" field
 *  - scannedAt:  not returned by the backend → stamped client-side
 */

import axios, { AxiosError } from 'axios';
import { supabase } from '@/lib/supabaseClient';
import type { ScanResult, SecurityCheck, RiskLevel, ScoreContribution } from '@/types/dashboard';

// ─────────────────────────────────────────────────────────────────────────────
// Backend response types (mirrors backend/src/models/scan.model.ts)
// ─────────────────────────────────────────────────────────────────────────────

interface BackendPhishingChecks {
  https: boolean;
  ipAddress: boolean;
  urlShortener: boolean;
  longUrl: boolean;
  suspiciousKeywords: string[];
  suspiciousTld: boolean;
  manySubdomains: boolean;
  hyphenCount: number;
  hasEncodedChars: boolean;
}

interface BackendScanResponse {
  url: string;
  riskScore: number;
  riskLevel: 'Safe' | 'Suspicious' | 'Dangerous';
  checks: BackendPhishingChecks;
  scoreBreakdown?: ScoreContribution[];
  recommendation: string;
  recommendations: string[];
  aiExplanation: string;
  /** 'gemini' when Gemini succeeded; 'deterministic' when fallback was used */
  aiExplanationProvider?: 'gemini' | 'deterministic';
}

interface BackendErrorResponse {
  error: string;
  message: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Axios instance
// ─────────────────────────────────────────────────────────────────────────────

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:5000/api';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15_000,
  headers: {
    'Content-Type': 'application/json',
  },
});

/**
 * Request interceptor: attach the current Supabase JWT before every request.
 *
 * getSession() returns the in-memory session (no network call) — Supabase
 * keeps it fresh via autoRefreshToken. If there is no session the header is
 * omitted and the backend will respond 401, which classifyError handles.
 */
apiClient.interceptors.request.use(async (requestConfig) => {
  const {
    data: { session },
  } = await supabase.auth.getSession();

  if (session?.access_token) {
    requestConfig.headers.Authorization = `Bearer ${session.access_token}`;
  }

  return requestConfig;
});

// ─────────────────────────────────────────────────────────────────────────────
// Response normalisation helpers
// ─────────────────────────────────────────────────────────────────────────────

function normaliseRiskLevel(level: BackendScanResponse['riskLevel']): RiskLevel {
  return level.toLowerCase() as RiskLevel;
}

function buildSecurityChecks(c: BackendPhishingChecks): SecurityCheck[] {
  return [
    {
      label: 'HTTPS',
      value: c.https ? 'Enabled' : 'Not enabled',
      passed: c.https,
    },
    {
      label: 'IP Address URL',
      value: c.ipAddress ? 'Yes — suspicious' : 'No',
      passed: !c.ipAddress,
    },
    {
      label: 'URL Shortener',
      value: c.urlShortener ? 'Detected' : 'Not detected',
      passed: !c.urlShortener,
    },
    {
      label: 'URL Length',
      value: c.longUrl ? 'Unusually long' : 'Normal',
      passed: !c.longUrl,
    },
    {
      label: 'Suspicious Keywords',
      value:
        c.suspiciousKeywords.length > 0
          ? c.suspiciousKeywords.slice(0, 3).join(', ')
          : 'None',
      passed: c.suspiciousKeywords.length === 0,
    },
    {
      label: 'Suspicious TLD',
      value: c.suspiciousTld ? 'High-risk TLD detected' : 'Normal',
      passed: !c.suspiciousTld,
    },
    {
      label: 'Subdomains',
      value: c.manySubdomains ? 'Excessive' : 'Normal',
      passed: !c.manySubdomains,
    },
    {
      label: 'Hyphens in Domain',
      value: String(c.hyphenCount),
      passed: c.hyphenCount <= 3,
    },
    {
      label: 'Encoded Characters',
      value: c.hasEncodedChars ? 'Detected (%xx)' : 'None',
      passed: !c.hasEncodedChars,
    },
  ];
}

function mapToScanResult(raw: BackendScanResponse): ScanResult {
  return {
    url: raw.url,
    riskScore: raw.riskScore,
    riskLevel: normaliseRiskLevel(raw.riskLevel),
    verdict: raw.recommendation,
    checks: buildSecurityChecks(raw.checks),
    scoreBreakdown: raw.scoreBreakdown,
    scannedAt: new Date().toISOString(),
    aiExplanation: raw.aiExplanation,
    aiExplanationProvider: raw.aiExplanationProvider ?? 'deterministic',
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Error classification
// ─────────────────────────────────────────────────────────────────────────────

function classifyError(err: unknown): string {
  if (!axios.isAxiosError(err)) {
    return 'An unexpected error occurred. Please try again.';
  }

  const axiosErr = err as AxiosError<BackendErrorResponse>;

  if (axiosErr.code === 'ECONNABORTED' || axiosErr.message.toLowerCase().includes('timeout')) {
    return 'The scan request timed out. Please check your connection and try again.';
  }

  if (!axiosErr.response) {
    return 'Cannot reach the scan server. Make sure the backend is running on port 5000.';
  }

  const { status, data } = axiosErr.response;

  if (status === 401) {
    return 'Your session has expired. Please sign out and sign in again.';
  }

  if (status === 400) {
    return data?.message ?? 'Invalid URL. Please enter a valid http:// or https:// address.';
  }

  if (status === 429) {
    return 'Too many requests. Please wait a moment and try again.';
  }

  if (status >= 500) {
    return 'The scan server encountered an error. Please try again later.';
  }

  return data?.message ?? `Unexpected error (HTTP ${status}). Please try again.`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Scan a URL for phishing indicators.
 *
 * The JWT is injected automatically by the request interceptor.
 * The backend verifies it, runs the rule engine, persists the result,
 * and returns the full ScanResponse.
 *
 * @param url  The raw URL string entered by the user
 * @returns    A fully mapped ScanResult ready for ResultCard
 * @throws     A user-friendly string on any failure
 */
export async function scanUrl(url: string): Promise<ScanResult> {
  try {
    const { data } = await apiClient.post<BackendScanResponse>('/scan', { url });
    return mapToScanResult(data);
  } catch (err) {
    throw classifyError(err);
  }
}
