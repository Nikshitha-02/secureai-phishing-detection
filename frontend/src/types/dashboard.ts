/**
 * types/dashboard.ts
 *
 * Shared TypeScript types for the Dashboard and URL Phishing Scanner.
 * These are designed to match the future backend API shape so that
 * swapping mock data for real API calls requires only service-layer changes.
 */

// ─── Risk Levels ─────────────────────────────────────────────────────────────

export type RiskLevel = 'safe' | 'suspicious' | 'dangerous';

// ─── Scan Result ─────────────────────────────────────────────────────────────

/** A single security check performed on a URL. */
export interface SecurityCheck {
  /** Human-readable label for the check */
  label: string;
  /** String result value to display in the table */
  value: string;
  /** Whether this check passed (green tick) or failed (red cross / warning) */
  passed: boolean;
}

/** Full result returned after analysing a URL. */
export interface ScanResult {
  /** The URL that was scanned */
  url: string;
  /** Numeric risk score, 0–100 */
  riskScore: number;
  /** Categorised risk level derived from the score */
  riskLevel: RiskLevel;
  /** Human-readable verdict message */
  verdict: string;
  /** Ordered list of individual security checks */
  checks: SecurityCheck[];
  /** ISO timestamp of when the scan was performed */
  scannedAt: string;
  /**
   * Plain-language AI explanation from Gemini.
   * Always a string — set to the unavailable message if Gemini fails.
   * Optional so existing mock data and history entries don't break.
   */
  aiExplanation?: string;
}

// ─── Recent Scan (history row) ────────────────────────────────────────────────

/** A condensed history entry shown in the Recent Scans table. */
export interface RecentScan {
  id: string;
  url: string;
  riskScore: number;
  riskLevel: RiskLevel;
  scannedAt: string;
}

// ─── Dashboard Statistics ─────────────────────────────────────────────────────

/** Aggregate stats shown at the top of the dashboard. */
export interface DashboardStats {
  totalScans: number;
  safeUrls: number;
  suspiciousUrls: number;
  highRiskUrls: number;
}

// ─── Stat Card configuration ──────────────────────────────────────────────────

/** Props shape used to drive a single StatCard. */
export interface StatCardConfig {
  label: string;
  value: number;
  /** Tailwind colour token suffix, e.g. "cyan-400" */
  colour: string;
  /** Icon component from lucide-react */
  icon: React.ComponentType<{ className?: string }>;
}
