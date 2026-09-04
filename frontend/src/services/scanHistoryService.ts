/**
 * services/scanHistoryService.ts
 *
 * Fetches the authenticated user's scan history from Supabase.
 *
 * Table: public.scan_results
 *   id          uuid  primary key
 *   user_id     uuid  references auth.users(id)
 *   url         text
 *   risk_score  integer  (0-100)
 *   risk_level  text     ('safe' | 'suspicious' | 'dangerous')
 *   scanned_at  timestamptz
 *
 * The frontend uses the anon key — the Supabase client sends the user's JWT
 * automatically via the session. The RLS policy:
 *   SELECT: auth.uid() = user_id
 * ensures each user only sees their own rows.
 */

import { supabase } from '@/lib/supabaseClient';
import type { RecentScan, DashboardStats, RiskLevel } from '@/types/dashboard';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ScanRow {
  id: string;
  url: string;
  risk_score: number;
  risk_level: string;
  scanned_at: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function toRecentScan(row: ScanRow): RecentScan {
  return {
    id: row.id,
    url: row.url,
    riskScore: row.risk_score,
    riskLevel: row.risk_level as RiskLevel,
    scannedAt: row.scanned_at,
  };
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Fetch the currently authenticated user's scan history, newest first.
 *
 * Throws a descriptive string on failure so the calling page can display it.
 * The full Supabase error (code, message, details, hint) is logged to the
 * console so debugging is possible without exposing internals to the UI.
 */
export async function fetchScanHistory(limit = 100): Promise<RecentScan[]> {
  // Get the user directly from the session — avoids an extra network call
  const {
    data: { session },
    error: sessionError,
  } = await supabase.auth.getSession();

  if (sessionError) {
    console.error('[scanHistoryService] getSession error:', sessionError);
    throw `Session error: ${sessionError.message}`;
  }

  if (!session?.user) {
    throw 'You must be logged in to view scan history.';
  }

  const userId = session.user.id;

  const { data, error } = await supabase
    .from('scan_results')
    .select('id, url, risk_score, risk_level, scanned_at')
    .eq('user_id', userId)
    .order('scanned_at', { ascending: false })
    .limit(limit);

  if (error) {
    // Log the full error object for debugging
    console.error('[scanHistoryService] Supabase query error:', {
      code:    error.code,
      message: error.message,
      details: error.details,
      hint:    error.hint,
    });

    // Surface a meaningful message based on the error code
    if (error.code === '42P01') {
      // relation does not exist
      throw 'Database table "scan_results" does not exist. Run the SQL migration in Supabase Dashboard → SQL Editor.';
    }
    if (error.code === 'PGRST301' || error.message?.includes('JWT')) {
      throw 'Authentication error accessing scan history. Please sign out and sign in again.';
    }

    throw `Failed to load scan history: ${error.message}`;
  }

  return (data as ScanRow[]).map(toRecentScan);
}

/**
 * Compute aggregate statistics from an array of scan history rows.
 * Used by the Dashboard and Reports pages.
 */
export function computeStats(scans: RecentScan[]): DashboardStats {
  return {
    totalScans:     scans.length,
    safeUrls:       scans.filter((s) => s.riskLevel === 'safe').length,
    suspiciousUrls: scans.filter((s) => s.riskLevel === 'suspicious').length,
    highRiskUrls:   scans.filter((s) => s.riskLevel === 'dangerous').length,
  };
}
