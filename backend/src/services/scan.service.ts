/**
 * scan.service.ts
 * ───────────────
 * Business logic layer — assembles the full scan pipeline AND persists results.
 *
 * Pipeline:
 *   1. Parse & validate the raw URL string
 *   2. Run structural checks        (urlStructureAnalyzer)
 *   3. Check trusted-domain list    (trustedDomains)
 *   4. Detect brand impersonation   (brandImpersonation)
 *   5. Query reputation provider    (domainReputation)
 *   6. Calculate weighted score     (riskScoring)
 *   7. Classify risk + recommend    (recommendationEngine)
 *   8. Generate AI explanation      (gemini.service)
 *   9. Persist to Supabase          (scan_results table via service role)
 *  10. Return complete ScanResponse
 *
 * Architecture principle:
 *   Steps 1–7 are the source of truth for the verdict.
 *   Step 8 (Gemini) only explains — if it fails, the scan proceeds.
 *   Step 9 (persistence) is fire-and-forget: if it fails we log the error
 *   but still return the result to the user. The scan is never blocked by DB.
 */

import {
  PhishingChecks,
  RiskLevel,
  ScanResponse,
} from '../models/scan.model';

import {
  parseUrl,
  checkHttps,
  checkIpAddress,
  checkLongUrl,
  checkManySubdomains,
  checkUrlShortener,
  checkSuspiciousKeywords,
  checkSuspiciousTld,
  countHyphens,
  checkEncodedChars,
} from '../utils/urlStructureAnalyzer';

import { isTrustedDomain } from '../config/trustedDomains';
import { detectBrandImpersonation } from '../utils/brandImpersonation';
import { getReputationProvider } from '../utils/domainReputation';
import { calculateScoreWithBreakdown, classifyRisk } from '../utils/riskScoring';
import { buildRecommendations } from '../utils/recommendationEngine';
import { generateExplanation } from './gemini.service';
import { getSupabaseAdmin } from '../config/supabaseAdmin';

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

export class InvalidUrlError extends Error {
  constructor(url: string) {
    super(`Invalid URL: "${url}". Must be a valid http:// or https:// address.`);
    this.name = 'InvalidUrlError';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Persistence helper
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Persists a completed scan result to the scan_results table.
 *
 * Uses the service-role client so RLS is bypassed for the INSERT.
 * The userId was verified by requireAuth middleware before this runs.
 *
 * This function never throws — persistence failure is logged but does NOT
 * prevent the scan result from being returned to the client.
 *
 * risk_level is stored lower-case ('safe'|'suspicious'|'dangerous') to match
 * the frontend RiskLevel type and the RLS SELECT policy.
 */
async function persistScanResult(
  userId: string,
  url: string,
  riskScore: number,
  riskLevel: RiskLevel,
): Promise<void> {
  try {
    const supabase = getSupabaseAdmin();

    const { error } = await supabase.from('scan_results').insert({
      user_id:    userId,
      url:        url,
      risk_score: riskScore,
      risk_level: riskLevel.toLowerCase(), // 'Safe' → 'safe'
    });

    if (error) {
      console.error('[scan.service] Failed to persist scan result:', {
        code:    error.code,
        message: error.message,
        details: error.details,
        hint:    error.hint,
      });
    } else {
      console.log(`[scan.service] Persisted scan for user ${userId}: ${url} → ${riskLevel} (${riskScore})`);
    }
  } catch (err) {
    // getSupabaseAdmin() throws if credentials are missing — log and continue
    console.error('[scan.service] Could not get Supabase admin client:', err);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Core scan function
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Runs the full phishing-detection + AI explanation pipeline, then persists.
 *
 * @param rawUrl  The URL string submitted by the user
 * @param userId  The verified Supabase user id (from requireAuth middleware)
 * @returns       A complete ScanResponse ready to serialise as JSON
 * @throws        InvalidUrlError if the URL cannot be parsed
 */
export async function scanUrl(rawUrl: string, userId: string): Promise<ScanResponse> {
  // ── 1. Parse & validate ──────────────────────────────────────────────────
  const parsed = parseUrl(rawUrl);
  if (!parsed) throw new InvalidUrlError(rawUrl);

  // ── 2. Structural checks ─────────────────────────────────────────────────
  const https            = checkHttps(parsed);
  const ipAddress        = checkIpAddress(parsed);
  const urlShortener     = checkUrlShortener(parsed);
  const longUrl          = checkLongUrl(parsed);
  const suspiciousTld    = checkSuspiciousTld(parsed);
  const manySubdomains   = checkManySubdomains(parsed);
  const hyphenCount      = countHyphens(parsed);
  const hasEncodedChars  = checkEncodedChars(parsed);
  const suspiciousKeywords = checkSuspiciousKeywords(parsed);

  // ── 3. Trusted-domain whitelist ──────────────────────────────────────────
  const trusted = isTrustedDomain(parsed.hostname);

  // ── 4. Brand impersonation ───────────────────────────────────────────────
  const brandImpersonation = detectBrandImpersonation(parsed);

  // ── 5. Domain reputation ─────────────────────────────────────────────────
  const reputationProvider = getReputationProvider();
  const reputation = await reputationProvider.checkUrl(parsed.href);

  // ── 6. Assemble checks object ────────────────────────────────────────────
  const checks: PhishingChecks = {
    https,
    ipAddress,
    urlShortener,
    longUrl,
    suspiciousKeywords,
    suspiciousTld,
    manySubdomains,
    hyphenCount,
    hasEncodedChars,
    brandImpersonation,
    isTrustedDomain: trusted,
    reputation,
  };

  // ── 7. Score, classify, recommend ────────────────────────────────────────
  const { score: riskScore, breakdown: scoreBreakdown } = calculateScoreWithBreakdown(checks);
  const riskLevel: RiskLevel = classifyRisk(riskScore);
  const recommendations = buildRecommendations(checks, riskLevel);

  const ruleEngineResult: ScanResponse = {
    url: parsed.href,
    riskScore,
    riskLevel,
    checks,
    scoreBreakdown,
    recommendations,
    recommendation: recommendations[0],
    aiExplanation: '',
    aiExplanationProvider: 'deterministic',
  };

  // ── 8. AI explanation (Gemini) ───────────────────────────────────────────
  // generateExplanation never throws — returns ExplanationResult with
  // explanation text + provider label ('gemini' | 'deterministic').
  // If Gemini times out, errors, or returns 503, the deterministic fallback
  // is used immediately and the scan response is returned without delay.
  const { explanation: aiExplanation, provider: aiExplanationProvider } =
    await generateExplanation(ruleEngineResult);

  const finalResult: ScanResponse = {
    ...ruleEngineResult,
    aiExplanation,
    aiExplanationProvider,
  };

  // ── 9. Persist to Supabase ───────────────────────────────────────────────
  // Fire-and-forget: await ensures the insert finishes before responding,
  // but errors are caught inside persistScanResult and never re-thrown.
  await persistScanResult(userId, parsed.href, riskScore, riskLevel);

  // ── 10. Return ───────────────────────────────────────────────────────────
  return finalResult;
}
