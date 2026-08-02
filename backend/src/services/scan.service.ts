/**
 * scan.service.ts
 * ───────────────
 * Business logic layer — assembles the full scan pipeline.
 *
 * Pipeline:
 *   1. Parse & validate the raw URL string
 *   2. Run structural checks        (urlStructureAnalyzer)
 *   3. Check trusted-domain list    (trustedDomains)
 *   4. Detect brand impersonation   (brandImpersonation)
 *   5. Query reputation provider    (domainReputation)
 *   6. Calculate weighted score     (riskScoring)
 *   7. Classify risk + recommend    (recommendationEngine)
 *   8. Generate AI explanation      (gemini.service)  ← NEW
 *   9. Return complete ScanResponse
 *
 * Architecture principle:
 *   The rule engine (steps 1–7) is the source of truth for the verdict.
 *   Gemini (step 8) only explains what the rule engine already decided.
 *   If Gemini fails, the scan is still returned — never blocked.
 *
 * Nothing in this file knows about HTTP — no req / res objects.
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
import { calculateScore, classifyRisk } from '../utils/riskScoring';
import { buildRecommendations } from '../utils/recommendationEngine';
import { generateExplanation } from './gemini.service';

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Thrown when the submitted URL cannot be parsed or has an unsupported scheme.
 * The controller catches this and returns a 400 response.
 */
export class InvalidUrlError extends Error {
  constructor(url: string) {
    super(`Invalid URL: "${url}". Must be a valid http:// or https:// address.`);
    this.name = 'InvalidUrlError';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Core scan function
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Runs the full phishing-detection + AI explanation pipeline.
 *
 * @param rawUrl  The URL string submitted by the user
 * @returns       A complete ScanResponse ready to serialise as JSON
 * @throws        InvalidUrlError if the URL cannot be parsed
 */
export async function scanUrl(rawUrl: string): Promise<ScanResponse> {
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
  const riskScore = calculateScore(checks);
  const riskLevel: RiskLevel = classifyRisk(riskScore);
  const recommendations = buildRecommendations(checks, riskLevel);

  // Assemble the rule-engine result before calling Gemini, so the AI
  // receives the complete, final scan data in its prompt.
  const ruleEngineResult: ScanResponse = {
    url: parsed.href,
    riskScore,
    riskLevel,
    checks,
    recommendations,
    recommendation: recommendations[0],
    aiExplanation: '', // placeholder — filled in step 8
  };

  // ── 8. AI explanation (Gemini) ───────────────────────────────────────────
  // generateExplanation never throws — it returns the fallback message on
  // any error, so the scan result is always returned to the client.
  const aiExplanation = await generateExplanation(ruleEngineResult);

  // ── 9. Return complete response ──────────────────────────────────────────
  return {
    ...ruleEngineResult,
    aiExplanation,
  };
}
