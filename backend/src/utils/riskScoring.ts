/**
 * riskScoring.ts
 * ──────────────
 * Weighted risk scoring engine.
 *
 * Converts a set of PhishingChecks into a numeric risk score (0–100) and
 * classifies it into a RiskLevel band.
 *
 * All weights are centralised here so they can be tuned in one place
 * without touching any other file.
 *
 * Score bands:
 *   0  – 30   Safe
 *   31 – 70   Suspicious
 *   71 – 100  Dangerous
 */

import type { PhishingChecks, RiskLevel } from '../models/scan.model';

// ─────────────────────────────────────────────────────────────────────────────
// Weight table
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Each key corresponds to one check result in PhishingChecks.
 * Values are the maximum points that check can contribute to the score.
 *
 * Adjust these numbers to tune sensitivity without changing logic elsewhere.
 */
export const SCORE_WEIGHTS = {
  /** HTTP instead of HTTPS */
  noHttps: 20,

  /**
   * Raw IP address in the hostname.
   * A raw IP in a public URL is nearly always malicious — very high weight.
   */
  ipAddress: 40,

  /** Known URL shortener */
  urlShortener: 15,

  /** URL exceeds length threshold */
  longUrl: 10,

  /** High-risk / abused TLD */
  suspiciousTld: 15,

  /** Excessive subdomain nesting */
  manySubdomains: 10,

  /**
   * Brand impersonation (brand + keyword + untrusted domain).
   * The most explicit phishing signal — bumped to push these URLs to Dangerous.
   */
  brandImpersonation: 35,

  /**
   * Additional penalty when brand impersonation and a suspicious TLD are
   * both present. This combination is a near-certain phishing signal.
   * e.g. "google-login.xyz" — already scored 50, this pushes it to 71+.
   */
  impersonationTldCombo: 25,

  /**
   * Per-hyphen penalty applied for each hyphen above the "normal" threshold.
   * A single domain like "my-company.com" is fine; "secure-paypal-login.com" is not.
   */
  hyphenPenalty: 5,

  /** URL contains percent-encoded characters */
  encodedChars: 10,

  /**
   * Per phishing action-keyword found in the URL path/query.
   * Capped to avoid runaway scoring from many keywords.
   */
  keywordPenalty: 5,
  maxKeywordScore: 20, // total keyword contribution never exceeds this

  /**
   * Reputation provider verdict.
   * Placeholder values — only applied when a real provider is wired in.
   */
  reputationMalicious: 40,
  reputationSuspicious: 20,
} as const;

/** Hyphens in the hostname up to this count are considered normal */
export const HYPHEN_PENALTY_THRESHOLD = 1;

// ─────────────────────────────────────────────────────────────────────────────
// Score calculation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Calculates the aggregate risk score from a completed PhishingChecks object.
 *
 * @param checks  Fully populated PhishingChecks (after all detectors have run)
 * @returns       Integer in the range [0, 100]
 */
export function calculateScore(checks: PhishingChecks): number {
  let score = 0;

  // ── Structural signals ────────────────────────────────────────────────────
  if (!checks.https)          score += SCORE_WEIGHTS.noHttps;
  if (checks.ipAddress)       score += SCORE_WEIGHTS.ipAddress;
  if (checks.urlShortener)    score += SCORE_WEIGHTS.urlShortener;
  if (checks.longUrl)         score += SCORE_WEIGHTS.longUrl;
  if (checks.suspiciousTld)   score += SCORE_WEIGHTS.suspiciousTld;
  if (checks.manySubdomains)  score += SCORE_WEIGHTS.manySubdomains;
  if (checks.hasEncodedChars) score += SCORE_WEIGHTS.encodedChars;

  // ── Hyphen penalty (per extra hyphen above threshold) ─────────────────────
  const extraHyphens = Math.max(0, checks.hyphenCount - HYPHEN_PENALTY_THRESHOLD);
  score += extraHyphens * SCORE_WEIGHTS.hyphenPenalty;

  // ── Keyword penalty (capped) ──────────────────────────────────────────────
  const rawKeywordScore = checks.suspiciousKeywords.length * SCORE_WEIGHTS.keywordPenalty;
  score += Math.min(rawKeywordScore, SCORE_WEIGHTS.maxKeywordScore);

  // ── Brand impersonation (only when NOT a trusted domain) ─────────────────
  if (checks.brandImpersonation !== null && !checks.isTrustedDomain) {
    score += SCORE_WEIGHTS.brandImpersonation;

    // Combination bonus: brand impersonation on a suspicious TLD is a
    // near-certain phishing signal — push it firmly into Dangerous.
    if (checks.suspiciousTld) {
      score += SCORE_WEIGHTS.impersonationTldCombo;
    }
  }

  // ── Reputation provider result ────────────────────────────────────────────
  if (checks.reputation.status === 'malicious') {
    score += SCORE_WEIGHTS.reputationMalicious;
  } else if (checks.reputation.status === 'suspicious') {
    score += SCORE_WEIGHTS.reputationSuspicious;
  }

  // ── Trusted domain discount ───────────────────────────────────────────────
  // A fully trusted domain gets a score floor — we never score a trusted
  // domain as Dangerous purely from keyword/structural checks.
  // (The ip / reputation checks are still valid even for trusted domains.)
  if (checks.isTrustedDomain) {
    // Remove keyword, subdomain, hyphen, and encoding scores —
    // those signals are not meaningful on real brand domains.
    score -= rawKeywordScore;
    score -= (checks.manySubdomains ? SCORE_WEIGHTS.manySubdomains : 0);
    score -= extraHyphens * SCORE_WEIGHTS.hyphenPenalty;
    score -= (checks.hasEncodedChars ? SCORE_WEIGHTS.encodedChars : 0);
  }

  // Clamp to [0, 100]
  return Math.min(100, Math.max(0, Math.round(score)));
}

// ─────────────────────────────────────────────────────────────────────────────
// Risk classification
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Converts a numeric score into a human-readable RiskLevel band.
 */
export function classifyRisk(score: number): RiskLevel {
  if (score <= 30) return 'Safe';
  if (score <= 70) return 'Suspicious';
  return 'Dangerous';
}
