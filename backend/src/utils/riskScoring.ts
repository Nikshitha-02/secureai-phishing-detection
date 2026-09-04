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
 *
 * DESIGN PHILOSOPHY
 * ──────────────────
 * Individual weak signals (e.g. a suspicious TLD, a keyword in a path) score
 * in the Suspicious band on their own. Only the combination of multiple
 * independent signals — or a single very strong signal (IP address, brand
 * impersonation with action keywords) — pushes a URL into Dangerous.
 *
 * This keeps false positives extremely low while raising recall for genuine
 * multi-signal phishing URLs.
 */

import type { PhishingChecks, RiskLevel, ScoreContribution } from '../models/scan.model';

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
   * Additional penalty when brand impersonation is detected AND phishing
   * action keywords are present in the URL path or query.
   *
   * This covers cases like:
   *   paypal-helpdesk.com/update          (brand + path keyword)
   *   secure-paypal-login.com/verify-account  (brand + path keyword)
   *
   * These URLs are NOT on a suspicious TLD but the brand+keyword+action
   * combination is strong evidence of phishing.
   */
  impersonationActionCombo: 20,

  /**
   * Additional penalty when brand impersonation + multiple hyphens
   * in the hostname + action keyword in path all co-occur.
   * Covers "secure-paypal-login.com/verify-account" style URLs.
   */
  impersonationHyphenActionCombo: 5,

  /**
   * Additional penalty when brand impersonation AND excessive subdomain
   * nesting co-occur.
   *
   * This covers "login.secure.paypal-helpdesk.com/update" style URLs
   * where the attacker uses deep subdomains to make the URL look legitimate
   * at a glance.
   *
   * We only add this bonus when keyword signals are also present, to ensure
   * legitimate CDN/API subdomains don't get penalised.
   */
  impersonationSubdomainCombo: 10,

  /**
   * Additional penalty when a suspicious TLD AND multiple prize/scam keywords
   * co-occur in the URL.
   *
   * This covers "free-gift-claim.xyz/winner?prize=iphone" style prize scams
   * that lack brand impersonation but combine multiple strong scam signals.
   *
   * Triggers when: suspiciousTld=true AND ≥2 prize/scam keywords present.
   */
  prizeScamCombo: 40,

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
  maxKeywordScore: 25, // total keyword contribution never exceeds this

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
 * Calculates the aggregate risk score AND a per-signal breakdown from a
 * completed PhishingChecks object.
 *
 * The breakdown array explains every point contribution so the frontend and
 * audit trail can show exactly why a URL scored as it did.
 *
 * @param checks  Fully populated PhishingChecks (after all detectors have run)
 * @returns       { score: number [0–100], breakdown: ScoreContribution[] }
 */
export function calculateScoreWithBreakdown(
  checks: PhishingChecks,
): { score: number; breakdown: ScoreContribution[] } {
  let score = 0;
  const breakdown: ScoreContribution[] = [];

  // ── Structural signals ────────────────────────────────────────────────────
  if (!checks.https) {
    const pts = SCORE_WEIGHTS.noHttps;
    score += pts;
    breakdown.push({ signal: 'noHttps', description: 'URL uses HTTP instead of HTTPS — connection is unencrypted', points: pts, severity: 'high' });
  }
  if (checks.ipAddress) {
    const pts = SCORE_WEIGHTS.ipAddress;
    score += pts;
    breakdown.push({ signal: 'ipAddress', description: 'Hostname is a raw IP address rather than a registered domain name — a common indicator of phishing infrastructure', points: pts, severity: 'critical' });
  }
  if (checks.urlShortener) {
    const pts = SCORE_WEIGHTS.urlShortener;
    score += pts;
    breakdown.push({ signal: 'urlShortener', description: 'URL passes through a shortener service that hides the real destination', points: pts, severity: 'medium' });
  }
  if (checks.longUrl) {
    const pts = SCORE_WEIGHTS.longUrl;
    score += pts;
    breakdown.push({ signal: 'longUrl', description: 'URL is unusually long — often used to hide the real destination in query parameters', points: pts, severity: 'low' });
  }
  if (checks.suspiciousTld) {
    const pts = SCORE_WEIGHTS.suspiciousTld;
    score += pts;
    breakdown.push({ signal: 'suspiciousTld', description: 'Domain uses a high-risk or commonly abused top-level domain', points: pts, severity: 'medium' });
  }
  if (checks.manySubdomains) {
    const pts = SCORE_WEIGHTS.manySubdomains;
    score += pts;
    breakdown.push({ signal: 'manySubdomains', description: 'Hostname has excessive subdomain nesting — a technique used to hide the real domain', points: pts, severity: 'medium' });
  }
  if (checks.hasEncodedChars) {
    const pts = SCORE_WEIGHTS.encodedChars;
    score += pts;
    breakdown.push({ signal: 'encodedChars', description: 'URL contains percent-encoded characters that may obfuscate the true destination', points: pts, severity: 'low' });
  }

  // ── Hyphen penalty (per extra hyphen above threshold) ─────────────────────
  const extraHyphens = Math.max(0, checks.hyphenCount - HYPHEN_PENALTY_THRESHOLD);
  if (extraHyphens > 0) {
    const pts = extraHyphens * SCORE_WEIGHTS.hyphenPenalty;
    score += pts;
    breakdown.push({ signal: 'hyphenCount', description: `Hostname contains ${checks.hyphenCount} hyphens (${extraHyphens} above the normal threshold)`, points: pts, severity: 'low' });
  }

  // ── Keyword penalty (capped) ──────────────────────────────────────────────
  const rawKeywordScore = checks.suspiciousKeywords.length * SCORE_WEIGHTS.keywordPenalty;
  const keywordScore = Math.min(rawKeywordScore, SCORE_WEIGHTS.maxKeywordScore);
  if (keywordScore > 0) {
    score += keywordScore;
    breakdown.push({ signal: 'suspiciousKeywords', description: `Contains phishing action keywords: ${checks.suspiciousKeywords.slice(0, 4).join(', ')}`, points: keywordScore, severity: 'medium' });
  }

  // ── Brand impersonation (only when NOT a trusted domain) ─────────────────
  if (checks.brandImpersonation !== null && !checks.isTrustedDomain) {
    const basePts = SCORE_WEIGHTS.brandImpersonation;
    score += basePts;
    breakdown.push({ signal: 'brandImpersonation', description: `Hostname appears to impersonate the "${checks.brandImpersonation.brand}" brand`, points: basePts, severity: 'critical' });

    // Combination bonus 1: brand + suspicious TLD
    if (checks.suspiciousTld) {
      const pts = SCORE_WEIGHTS.impersonationTldCombo;
      score += pts;
      breakdown.push({ signal: 'impersonationTldCombo', description: `Brand impersonation combined with a high-risk TLD — near-certain phishing`, points: pts, severity: 'critical' });
    }

    // Combination bonus 2: brand + action keywords
    if (checks.suspiciousKeywords.length > 0) {
      const pts = SCORE_WEIGHTS.impersonationActionCombo;
      score += pts;
      breakdown.push({ signal: 'impersonationActionCombo', description: `Brand impersonation combined with action/urgency keywords in the URL path`, points: pts, severity: 'critical' });

      // Combination bonus 3: also has multiple hyphens
      if (extraHyphens >= 1) {
        const pts2 = SCORE_WEIGHTS.impersonationHyphenActionCombo;
        score += pts2;
        breakdown.push({ signal: 'impersonationHyphenActionCombo', description: `Brand impersonation with multiple hyphens and action keywords — high confidence phishing pattern`, points: pts2, severity: 'high' });
      }

      // Combination bonus 4: brand + deep subdomains
      if (checks.manySubdomains) {
        const pts3 = SCORE_WEIGHTS.impersonationSubdomainCombo;
        score += pts3;
        breakdown.push({ signal: 'impersonationSubdomainCombo', description: `Brand impersonation with deep subdomain nesting — attacker using fake subdomains to look legitimate`, points: pts3, severity: 'high' });
      }
    }
  }

  // ── Prize/scam combination signal ────────────────────────────────────────
  if (!checks.isTrustedDomain && checks.suspiciousTld) {
    const scamKeywords = new Set(['winner', 'prize', 'free-gift', 'gift-claim', 'claim', 'reward', 'lucky', 'free-iphone', 'win-prize', 'claim-prize', 'gift']);
    const scamHits = checks.suspiciousKeywords.filter((kw) => scamKeywords.has(kw)).length;
    if (scamHits >= 2) {
      const pts = SCORE_WEIGHTS.prizeScamCombo;
      score += pts;
      breakdown.push({ signal: 'prizeScamCombo', description: `Suspicious TLD combined with multiple prize/scam keywords — prize-scam phishing pattern`, points: pts, severity: 'critical' });
    }
  }

  // ── Reputation provider result ────────────────────────────────────────────
  if (checks.reputation.status === 'malicious') {
    const pts = SCORE_WEIGHTS.reputationMalicious;
    score += pts;
    breakdown.push({ signal: 'reputationMalicious', description: `Flagged as malicious by ${checks.reputation.source ?? 'reputation provider'}`, points: pts, severity: 'critical' });
  } else if (checks.reputation.status === 'suspicious') {
    const pts = SCORE_WEIGHTS.reputationSuspicious;
    score += pts;
    breakdown.push({ signal: 'reputationSuspicious', description: `Flagged as suspicious by ${checks.reputation.source ?? 'reputation provider'}`, points: pts, severity: 'high' });
  }

  // ── Trusted domain discount ───────────────────────────────────────────────
  if (checks.isTrustedDomain) {
    const discount = rawKeywordScore +
      (checks.manySubdomains ? SCORE_WEIGHTS.manySubdomains : 0) +
      extraHyphens * SCORE_WEIGHTS.hyphenPenalty +
      (checks.hasEncodedChars ? SCORE_WEIGHTS.encodedChars : 0);

    if (discount > 0) {
      score -= discount;
      breakdown.push({ signal: 'trustedDomainDiscount', description: `Domain is on the trusted whitelist — keyword, subdomain, hyphen and encoding signals removed`, points: -discount, severity: 'info' });
    }
  }

  // Clamp to [0, 100]
  const finalScore = Math.min(100, Math.max(0, Math.round(score)));
  return { score: finalScore, breakdown };
}

/**
 * Calculates the aggregate risk score from a completed PhishingChecks object.
 * Backward-compatible wrapper around calculateScoreWithBreakdown.
 *
 * @param checks  Fully populated PhishingChecks (after all detectors have run)
 * @returns       Integer in the range [0, 100]
 */
export function calculateScore(checks: PhishingChecks): number {
  return calculateScoreWithBreakdown(checks).score;
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
