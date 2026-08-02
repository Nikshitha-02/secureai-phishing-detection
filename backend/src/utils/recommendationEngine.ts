/**
 * recommendationEngine.ts
 * ───────────────────────
 * Generates specific, actionable recommendations for each triggered check.
 *
 * Design principles:
 *  - One recommendation per triggered check (specific, not generic).
 *  - Recommendations are ordered from highest to lowest severity.
 *  - A "Safe" result still returns a positive confirmation message.
 *  - The final list is deduplicated (no duplicate messages).
 *
 * This module has no side effects and is fully unit-testable.
 */

import type { PhishingChecks, RiskLevel } from '../models/scan.model';

// ─────────────────────────────────────────────────────────────────────────────
// Per-check recommendation messages
// ─────────────────────────────────────────────────────────────────────────────

const MESSAGES = {
  // Structural
  noHttps:
    'Uses HTTP instead of HTTPS — your connection is not encrypted and can be intercepted.',
  ipAddress:
    'The domain is a raw IP address instead of a registered domain name — a strong phishing indicator.',
  urlShortener:
    'The URL goes through a shortener service that hides the real destination.',
  longUrl:
    'The URL is unusually long — often used to bury the real domain in visual noise.',
  suspiciousTld:
    'Uses a high-risk top-level domain (e.g. .tk, .xyz, .click) that is frequently abused in phishing campaigns.',
  manySubdomains:
    'The hostname has an abnormally deep subdomain structure, a common technique to make fake URLs look legitimate.',
  encodedChars:
    'The URL contains percent-encoded characters — sometimes used to disguise malicious paths.',
  excessiveHyphens:
    'The hostname contains multiple hyphens, a pattern common in machine-generated phishing domains.',

  // Brand impersonation
  brandImpersonation: (brand: string, hostname: string) =>
    `Domain "${hostname}" appears to impersonate "${brand}" — do not enter any credentials.`,

  // Keywords
  keywords: (kws: string[]) =>
    `Contains phishing action-keywords in the URL: ${kws.slice(0, 4).join(', ')}.`,

  // Reputation
  reputationMalicious: (source: string, detail: string | null) =>
    `Flagged as malicious by ${source}${detail ? ` (${detail})` : ''}.`,
  reputationSuspicious: (source: string) =>
    `Flagged as suspicious by ${source}.`,

  // Safe / catch-all
  safe:
    'No significant phishing indicators detected. The domain is on the trusted-domain whitelist.',
  safeNoTrust:
    'No significant phishing indicators detected.',
  multipleIndicators:
    'Multiple phishing indicators detected — treat this URL as dangerous.',
} as const;

// ─────────────────────────────────────────────────────────────────────────────
// Builder
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Builds an ordered, deduplicated list of specific recommendations based on
 * which checks triggered.
 *
 * @param checks     Fully populated PhishingChecks object
 * @param riskLevel  The classified risk level for this scan
 * @returns          Non-empty array of recommendation strings
 */
export function buildRecommendations(
  checks: PhishingChecks,
  riskLevel: RiskLevel,
): string[] {
  const items: string[] = [];

  // ── Highest severity first ────────────────────────────────────────────────

  // Reputation verdict (from an external API — most authoritative)
  if (checks.reputation.status === 'malicious' && checks.reputation.source) {
    items.push(MESSAGES.reputationMalicious(checks.reputation.source, checks.reputation.detail));
  } else if (checks.reputation.status === 'suspicious' && checks.reputation.source) {
    items.push(MESSAGES.reputationSuspicious(checks.reputation.source));
  }

  // Brand impersonation
  if (checks.brandImpersonation && !checks.isTrustedDomain) {
    items.push(
      MESSAGES.brandImpersonation(
        checks.brandImpersonation.brand,
        checks.brandImpersonation.hostname,
      ),
    );
  }

  // Raw IP address
  if (checks.ipAddress) {
    items.push(MESSAGES.ipAddress);
  }

  // HTTP
  if (!checks.https) {
    items.push(MESSAGES.noHttps);
  }

  // Suspicious TLD
  if (checks.suspiciousTld) {
    items.push(MESSAGES.suspiciousTld);
  }

  // URL shortener
  if (checks.urlShortener) {
    items.push(MESSAGES.urlShortener);
  }

  // Keywords (only show if not a trusted domain, to avoid false messages)
  if (checks.suspiciousKeywords.length > 0 && !checks.isTrustedDomain) {
    items.push(MESSAGES.keywords(checks.suspiciousKeywords));
  }

  // Excessive hyphens (only meaningful on untrusted domains)
  if (checks.hyphenCount > 2 && !checks.isTrustedDomain) {
    items.push(MESSAGES.excessiveHyphens);
  }

  // Many subdomains
  if (checks.manySubdomains && !checks.isTrustedDomain) {
    items.push(MESSAGES.manySubdomains);
  }

  // Long URL
  if (checks.longUrl) {
    items.push(MESSAGES.longUrl);
  }

  // Encoded characters (lower priority)
  if (checks.hasEncodedChars && !checks.isTrustedDomain) {
    items.push(MESSAGES.encodedChars);
  }

  // ── Multiple indicators summary (for Dangerous level only) ───────────────
  if (riskLevel === 'Dangerous' && items.length > 2) {
    items.push(MESSAGES.multipleIndicators);
  }

  // ── Safe result ───────────────────────────────────────────────────────────
  if (items.length === 0) {
    items.push(checks.isTrustedDomain ? MESSAGES.safe : MESSAGES.safeNoTrust);
  }

  // Deduplicate (preserves order)
  return [...new Set(items)];
}
