/**
 * brandImpersonation.ts
 * ─────────────────────
 * Detects when a URL hostname is trying to impersonate a well-known brand.
 *
 * The key insight that prevents false positives:
 *
 *   "google.com"        → isTrustedDomain = true  → no impersonation check
 *   "mail.google.com"   → subdomain of trusted     → no impersonation check
 *   "google-login.xyz"  → brand name present BUT not a trusted domain
 *                          + phishing keyword present → IMPERSONATION ✓
 *
 * Detection has two complementary layers:
 *
 *   LAYER 1 — Exact brand-name match:
 *     The brand name appears as a literal substring of the hostname.
 *     Requires ALL THREE conditions to fire:
 *       1. Brand name appears in the hostname
 *       2. A phishing keyword appears in the hostname OR the TLD is suspicious
 *       3. The domain is NOT on the trusted-domain whitelist
 *
 *   LAYER 2 — Typosquatting / homoglyph detection:
 *     The hostname, after normalisation (homoglyph substitution), matches a
 *     known brand name with at most 1 character difference (Levenshtein ≤ 1
 *     or known digit/character swap). Designed to catch:
 *       - paypa1  → paypal   (digit 1 for letter l)
 *       - netfiix → netflix  (capital I renders like l; detected after lc-norm)
 *       - rnicro  → micro    (rn rendered as m)
 *     Only fires on untrusted domains to avoid false positives on legitimate sites.
 */

import { isTrustedDomain } from '../config/trustedDomains';
import type { BrandImpersonationResult } from '../models/scan.model';

// ─────────────────────────────────────────────────────────────────────────────
// Brand name registry
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Map of brand name → trusted apex domains.
 * The apex domains are used to confirm that an exact/subdomain match is
 * legitimate, so those cases are skipped before impersonation checks run.
 *
 * Add entries here as new brands need coverage.
 *
 * IMPORTANT: icloud is listed separately so hostname-level matching works.
 * Apple's actual iCloud domain (icloud.com) is also in trustedDomains.ts,
 * so legitimate icloud.com URLs are always whitelisted before reaching here.
 */
const BRAND_REGISTRY: Record<string, string[]> = {
  google:       ['google.com', 'googleapis.com', 'googlesyndication.com', 'googletagmanager.com'],
  github:       ['github.com'],
  microsoft:    ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'azure.com', 'bing.com', 'msn.com'],
  amazon:       ['amazon.com', 'amazonaws.com', 'aws.amazon.com'],
  apple:        ['apple.com', 'icloud.com'],
  icloud:       ['icloud.com', 'apple.com'],
  paypal:       ['paypal.com'],
  netflix:      ['netflix.com'],
  facebook:     ['facebook.com', 'fb.com', 'messenger.com'],
  instagram:    ['instagram.com'],
  twitter:      ['twitter.com', 'x.com'],
  linkedin:     ['linkedin.com'],
  youtube:      ['youtube.com'],
  ebay:         ['ebay.com'],
  adobe:        ['adobe.com'],
  dropbox:      ['dropbox.com'],
  spotify:      ['spotify.com'],
  stripe:       ['stripe.com'],
  chase:        ['chase.com'],
  wellsfargo:   ['wellsfargo.com'],
  bankofamerica:['bankofamerica.com'],
  openai:       ['openai.com'],
  discord:      ['discord.com'],
  zoom:         ['zoom.us'],
  slack:        ['slack.com'],
  shopify:      ['shopify.com'],
  cloudflare:   ['cloudflare.com'],
};

/**
 * Keywords that — when combined with a brand name in the hostname — strongly
 * indicate impersonation rather than a legitimate brand subdomain.
 *
 * These are action or urgency words that a real brand would NOT include
 * inside the domain name itself.
 */
const IMPERSONATION_KEYWORDS: string[] = [
  'login',
  'signin',
  'sign-in',
  'secure',
  'security',
  'verify',
  'verification',
  'account',
  'update',
  'confirm',
  'support',
  'helpdesk',
  'password',
  'reset',
  'billing',
  'payment',
  'invoice',
  'unlock',
  'suspended',
  'alert',
  'recovery',
  'access',
  'portal',
  'auth',
  'validate',
  'credential',
];

/** High-risk TLDs that together with a brand name are a strong impersonation signal */
const HIGH_RISK_TLDS_FOR_IMPERSONATION = new Set<string>([
  '.tk', '.ml', '.ga', '.cf', '.gq',
  '.xyz', '.top', '.click', '.pw',
  '.icu', '.live', '.online', '.site',
  '.work', '.buzz', '.rest', '.fun',
  '.cc', '.biz', '.ws', '.vip', '.win',
  '.download', '.stream', '.net',
]);

// ─────────────────────────────────────────────────────────────────────────────
// Homoglyph / typosquatting normalisation table
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Character substitution table for visual lookalike attacks.
 *
 * Keys are the characters attackers use; values are the canonical ASCII
 * character they mimic. After replacing all keys with values, the hostname
 * can be compared to known brand names for near-matches.
 *
 * This covers the most common practical substitutions seen in phishing domains:
 *   - Digit-for-letter swaps (0→o, 1→l, 3→e, 4→a, 5→s, etc.)
 *   - Unicode homoglyphs (ɑ→a, ν→v, etc.)
 *   - Letter combination substitutions (rn→m handled separately)
 */
const HOMOGLYPH_MAP: Record<string, string> = {
  '0': 'o',
  '1': 'l',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '6': 'g',
  '8': 'b',
  '@': 'a',
  'ɑ': 'a', // Cyrillic/IPA alpha
  'à': 'a',
  'á': 'a',
  'â': 'a',
  'ä': 'a',
  'ã': 'a',
  'å': 'a',
  'ç': 'c',
  'è': 'e',
  'é': 'e',
  'ê': 'e',
  'ë': 'e',
  'ì': 'i',
  'í': 'i',
  'î': 'i',
  'ï': 'i',
  'ñ': 'n',
  'ò': 'o',
  'ó': 'o',
  'ô': 'o',
  'ö': 'o',
  'õ': 'o',
  'ø': 'o',
  'ù': 'u',
  'ú': 'u',
  'û': 'u',
  'ü': 'u',
  'ý': 'y',
  'ß': 'ss',
  'ν': 'v',  // Greek nu
  'μ': 'u',  // Greek mu
  'κ': 'k',  // Greek kappa
  'ο': 'o',  // Greek omicron
  'ρ': 'p',  // Greek rho
  'τ': 't',  // Greek tau
  'χ': 'x',  // Greek chi
};

/**
 * Normalises a hostname segment by replacing homoglyphs with canonical ASCII.
 *
 * Also handles:
 *   - "rn" → "m" substitution (two letters that look like one)
 *
 * This is used only for typosquatting detection, never for whitelist checks.
 */
function normaliseHomoglyphs(s: string): string {
  let result = s.toLowerCase();

  // Apply character-level substitutions
  for (const [from, to] of Object.entries(HOMOGLYPH_MAP)) {
    // Use split/join for simple single-char replacements (no regex needed)
    result = result.split(from).join(to);
  }

  // "rn" → "m" (common visual confusion: rn looks like m in many fonts)
  result = result.replace(/rn/g, 'm');

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Levenshtein distance (for near-match typosquatting detection)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Computes the Levenshtein edit distance between two strings.
 * Used to detect typosquatting where one character is changed/swapped.
 *
 * We only run this for short strings (brand names ≤ 20 chars) so performance
 * is not a concern.
 */
function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;

  // Use a 1D rolling array for memory efficiency
  const dp: number[] = Array.from({ length: n + 1 }, (_, i) => i);

  for (let i = 1; i <= m; i++) {
    let prev = i;
    for (let j = 1; j <= n; j++) {
      const val =
        a[i - 1] === b[j - 1]
          ? dp[j - 1]
          : 1 + Math.min(dp[j - 1], dp[j], prev);
      dp[j - 1] = prev;
      prev = val;
    }
    dp[n] = prev;
  }

  return dp[n];
}

// ─────────────────────────────────────────────────────────────────────────────
// Main detection function
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Checks whether the hostname appears to impersonate a trusted brand.
 *
 * Returns a BrandImpersonationResult if impersonation is detected, otherwise null.
 *
 * @param parsed   Pre-parsed URL object
 */
export function detectBrandImpersonation(
  parsed: URL,
): BrandImpersonationResult | null {
  const hostname = parsed.hostname.toLowerCase();

  // ── Guard: trusted domains never impersonate themselves ──────────────────
  if (isTrustedDomain(hostname)) return null;

  // ── Extract TLD for high-risk check ──────────────────────────────────────
  const dotIdx = hostname.lastIndexOf('.');
  const tld = dotIdx !== -1 ? hostname.slice(dotIdx) : '';
  const hasSuspiciousTld = HIGH_RISK_TLDS_FOR_IMPERSONATION.has(tld);

  // ── LAYER 1: Exact brand name in hostname ─────────────────────────────────
  for (const [brand] of Object.entries(BRAND_REGISTRY)) {
    // Does the brand name appear somewhere in the hostname?
    if (!hostname.includes(brand)) continue;

    // Condition 3: a phishing keyword OR a suspicious TLD
    const hasImpersonationKeyword = IMPERSONATION_KEYWORDS.some((kw) =>
      hostname.includes(kw),
    );

    if (hasImpersonationKeyword || hasSuspiciousTld) {
      return { brand, hostname };
    }
  }

  // ── LAYER 2: Typosquatting / homoglyph detection ──────────────────────────
  //
  // Strategy:
  //   a. Split the hostname into dot-separated labels.
  //   b. For each label, also split on hyphens to get individual word segments.
  //   c. Normalise each segment by replacing known homoglyphs.
  //   d. Compare normalised text against every brand name using:
  //        i.  Exact match after normalisation (catches paypa1 → paypal)
  //        ii. Levenshtein distance ≤ 1 (one substitution/insertion/deletion)
  //            — only for brands longer than 4 chars to avoid false positives
  //              on short common words
  //
  // We check ALL labels in the hostname (including subdomains) because
  // phishing URLs often embed the typosquatted brand in a subdomain label,
  // e.g. "paypa1-secure.login.verify-account.tk" (paypa1 is the subdomain).
  //
  // We still require at least one additional signal (suspicious TLD, keyword,
  // or hyphens) before declaring impersonation, to avoid flagging legitimate
  // domains that happen to share short letter sequences with brand names.

  // Build candidate segments from all hostname labels and their hyphen parts
  const allLabels = hostname.split('.');
  const candidateSegments = new Set<string>();
  for (const label of allLabels) {
    if (label.length >= 3) candidateSegments.add(label);
    for (const part of label.split('-')) {
      if (part.length >= 3) candidateSegments.add(part);
    }
  }

  for (const segment of candidateSegments) {
    const normalised = normaliseHomoglyphs(segment);

    for (const [brand] of Object.entries(BRAND_REGISTRY)) {
      if (brand.length < 4) continue; // short brand names → too many false positives

      // Check if normalised segment contains the brand or is very close to it
      const isExactContained = normalised.includes(brand);

      // For Levenshtein: compare normalised segment against brand only when
      // lengths are similar (within 2 chars) to avoid irrelevant comparisons
      const lenDiff = Math.abs(normalised.length - brand.length);
      const isNearMatch = lenDiff <= 1 && levenshtein(normalised, brand) <= 1;

      if (isExactContained || isNearMatch) {
        // Verify this is actually a new detection — literal brand already
        // handled in Layer 1, so this only triggers when the literal check missed
        if (hostname.includes(brand)) continue; // already detected or whitelisted

        // Require at least one additional signal for near-matches:
        // suspicious TLD, impersonation keyword, or hyphens in hostname
        const hasKeyword = IMPERSONATION_KEYWORDS.some((kw) => hostname.includes(kw));
        const hasHyphens = (hostname.match(/-/g) ?? []).length >= 1;

        if (hasSuspiciousTld || hasKeyword || hasHyphens) {
          return { brand, hostname };
        }
      }
    }
  }

  return null;
}

/**
 * Returns all brand names that appear in the URL hostname.
 * Used for informational purposes in scan results.
 *
 * Includes both exact matches and typosquatting detections.
 */
export function detectBrandsInHostname(hostname: string): string[] {
  const lower = hostname.toLowerCase();
  const found = new Set<string>();

  // Exact substring matches
  for (const brand of Object.keys(BRAND_REGISTRY)) {
    if (lower.includes(brand)) found.add(brand);
  }

  // Homoglyph/typosquatting matches on all label and hyphen segments
  const allLabels = lower.split('.');
  for (const label of allLabels) {
    const segments = [label, ...label.split('-')];
    for (const segment of segments) {
      if (segment.length < 3) continue;
      const normalised = normaliseHomoglyphs(segment);
      for (const brand of Object.keys(BRAND_REGISTRY)) {
        if (brand.length < 4) continue;
        const lenDiff = Math.abs(normalised.length - brand.length);
        if (normalised.includes(brand) || (lenDiff <= 1 && levenshtein(normalised, brand) <= 1)) {
          found.add(brand);
        }
      }
    }
  }

  return Array.from(found);
}
