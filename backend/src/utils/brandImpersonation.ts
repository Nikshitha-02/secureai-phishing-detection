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
 * Detection logic requires ALL THREE conditions to fire:
 *   1. Brand name appears in the hostname
 *   2. A phishing keyword appears in the hostname OR the TLD is suspicious
 *   3. The domain is NOT on the trusted-domain whitelist
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
 */
const BRAND_REGISTRY: Record<string, string[]> = {
  google: ['google.com', 'googleapis.com', 'googlesyndication.com', 'googletagmanager.com'],
  github: ['github.com'],
  microsoft: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'azure.com', 'bing.com', 'msn.com'],
  amazon: ['amazon.com', 'amazonaws.com', 'aws.amazon.com'],
  apple: ['apple.com', 'icloud.com'],
  paypal: ['paypal.com'],
  netflix: ['netflix.com'],
  facebook: ['facebook.com', 'fb.com', 'messenger.com'],
  instagram: ['instagram.com'],
  twitter: ['twitter.com', 'x.com'],
  linkedin: ['linkedin.com'],
  youtube: ['youtube.com'],
  ebay: ['ebay.com'],
  adobe: ['adobe.com'],
  dropbox: ['dropbox.com'],
  spotify: ['spotify.com'],
  stripe: ['stripe.com'],
  chase: ['chase.com'],
  wellsfargo: ['wellsfargo.com'],
  bankofamerica: ['bankofamerica.com'],
  openai: ['openai.com'],
  discord: ['discord.com'],
  zoom: ['zoom.us'],
  slack: ['slack.com'],
  shopify: ['shopify.com'],
  cloudflare: ['cloudflare.com'],
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
  '.download', '.stream',
]);

// ─────────────────────────────────────────────────────────────────────────────
// Detection function
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

  // ── Check each brand ──────────────────────────────────────────────────────
  for (const [brand] of Object.entries(BRAND_REGISTRY)) {
    // Does the brand name appear somewhere in the hostname?
    if (!hostname.includes(brand)) continue;

    // At this point we know:
    //   1. The domain is NOT trusted
    //   2. The brand name appears in the hostname
    //
    // Now we need condition 3: a phishing keyword OR a suspicious TLD
    // to avoid flagging coincidental brand-name substrings.

    const hasImpersonationKeyword = IMPERSONATION_KEYWORDS.some((kw) =>
      hostname.includes(kw),
    );

    if (hasImpersonationKeyword || hasSuspiciousTld) {
      return {
        brand,
        hostname,
      };
    }
  }

  return null;
}

/**
 * Returns all brand names that appear in the URL hostname.
 * Used for informational purposes in scan results.
 */
export function detectBrandsInHostname(hostname: string): string[] {
  const lower = hostname.toLowerCase();
  return Object.keys(BRAND_REGISTRY).filter((brand) => lower.includes(brand));
}
