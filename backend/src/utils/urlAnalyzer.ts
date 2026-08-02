/**
 * urlAnalyzer.ts
 * ──────────────
 * Pure, side-effect-free helper functions.
 * Each function inspects one aspect of a URL and returns a typed result.
 * They all accept a pre-parsed `URL` object so the expensive parse step
 * happens exactly once in the service layer.
 */

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/** Known URL-shortening domains */
const URL_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'adf.ly',
  'rb.gy',
  'shorte.st',
  'tiny.cc',
  'cutt.ly',
  'short.io',
  'rebrand.ly',
]);

/** Top-level domains frequently abused in phishing campaigns */
const SUSPICIOUS_TLDS = new Set([
  '.tk',
  '.ml',
  '.ga',
  '.cf',
  '.gq',    // Freenom free TLDs — massively abused
  '.xyz',
  '.top',
  '.club',
  '.work',
  '.click',
  '.link',
  '.live',
  '.online',
  '.site',
  '.icu',
  '.buzz',
  '.rest',
  '.fun',
]);

/** Keywords that commonly appear in phishing URLs */
const SUSPICIOUS_KEYWORDS = [
  'login',
  'signin',
  'sign-in',
  'verify',
  'verification',
  'secure',
  'account',
  'update',
  'confirm',
  'banking',
  'password',
  'credential',
  'wallet',
  'support',
  'helpdesk',
  'invoice',
  'payment',
  'paypal',
  'apple',
  'amazon',
  'google',
  'microsoft',
  'netflix',
  'ebay',
  'webscr',
  'cmd=',
  'free',
  'winner',
  'prize',
];

/** URLs longer than this character count are considered suspicious */
const LONG_URL_THRESHOLD = 75;

/** More than this many dot-separated labels in the hostname is suspicious */
const SUBDOMAIN_THRESHOLD = 3;

// ─────────────────────────────────────────────────────────────────────────────
// 1. URL validation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Validates that the string is a parseable URL with an http/https scheme.
 * Returns the parsed URL object on success, or null on failure.
 */
export function parseUrl(raw: string): URL | null {
  try {
    const parsed = new URL(raw.trim());
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    return parsed;
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. HTTPS detection
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns true if the URL uses the HTTPS protocol.
 * Plain HTTP is considered a risk signal.
 */
export function checkHttps(parsed: URL): boolean {
  return parsed.protocol === 'https:';
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. IP address instead of domain
// ─────────────────────────────────────────────────────────────────────────────

/** IPv4 pattern — e.g. 192.168.1.1 */
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

/** IPv6 in bracket notation — e.g. [::1] */
const IPV6_BRACKET_RE = /^\[.*]$/;

/**
 * Returns true if the hostname is a raw IP address.
 * Legitimate sites use domain names; IPs in URLs are a phishing red flag.
 */
export function checkIpAddress(parsed: URL): boolean {
  const host = parsed.hostname;
  return IPV4_RE.test(host) || IPV6_BRACKET_RE.test(host);
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. URL length analysis
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns true if the full URL string exceeds LONG_URL_THRESHOLD characters.
 * Phishing URLs often embed extra parameters to disguise the real destination.
 */
export function checkLongUrl(parsed: URL): boolean {
  return parsed.href.length > LONG_URL_THRESHOLD;
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Number of subdomains
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns true if the hostname has more than SUBDOMAIN_THRESHOLD labels.
 * Example: "secure.login.paypal.phish.com" has 5 labels — suspicious.
 * A normal domain like "www.example.com" has 3 labels — acceptable.
 */
export function checkManySubdomains(parsed: URL): boolean {
  const labels = parsed.hostname.split('.');
  return labels.length > SUBDOMAIN_THRESHOLD;
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. URL shortener detection
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns true if the domain (without www prefix) matches a known shortener.
 * Shorteners hide the real destination — a classic phishing technique.
 */
export function checkUrlShortener(parsed: URL): boolean {
  const domain = parsed.hostname.replace(/^www\./, '');
  return URL_SHORTENERS.has(domain);
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Suspicious keywords
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns the list of suspicious keywords found anywhere in the URL string.
 * Phishing pages impersonate trusted brands and action-words to lure users.
 */
export function checkSuspiciousKeywords(parsed: URL): string[] {
  const lower = parsed.href.toLowerCase();
  return SUSPICIOUS_KEYWORDS.filter((kw) => lower.includes(kw));
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Suspicious TLD
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns true if the URL's TLD is on the high-risk list.
 * Attackers register on free / cheap TLDs to keep costs low.
 */
export function checkSuspiciousTld(parsed: URL): boolean {
  const hostname = parsed.hostname;
  const dotIndex = hostname.lastIndexOf('.');
  if (dotIndex === -1) return false;
  const tld = hostname.slice(dotIndex); // includes the dot, e.g. ".tk"
  return SUSPICIOUS_TLDS.has(tld);
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Excessive hyphens
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Counts hyphens in the hostname.
 * Machine-generated phishing domains often look like:
 *   secure-paypal-login-verify.com
 */
export function countHyphens(parsed: URL): number {
  return (parsed.hostname.match(/-/g) ?? []).length;
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Encoded characters
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns true if the URL contains percent-encoded characters (%xx).
 * Encoding is sometimes used to obfuscate malicious paths or query params.
 */
export function checkEncodedChars(parsed: URL): boolean {
  return /%[0-9a-fA-F]{2}/.test(parsed.href);
}
