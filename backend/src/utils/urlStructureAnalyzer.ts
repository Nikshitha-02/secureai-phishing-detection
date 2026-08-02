/**
 * urlStructureAnalyzer.ts
 * ───────────────────────
 * Pure, side-effect-free functions that analyse the structural properties
 * of a URL to detect phishing signals.
 *
 * Each function accepts a pre-parsed `URL` object so the expensive parse step
 * happens exactly once in the service layer.
 *
 * None of these functions consider domain reputation or brand names — that
 * responsibility lives in brandImpersonation.ts.
 */

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Known URL-shortening services.
 * Shorteners hide the real destination and are a classic phishing technique.
 */
export const URL_SHORTENERS = new Set<string>([
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
  'bl.ink',
  'lnkd.in',
  'ift.tt',
  'dlvr.it',
  'soo.gd',
  'mcaf.ee',
  'url.ie',
  'u.to',
  'qr.ae',
  'v.gd',
  'clck.ru',
  'shorturl.at',
]);

/**
 * Top-level domains frequently abused in phishing campaigns.
 * These are cheap or free to register, making them popular with attackers.
 */
export const SUSPICIOUS_TLDS = new Set<string>([
  '.tk',   // Freenom — massively abused
  '.ml',   // Freenom
  '.ga',   // Freenom
  '.cf',   // Freenom
  '.gq',   // Freenom
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
  '.pw',
  '.cc',
  '.biz',
  '.info',
  '.ws',
  '.vip',
  '.win',
  '.download',
  '.stream',
  '.racing',
  '.review',
  '.accountant',
  '.loan',
  '.trade',
  '.date',
  '.gdn',
]);

/**
 * Phishing ACTION keywords — words that indicate urgency or a suspicious
 * action WITHOUT containing brand names.
 *
 * Brand names (google, paypal, amazon, …) are intentionally removed here.
 * They are handled separately in brandImpersonation.ts to avoid false positives
 * on legitimate brand domains.
 */
export const ACTION_KEYWORDS: string[] = [
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
  'webscr',
  'cmd=',
  'free',
  'winner',
  'prize',
  'reset',
  'suspended',
  'unusual',
  'limited',
  'locked',
  'alert',
  'unauthorized',
];

/** Full URL lengths above this threshold are considered suspicious */
export const LONG_URL_THRESHOLD = 75;

/** More labels in the hostname than this count is suspicious */
export const SUBDOMAIN_THRESHOLD = 3;

/** Hyphens in the hostname above this count incur a per-hyphen penalty */
export const HYPHEN_PENALTY_THRESHOLD = 1;

// ─────────────────────────────────────────────────────────────────────────────
// Parsing
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
// Individual structural checks
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns true if the URL uses HTTPS.
 * Plain HTTP is a meaningful risk signal — legitimate sites almost universally
 * use TLS today.
 */
export function checkHttps(parsed: URL): boolean {
  return parsed.protocol === 'https:';
}

// IPv4  e.g. 192.168.1.1
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
// IPv6 in bracket notation  e.g. [::1]
const IPV6_BRACKET_RE = /^\[.*]$/;

/**
 * Returns true if the hostname is a raw IP address.
 * Legitimate public-facing sites always use a registered domain name.
 * A raw IP strongly suggests an attacker trying to avoid domain registration.
 */
export function checkIpAddress(parsed: URL): boolean {
  const host = parsed.hostname;
  return IPV4_RE.test(host) || IPV6_BRACKET_RE.test(host);
}

/**
 * Returns true if the full URL string exceeds LONG_URL_THRESHOLD characters.
 * Phishing URLs often embed extra parameters to disguise the real destination.
 */
export function checkLongUrl(parsed: URL): boolean {
  return parsed.href.length > LONG_URL_THRESHOLD;
}

/**
 * Returns true if the hostname has more dot-separated labels than
 * SUBDOMAIN_THRESHOLD.
 *
 * "secure.login.paypal.phish.com" → 5 labels → suspicious
 * "www.example.com"               → 3 labels → normal
 */
export function checkManySubdomains(parsed: URL): boolean {
  const labels = parsed.hostname.split('.');
  return labels.length > SUBDOMAIN_THRESHOLD;
}

/**
 * Returns true if the domain (without www prefix) matches a known shortener.
 * URL shorteners hide the real destination — a classic phishing vector.
 */
export function checkUrlShortener(parsed: URL): boolean {
  const domain = parsed.hostname.replace(/^www\./, '');
  return URL_SHORTENERS.has(domain);
}

/**
 * Returns the list of phishing action-keywords found in the URL path + query.
 * Brand names are NOT searched here to avoid false positives on real brand domains.
 * Only matches against PATH and QUERY to avoid false positives on TLDs and hostnames.
 *
 * e.g. "https://evil.xyz/login?account=reset"  → ['login', 'account', 'reset']
 *      "https://google.com"                     → []
 */
export function checkSuspiciousKeywords(parsed: URL): string[] {
  // Only inspect path + query, not the hostname (brand check handles hostname)
  const searchTarget = (parsed.pathname + parsed.search).toLowerCase();
  return ACTION_KEYWORDS.filter((kw) => searchTarget.includes(kw));
}

/**
 * Returns true if the URL's TLD is on the high-risk list.
 * Attackers register on free / cheap TLDs to keep costs low.
 */
export function checkSuspiciousTld(parsed: URL): boolean {
  const hostname = parsed.hostname;
  const dotIndex = hostname.lastIndexOf('.');
  if (dotIndex === -1) return false;
  const tld = hostname.slice(dotIndex); // e.g. ".tk"
  return SUSPICIOUS_TLDS.has(tld);
}

/**
 * Counts hyphens in the hostname.
 * Phishing domains frequently look like: "secure-paypal-login-verify.com"
 */
export function countHyphens(parsed: URL): number {
  return (parsed.hostname.match(/-/g) ?? []).length;
}

/**
 * Returns true if the URL contains percent-encoded characters (%xx).
 * Encoding is sometimes used to obfuscate malicious paths or query params.
 */
export function checkEncodedChars(parsed: URL): boolean {
  // Check pathname and search for encoding — ignore the host
  const pathAndQuery = parsed.pathname + parsed.search;
  return /%[0-9a-fA-F]{2}/.test(pathAndQuery);
}
