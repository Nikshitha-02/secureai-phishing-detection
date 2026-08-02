/**
 * trustedDomains.ts
 * ─────────────────
 * Single source of truth for domains that are considered trusted.
 *
 * A domain is trusted when the scanned hostname EXACTLY matches an entry,
 * OR is a valid subdomain of it (e.g. mail.google.com is trusted via google.com).
 *
 * When a domain is trusted:
 *  - Brand-name keyword penalties are NOT applied.
 *  - The isTrustedDomain flag in PhishingChecks is set to true.
 *  - Brand impersonation detection is skipped.
 *
 * To extend: add the apex domain in lowercase to TRUSTED_DOMAINS below.
 */

/** Set of trusted apex domains (all lowercase, no trailing dot). */
export const TRUSTED_DOMAINS = new Set<string>([
  // Search & Productivity
  'google.com',
  'googleapis.com',
  'googlesyndication.com',
  'googletagmanager.com',

  // Developer platforms
  'github.com',
  'gitlab.com',
  'bitbucket.org',
  'stackoverflow.com',
  'npmjs.com',

  // Microsoft
  'microsoft.com',
  'live.com',
  'outlook.com',
  'office.com',
  'office365.com',
  'azure.com',
  'bing.com',
  'msn.com',
  'skype.com',
  'xbox.com',

  // Amazon / AWS
  'amazon.com',
  'aws.amazon.com',
  'amazonaws.com',

  // Apple
  'apple.com',
  'icloud.com',

  // Meta
  'facebook.com',
  'instagram.com',
  'whatsapp.com',
  'messenger.com',
  'fb.com',

  // Payment / Finance
  'paypal.com',
  'stripe.com',
  'square.com',
  'venmo.com',
  'chase.com',
  'wellsfargo.com',
  'bankofamerica.com',

  // Social / Media
  'x.com',
  'twitter.com',
  'linkedin.com',
  'youtube.com',
  'tiktok.com',
  'reddit.com',
  'pinterest.com',
  'snapchat.com',
  'discord.com',
  'twitch.tv',
  'spotify.com',

  // Streaming
  'netflix.com',
  'hulu.com',
  'disneyplus.com',

  // E-commerce
  'ebay.com',
  'etsy.com',
  'shopify.com',

  // Cloud / Infra
  'cloudflare.com',
  'fastly.com',
  'akamai.com',
  'digitalocean.com',
  'heroku.com',
  'netlify.com',
  'vercel.com',

  // Adobe / Creative
  'adobe.com',
  'behance.net',
  'figma.com',

  // Enterprise SaaS
  'oracle.com',
  'salesforce.com',
  'zoom.us',
  'slack.com',
  'atlassian.com',
  'jira.com',
  'confluence.com',
  'dropbox.com',
  'box.com',
  'notion.so',

  // AI / Tech
  'openai.com',
  'anthropic.com',
  'huggingface.co',

  // Comms
  'gmail.com',
  'yahoo.com',
  'proton.me',
  'protonmail.com',
  'icloud.com',
]);

/**
 * Returns true if the given hostname is trusted — either as an exact match
 * or as a valid subdomain of a trusted apex domain.
 *
 * Examples:
 *   isTrusted('google.com')       → true
 *   isTrusted('mail.google.com')  → true
 *   isTrusted('google-login.xyz') → false
 *   isTrusted('fakegoogle.com')   → false
 *
 * @param hostname  The raw hostname from URL.hostname (no port, all lowercase).
 */
export function isTrustedDomain(hostname: string): boolean {
  const lower = hostname.toLowerCase();

  // 1. Exact match
  if (TRUSTED_DOMAINS.has(lower)) return true;

  // 2. Subdomain match — walk up the labels until we find a trusted apex.
  //    e.g. "docs.google.com" → check "google.com" → trusted ✓
  const labels = lower.split('.');
  for (let i = 1; i < labels.length - 1; i++) {
    const candidate = labels.slice(i).join('.');
    if (TRUSTED_DOMAINS.has(candidate)) return true;
  }

  return false;
}
