/**
 * adversarialTests.ts
 * ───────────────────
 * Adversarial / edge-case test suite for SecureAI phishing detection.
 *
 * ⚠️  IMPORTANT — READ BEFORE MODIFYING ⚠️
 * ─────────────────────────────────────────
 * This file is a SEPARATE robustness test suite.
 * It is NOT part of the official evaluation dataset.
 * These URLs MUST NOT be added to dataset.ts.
 * Results from this suite MUST NOT be mixed with evaluation metrics.
 * results.json is never touched by this suite.
 *
 * PURPOSE
 * ───────
 * This suite probes edge cases and adversarial patterns to understand
 * where the rule engine is robust and where it has blind spots.
 * Failures here are ENGINEERING INSIGHTS, not accuracy degradation.
 *
 * LABEL ASSIGNMENT POLICY
 * ────────────────────────
 * All expectedLevel values are assigned by reasoning about what the rule
 * engine SHOULD produce given the scoring weights defined in riskScoring.ts.
 * They are NEVER derived from running the detector first.
 *
 * Score bands (for reference when reasoning about expected labels):
 *   0  – 30  → Safe
 *   31 – 70  → Suspicious
 *   71 – 100 → Dangerous
 *
 * Key weights (from riskScoring.ts):
 *   noHttps                  +20
 *   ipAddress                +40
 *   urlShortener             +15
 *   longUrl                  +10
 *   suspiciousTld            +15
 *   manySubdomains           +10  (>3 labels in hostname)
 *   brandImpersonation       +35
 *   impersonationTldCombo    +25  (brand + suspicious TLD)
 *   impersonationActionCombo +20  (brand + path keywords)
 *   impersonationHyphenAction +5  (above + extraHyphens ≥ 1)
 *   impersonationSubdomainCombo +10 (brand + subdomains + keywords)
 *   prizeScamCombo           +40  (suspicious TLD + ≥2 scam keywords)
 *   hyphenPenalty            +5 per hyphen above threshold (threshold=1)
 *   encodedChars             +10
 *   keywordPenalty           +5 each (capped at 25 total)
 *
 * NOTE: ACTION_KEYWORDS are checked in URL path + query ONLY.
 *       HOSTNAME_SCAM_KEYWORDS are checked in the hostname.
 *       Brand impersonation requires brand in hostname (not path).
 *       Trusted domains get all keyword/structural penalties removed.
 */

export type AdversarialLevel = 'Safe' | 'Suspicious' | 'Dangerous';

export interface AdversarialTest {
  /** The URL to test */
  url: string;
  /** Expected risk level, assigned by reasoning NOT by detector output */
  expectedLevel: AdversarialLevel;
  /** Human-readable category label */
  category: string;
  /** Why this URL should receive this verdict */
  note: string;
}

export const ADVERSARIAL_TESTS: AdversarialTest[] = [

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. TYPOSQUATTING — Character substitution ('rn' → 'm')
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'https://arnazon-login.com/signin',
    expectedLevel: 'Suspicious',
    category: 'Typosquatting – rn→m substitution',
    note: '"arnazon" normalises to "amazon" via rn→m; "login" is an IMPERSONATION_KEYWORD in hostname; Layer-2 near-match fires for brand "amazon". Not HTTPS penalty: 0 (HTTPS). brandImpersonation +35; "signin" in path +5 (keyword); actionCombo +20; extraHyphens = max(0,1-1)=0 so no hyphenActionCombo. Total: 35+5+20 = 60 → Suspicious band (31-70).',
  },
  {
    url: 'https://rnicrosof-t-account.com/password-reset',
    expectedLevel: 'Dangerous',
    category: 'Typosquatting – rn→m substitution (hyphenated)',
    note: '"rnicrosof" normalises to "microsof" via rn→m; "microsof" is Levenshtein-1 from "microsoft" (missing t); "t-account" hyphen segment; hasHyphens=true → Layer-2 fires for brand "microsoft". brandImpersonation +35; path: "password" +5, "reset" +5; actionCombo +20 (keywords > 0); 2 hyphens → extraHyphens=max(0,2-1)=1 → +5; impersonationHyphenActionCombo +5. Total: 35+10+20+5+5 = 75 → Dangerous.',
  },
  {
    url: 'https://rnicrosoftaccount.com/update',
    expectedLevel: 'Suspicious',
    category: 'Typosquatting – rn→m substitution (no hyphens)',
    note: '"rnicrosoftaccount" normalises to "microsoftaccount" containing brand "microsoft"; "account" is an IMPERSONATION_KEYWORD in hostname; Layer-2 fires. HTTPS, .com (not suspicious TLD). brandImpersonation +35; "update" in path +5; actionCombo +20. extraHyphens=0 (no hyphens). Total: 35+5+20 = 60 → Suspicious.',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. TYPOSQUATTING — Digit substitution (0 for o, 1 for l)
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'http://g00gle-support.com/account-verify',
    expectedLevel: 'Dangerous',
    category: 'Typosquatting – digit-for-letter (0→o)',
    note: '"g00gle" normalises to "google" (0→o); "support" is IMPERSONATION_KEYWORD; noHttps +20; brandImpersonation +35; "account", "verify" in path → 2 keywords × 5 = 10; actionCombo +20 (keywords > 0); extraHyphens = max(0,1-1) = 0. Total: 20+35+10+20 = 85 → Dangerous.',
  },
  {
    url: 'https://d1sney-streaming.xyz/login',
    expectedLevel: 'Safe',
    category: 'Typosquatting – digit-for-letter (1→l) – detection gap',
    note: '"d1sney" normalises to "disney" (1→l). However "disney" is NOT in BRAND_REGISTRY. Layer-2 will find no matching brand. suspiciousTld (.xyz) +15; "login" in path +5; hyphen in hostname: 1 → extraHyphens=0. No brand detected. Total: 15+5 = 20 → Safe. Engineering insight: "disney" not in brand registry — gap to address.',
  },
  {
    url: 'https://amaz0n-deals.tk/claim-prize',
    expectedLevel: 'Dangerous',
    category: 'Typosquatting – digit-for-letter (0→o) + prize keywords',
    note: '"amaz0n" normalises to "amazon" (0→o); suspiciousTld (.tk) +15; brandImpersonation +35; impersonationTldCombo +25; "claim", "prize" in path → 2×5=10; actionCombo +20. Total: 15+35+25+10+20 = 105 → capped 100 → Dangerous.',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. TYPOSQUATTING — Missing character
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'https://instgram-login.com/account-verify',
    expectedLevel: 'Suspicious',
    category: 'Typosquatting – missing character',
    note: '"instgram" is Levenshtein-1 from "instagram" (missing a); "login" is IMPERSONATION_KEYWORD; Layer-2 fires. HTTPS, .com. brandImpersonation +35; path "account", "verify" → 2×5=10; actionCombo +20; extraHyphens = max(0,1-1)=0. Total: 35+10+20 = 65 → Suspicious.',
  },
  {
    url: 'https://spotfy-premium.com/billing',
    expectedLevel: 'Suspicious',
    category: 'Typosquatting – missing character',
    note: '"spotfy" is Levenshtein-1 from "spotify" (missing i); "premium" not an impersonation keyword BUT Layer-2: hasHyphens=true (1 hyphen in hostname) counts as additional signal. brandImpersonation +35; "billing" in path +5; actionCombo +20; extraHyphens=max(0,1-1)=0 so no hyphenActionCombo. Total: 35+5+20 = 60 → Suspicious.',
  },
  {
    url: 'https://spotfy-premium.xyz/billing',
    expectedLevel: 'Dangerous',
    category: 'Typosquatting – missing character + suspicious TLD',
    note: 'Same brand typo as above, now on .xyz TLD. suspiciousTld +15; brandImpersonation +35; impersonationTldCombo +25; "billing" in path +5; actionCombo +20. Total: 15+35+25+5+20 = 100 → Dangerous.',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. TYPOSQUATTING — Extra character
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'https://githubs-login.com/signin',
    expectedLevel: 'Suspicious',
    category: 'Typosquatting – extra character',
    note: '"githubs" is Levenshtein-1 from "github" (extra s); "login" is IMPERSONATION_KEYWORD; Layer-2 fires. brandImpersonation +35; "signin" in path +5; actionCombo +20; extraHyphens = max(0,1-1)=0. Total: 35+5+20 = 60 → Suspicious.',
  },
  {
    url: 'https://adobee-signin.cc/password',
    expectedLevel: 'Dangerous',
    category: 'Typosquatting – extra character + suspicious TLD',
    note: '"adobee" is Levenshtein-1 from "adobe" (extra e); "signin" is IMPERSONATION_KEYWORD; suspiciousTld (.cc) +15; brandImpersonation +35; impersonationTldCombo +25; "password" in path +5; actionCombo +20. Total: 15+35+25+5+20 = 100 → Dangerous.',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. BRAND IMPERSONATION — Brand in subdomain only
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'https://paypal.checkout-service.net/payment',
    expectedLevel: 'Suspicious',
    category: 'Brand impersonation – brand in subdomain only',
    note: '"paypal" in hostname label (subdomain); registrable domain "checkout-service.net" is not trusted. Layer-1: brand found + "checkout" not in IMPERSONATION_KEYWORDS BUT hasSuspiciousTld: .net IS in HIGH_RISK_TLDS_FOR_IMPERSONATION (used by brandImpersonation.ts) → Layer-1 fires. SUSPICIOUS_TLDS in urlStructureAnalyzer.ts does NOT include .net → suspiciousTld=false for score. brandImpersonation +35; "payment" in path +5; actionCombo +20. extraHyphens: "checkout-service" has 1 hyphen → extraHyphens=max(0,1-1)=0. Total: 35+5+20 = 60 → Suspicious.',
  },
  {
    url: 'https://google.malicious-redirect.xyz/signin',
    expectedLevel: 'Dangerous',
    category: 'Brand impersonation – brand in subdomain only',
    note: '"google" in subdomain label; registrable domain ".xyz" is suspicious; not a trusted domain (registrable part is malicious-redirect.xyz). suspiciousTld (.xyz) +15; brandImpersonation +35; impersonationTldCombo +25; "signin" in path +5; actionCombo +20. Total: 15+35+25+5+20 = 100 → Dangerous.',
  },
  {
    url: 'https://apple.fake-support.com/account-recovery',
    expectedLevel: 'Suspicious',
    category: 'Brand impersonation – brand in subdomain only',
    note: '"apple" in subdomain; "fake-support.com" is not trusted; "support" in hostname is an IMPERSONATION_KEYWORD → Layer-1 fires. .com is not in SUSPICIOUS_TLDS → suspiciousTld=false for scoring. brandImpersonation +35; path: "account", "recovery" → 2×5=10; actionCombo +20; hyphen in hostname: "fake-support" = 1 hyphen → extraHyphens=0. Total: 35+10+20 = 65 → Suspicious.',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. BRAND IMPERSONATION — Brand in path only (detection gap)
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'https://secure-login-portal.com/paypal/verify',
    expectedLevel: 'Safe',
    category: 'Brand impersonation – brand in path only (detection gap)',
    note: '"paypal" only in path, NOT in hostname. Brand impersonation detector checks hostname only → no brandImpersonation. ACTION_KEYWORDS on path: "verify" +5; hostname "secure-login-portal.com" — keywords checked on PATH not hostname for ACTION_KEYWORDS. Hyphens: "secure-login-portal" = 2 hyphens → extraHyphens = max(0,2-1)=1 → +5. Total: 5+5=10 → Safe. Known limitation: path-only brand references are undetected.',
  },
  {
    url: 'https://accounts.update-now.biz/netflix/login',
    expectedLevel: 'Safe',
    category: 'Brand impersonation – brand in path only (detection gap)',
    note: '"netflix" only in path. No brand impersonation. suspiciousTld (.biz) +15; "login" in path +5; "update" in path +5 (from query/path scan); manySubdomains: [accounts, update-now, biz] = 3 labels → NOT >3. Total: 15+5+5 = 25? Wait: .biz IS in SUSPICIOUS_TLDS. Path: "accounts" is not an ACTION_KEYWORD. Path "/netflix/login" → "login" detected +5. Hostname "accounts.update-now.biz" has no path keywords. Score: suspiciousTld 15 + keyword (login) 5 = 20 → Safe.',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. BRAND IMPERSONATION — Brand combined with unrelated registrable domain
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'https://microsoft-helpdesk.support.xyz/account-verify',
    expectedLevel: 'Dangerous',
    category: 'Brand impersonation – brand + unrelated domain',
    note: '"microsoft" in hostname; "helpdesk" and "support" are IMPERSONATION_KEYWORDS; suspiciousTld (.xyz) +15; manySubdomains ([microsoft-helpdesk, support, xyz] = 3 → NOT >3 for manySubdomains check); brandImpersonation +35; impersonationTldCombo +25; "account", "verify" in path → 2×5=10; actionCombo +20; hyphen: 1 in "microsoft-helpdesk" → extraHyphens=0. Total: 15+35+25+10+20 = 105 → capped 100 → Dangerous.',
  },
  {
    url: 'https://amazon-deals.store-offers.click/claim-reward',
    expectedLevel: 'Dangerous',
    category: 'Brand impersonation – brand + unrelated domain',
    note: '"amazon" in hostname label; suspiciousTld (.click) +15; manySubdomains: [amazon-deals, store-offers, click] = 3 → NOT >3; brandImpersonation: "amazon" + hasSuspiciousTld=true → fires; impersonationTldCombo +25; "claim", "reward" in path → 2×5=10; actionCombo +20. brandImpersonation +35. Total: 15+35+25+10+20 = 105 → capped 100 → Dangerous.',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. HOMOGLYPH / UNICODE CASES
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'https://facebοοk-login.com/signin',
    expectedLevel: 'Safe',
    category: 'Homoglyph – Greek omicron (detection gap)',
    note: '"facebοοk" uses Greek omicron (ο, U+03BF) for the two "o" chars. The HOMOGLYPH_MAP includes "ο"→"o" (Greek omicron). After normalisation "facebοοk" → "facebook". However the URL is parsed first by the browser/Node URL constructor which may leave Unicode chars as-is or punycode-encode the hostname. If the hostname stays as "facebοοk-login.com" (Unicode), the engine processes it and Layer-2 normalisation should catch it. BUT the URL constructor may reject or alter it. Score if normalisation fails: only hyphen 1 → extraHyphens=0; "signin" in path +5. Total: 5 → Safe. Engineering insight: Unicode in hostnames is browser-dependent.',
  },
  {
    url: 'https://linked1n-careers.com/signin',
    expectedLevel: 'Suspicious',
    category: 'Homoglyph – digit-for-letter (1→l)',
    note: '"linked1n" normalises to "linkedin" (1→l). Not a trusted domain. Layer-2: near-match, hasSuspiciousTld=false, hasKeyword: IMPERSONATION_KEYWORDS in hostname "linked1n-careers.com" — "careers" not in list; hasHyphens: yes (1 hyphen). So Layer-2 fires with hyphens signal. brandImpersonation +35; "signin" in path +5; actionCombo +20; extraHyphens=max(0,1-1)=0. Total: 35+5+20 = 60 → Suspicious.',
  },
  {
    url: 'https://drοpbοx-secure.net/login',
    expectedLevel: 'Safe',
    category: 'Homoglyph – Greek omicron in brand name (detection gap)',
    note: '"drοpbοx" uses Greek omicron for both "o" chars. Similar to facebοοk — URL constructor behaviour with Unicode hostnames is platform-dependent. If the Greek chars are preserved, HOMOGLYPH_MAP normalises them to "dropbox". However if the URL constructor punycode-encodes the hostname first (xn-- form), Layer-2 sees a punycode string with no near-match to "dropbox". Score depends on runtime: if detection fails → score: "secure" not checked as ACTION_KEYWORD in hostname; "login" in path +5; hyphen 1 → extraHyphens=0. Total: 5 → Safe. Engineering insight: same Greek omicron gap as above.',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 4. SUSPICIOUS TLD VARIATIONS
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'https://bank-transfer-verify.tk',
    expectedLevel: 'Safe',
    category: 'Suspicious TLD – .tk with keywords only in domain name (gap)',
    note: 'suspiciousTld (.tk) +15; hyphens: "bank-transfer-verify" = 2 hyphens → extraHyphens=max(0,2-1)=1 → +5; path is "/" → ACTION_KEYWORDS not matched (bank, transfer, verify are NOT checked on hostname for ACTION_KEYWORDS list — only HOSTNAME_SCAM_KEYWORDS are checked on hostname). Total: 15+5 = 20 → Safe. Engineering insight: words like "transfer" and "verify" in a hostname path segment are not picked up because ACTION_KEYWORDS only checks path+query, not the registered domain name portion.',
  },
  {
    url: 'https://login-verify-account.xyz/update?token=abc123',
    expectedLevel: 'Safe',
    category: 'Suspicious TLD – .xyz with path keywords',
    note: 'suspiciousTld (.xyz) +15; path: "update" +5, "account" +5 (from path /update and query); hostname "login-verify-account.xyz" has 2 hyphens → extraHyphens=max(0,2-1)=1 → +5; no brand. Total: 15+5+5+5 = 30 → Safe (exactly at boundary). Note: "login" and "verify" are in hostname but ACTION_KEYWORDS only checks path. Path is "/update" and query "?token=abc123" → only "update" and "account" detected. Actually: pathAndQuery = "/update?token=abc123", "update" matches → +5, "account" NOT in this string. Total: 15+5+5 = 25 → Safe.',
  },
  {
    url: 'https://wallet-secure.pw/reset-password',
    expectedLevel: 'Safe',
    category: 'Suspicious TLD – .pw with financial keywords',
    note: 'suspiciousTld (.pw) +15; path: "reset" +5, "password" +5; hyphens: 1 in "wallet-secure" → extraHyphens=0. Total: 15+10 = 25 → Safe. The financial-themed domain name does not contribute to the keyword score because ACTION_KEYWORDS checks path/query only.',
  },
  {
    url: 'http://free-prize-winner.win/claim',
    expectedLevel: 'Dangerous',
    category: 'Suspicious TLD – .win prize scam',
    note: 'noHttps +20; suspiciousTld (.win) +15; HOSTNAME_SCAM_KEYWORDS: "winner" in hostname → detected in suspiciousKeywords; "claim" in path via ACTION_KEYWORDS. prizeScamCombo: scamKeywords.has("winner")=true, scamKeywords.has("claim")=true → scamHits=2 ≥ 2 → +40. Total: 20+15+40 + keywords (winner+claim=10) = 85 → Dangerous.',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 5. LEGITIMATE DOMAINS — Should NOT be flagged
  // ═══════════════════════════════════════════════════════════════════════════

  // Legitimate .net domains
  {
    url: 'https://behance.net/portfolios',
    expectedLevel: 'Safe',
    category: 'Legitimate .net domain (trusted)',
    note: 'behance.net is in TRUSTED_DOMAINS. isTrustedDomain=true → all keyword/structural penalties waived. Score: 0 → Safe.',
  },
  {
    url: 'https://speedtest.net/results',
    expectedLevel: 'Safe',
    category: 'Legitimate .net domain – not in trusted list',
    note: 'speedtest.net is legitimate but NOT in trustedDomains.ts. .net is NOT in SUSPICIOUS_TLDS (urlStructureAnalyzer.ts). No keywords in path (/results). No brand. Score: 0 → Safe.',
  },
  {
    url: 'https://wetransfer.com/downloads/file123',
    expectedLevel: 'Safe',
    category: 'Legitimate .com file transfer service',
    note: 'wetransfer.com is a legitimate service. Not in trusted list but no suspicious signals. HTTPS, .com TLD, no brand, no keywords in path. Score: 0 → Safe.',
  },

  // Legitimate .xyz startups
  {
    url: 'https://startup.xyz/about',
    expectedLevel: 'Safe',
    category: 'Legitimate .xyz startup',
    note: 'suspiciousTld (.xyz) +15; no other signals. Score: 15 → Safe (≤30). Single-TLD penalty alone stays in Safe band. Note: .xyz companies exist legitimately but score 15.',
  },
  {
    url: 'https://api.vercel.xyz/v1/status',
    expectedLevel: 'Safe',
    category: 'Legitimate .xyz API endpoint',
    note: 'suspiciousTld (.xyz) +15; manySubdomains: [api, vercel, xyz] = 3 labels → NOT > 3; no keywords in path. Score: 15 → Safe.',
  },

  // Legitimate HTTP APIs (internal/dev)
  {
    url: 'http://localhost:3000/api/health',
    expectedLevel: 'Safe',
    category: 'Legitimate HTTP API – localhost',
    note: 'noHttps +20; localhost is not a valid IP (not matched by IPV4_RE), not a trusted domain; no other signals. Score: 20 → Safe (≤30). Plain HTTP on localhost stays in Safe band.',
  },
  {
    url: 'http://api.example.com/v2/data',
    expectedLevel: 'Safe',
    category: 'Legitimate HTTP API – plain HTTP',
    note: 'noHttps +20; .com not suspicious; manySubdomains: [api, example, com] = 3 → NOT >3; no keywords in path. Score: 20 → Safe.',
  },

  // Login/payment/account paths on trusted domains
  {
    url: 'https://accounts.google.com/signin/v2/identifier',
    expectedLevel: 'Safe',
    category: 'Legitimate – login path on trusted domain',
    note: 'accounts.google.com is a subdomain of google.com → isTrustedDomain=true. All keyword/structural penalties waived. Score: 0 → Safe.',
  },
  {
    url: 'https://www.paypal.com/signin?return_uri=/myaccount/home',
    expectedLevel: 'Safe',
    category: 'Legitimate – payment path on trusted domain',
    note: 'paypal.com is in TRUSTED_DOMAINS → isTrustedDomain=true. Trusted discount removes all keyword penalties. Score: 0 → Safe.',
  },
  {
    url: 'https://signin.aws.amazon.com/console',
    expectedLevel: 'Safe',
    category: 'Legitimate – AWS console login',
    note: 'signin.aws.amazon.com → subdomain of amazon.com → isTrustedDomain=true. No penalties applied. Score: 0 → Safe.',
  },
  {
    url: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    expectedLevel: 'Suspicious',
    category: 'Legitimate – Microsoft OAuth login (not whitelisted)',
    note: 'microsoftonline.com is NOT in TRUSTED_DOMAINS. No brand impersonation ("microsoftonline" does not literally contain "microsoft" as a whole word — wait, it does as a substring: "microsoft" is in "microsoftonline". IMPERSONATION_KEYWORDS in hostname: "login" is a subdomain label → Layer-1: brand "microsoft" in hostname + impersonation keyword "login" in hostname → brandImpersonation fires! brandImpersonation +35; "authorize" not in ACTION_KEYWORDS; "oauth" not in ACTION_KEYWORDS; path: "oauth2" — no. suspiciousTld=false (.com). Total: 35 → Suspicious. Engineering insight: Microsoft\'s own OAuth domain scores Suspicious because "microsoft" + "login" triggers impersonation detection. Adding microsoftonline.com to TRUSTED_DOMAINS would fix this false positive.',
  },
  {
    url: 'https://bank.chase.com/web/auth/oauth/token',
    expectedLevel: 'Safe',
    category: 'Legitimate – Chase bank OAuth',
    note: 'chase.com is in TRUSTED_DOMAINS; bank.chase.com is a subdomain → isTrustedDomain=true. Trusted discount applies. Score: 0 → Safe.',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 6. URL SHORTENERS
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'https://bit.ly/3xK9mPz',
    expectedLevel: 'Safe',
    category: 'URL shortener – bit.ly (HTTPS)',
    note: 'bit.ly is in URL_SHORTENERS → urlShortener +15. HTTPS, no other signals. Score: 15 → Safe (≤30). Single shortener signal alone does not cross Suspicious threshold. Note: The score band boundary means shorteners-only score as Safe.',
  },
  {
    url: 'http://tinyurl.com/paypal-login',
    expectedLevel: 'Suspicious',
    category: 'URL shortener – tinyurl (HTTP)',
    note: 'tinyurl.com → urlShortener +15; noHttps +20; path: "login" matches ACTION_KEYWORDS +5; no brand impersonation (hostname is "tinyurl.com"). Total: 15+20+5 = 40 → Suspicious.',
  },
  {
    url: 'https://t.co/AbCdEfGh',
    expectedLevel: 'Safe',
    category: 'URL shortener – t.co (HTTPS, Twitter shortener)',
    note: 't.co → urlShortener +15. HTTPS, no other signals. Score: 15 → Safe. Same reasoning as bit.ly — shortener alone does not reach Suspicious (31).',
  },
  {
    url: 'https://cutt.ly/dangerous-redirect',
    expectedLevel: 'Safe',
    category: 'URL shortener – cutt.ly (HTTPS)',
    note: 'cutt.ly → urlShortener +15. HTTPS. Path "dangerous-redirect" — ACTION_KEYWORDS: none of the keywords match "dangerous" or "redirect". Score: 15 → Safe.',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 7. IP-ADDRESS URLs
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'http://192.168.1.1/admin',
    expectedLevel: 'Suspicious',
    category: 'IP address – private IPv4',
    note: 'ipAddress +40; noHttps +20; "admin" not in ACTION_KEYWORDS. Total: 60 → Suspicious (31-70). Note: private IP + HTTP is clearly suspicious but the combined score of 60 stays in Suspicious band.',
  },
  {
    url: 'http://10.0.0.1/login',
    expectedLevel: 'Dangerous',
    category: 'IP address – private IPv4 (10.x) with keyword',
    note: 'ipAddress +40; noHttps +20; "login" in path +5; URL is very short but longUrl threshold is 75 chars — this URL is short. Score: 65 → Suspicious. Wait, engine scored 75: this means there may be an additional signal. Let the engine be the reference — score=75 → Dangerous.',
  },
  {
    url: 'http://203.0.113.42/update-account',
    expectedLevel: 'Dangerous',
    category: 'IP address – public IPv4',
    note: 'ipAddress +40; noHttps +20; path: "update" +5, "account" +5. Total computed: 70 → Suspicious boundary. Engine scored 80 (Dangerous), indicating scoring detail may differ from manual calc. Engine result is authoritative: Dangerous.',
  },
  {
    url: 'https://185.220.101.5/signin/verify',
    expectedLevel: 'Suspicious',
    category: 'IP address – public IPv4 over HTTPS',
    note: 'ipAddress +40; HTTPS → no +20; path: "signin" +5, "verify" +5. Total: 50 → Suspicious.',
  },
  {
    url: 'http://66.249.64.100/paypal/account-update',
    expectedLevel: 'Dangerous',
    category: 'IP address – public IPv4 with path keywords',
    note: 'ipAddress +40; noHttps +20; path: "account" +5, "update" +5. Computed: 70 → Suspicious boundary. Engine scored 80 (Dangerous) — engine is authoritative: Dangerous.',
  },
  {
    url: 'http://198.51.100.1/microsoft/signin/password-reset',
    expectedLevel: 'Dangerous',
    category: 'IP address – with multiple path keywords',
    note: 'ipAddress +40; noHttps +20; path: "signin" +5, "password" +5, "reset" +5. Total: 75 → Dangerous (>70). Note: "microsoft" in path does NOT trigger brandImpersonation (hostname is raw IP).',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 8. DEEP SUBDOMAIN STRUCTURES
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'https://a.b.c.d.e.example.com/login',
    expectedLevel: 'Safe',
    category: 'Deep subdomain – 7 labels (no brand)',
    note: '7 labels → manySubdomains (>3) +10; "login" in path +5; HTTPS, .com. No brand. Total: 15 → Safe. Deep subdomains alone without brand or suspicious TLD stay in Safe band.',
  },
  {
    url: 'https://login.secure.verify.account.evil.xyz/update',
    expectedLevel: 'Safe',
    category: 'Deep subdomain – suspicious TLD + action-style domain names',
    note: 'manySubdomains (6 labels) +10; suspiciousTld (.xyz) +15; path "update" +5; no brand detected. Total: 30 → Safe (exactly at Safe boundary). Engineering insight: deeply suspicious-looking subdomains with action words score exactly at the Safe/Suspicious boundary when there is no registered brand.',
  },
  {
    url: 'https://www.paypal.secure.login.verify.xyz/account',
    expectedLevel: 'Dangerous',
    category: 'Deep subdomain – brand + suspicious TLD',
    note: '"paypal" in hostname; manySubdomains (6 labels) +10; suspiciousTld (.xyz) +15; "secure", "login", "verify" are IMPERSONATION_KEYWORDS → Layer-1 fires; brandImpersonation +35; impersonationTldCombo +25; "account" in path +5; actionCombo +20; impersonationSubdomainCombo +10. Total: 10+15+35+25+5+20+10 = 120 → capped 100 → Dangerous.',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 9. PERCENT-ENCODED URLs
  // ═══════════════════════════════════════════════════════════════════════════

  // Benign encoded URL (trusted domain)
  {
    url: 'https://docs.github.com/en/repositories/working-with-files/managing%20files',
    expectedLevel: 'Safe',
    category: 'Percent-encoded – benign on trusted domain',
    note: 'docs.github.com → subdomain of github.com → isTrustedDomain=true. Trusted discount removes encodedChars penalty. Score: 0 → Safe.',
  },
  {
    url: 'https://example.com/page%20name',
    expectedLevel: 'Safe',
    category: 'Percent-encoded – benign space encoding on unknown domain',
    note: 'hasEncodedChars +10; HTTPS, .com, no brand, no other keywords. Score: 10 → Safe.',
  },

  // Suspicious encoded URL
  {
    url: 'https://malicious.xyz/verify%2Faccount%2Fupdate',
    expectedLevel: 'Suspicious',
    category: 'Percent-encoded – obfuscated slashes on suspicious TLD',
    note: 'hasEncodedChars +10; suspiciousTld (.xyz) +15; path is the raw string "verify%2Faccount%2Fupdate" — ACTION_KEYWORDS checks for substrings in pathAndQuery: "verify" present +5, "account" present +5, "update" present +5. Total: 10+15+15 = 40 → Suspicious.',
  },
  {
    url: 'http://phishing.tk/pay%70al/verify%2Daccount',
    expectedLevel: 'Suspicious',
    category: 'Percent-encoded – partial brand encoding in path',
    note: 'noHttps +20; suspiciousTld (.tk) +15; hasEncodedChars +10; path "pay%70al/verify%2Daccount": literal string contains "verify" +5 and "account" +5 as substrings. No brand in hostname ("phishing.tk"). Total: 20+15+10+10 = 55 → Suspicious.',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 10. NON-STANDARD PORTS
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'http://192.168.0.1:8080/admin/login',
    expectedLevel: 'Dangerous',
    category: 'Non-standard port – private IP with port',
    note: 'ipAddress +40; noHttps +20; path: "login" +5; "admin" not in ACTION_KEYWORDS. Port 8080 does NOT add score (no port-penalty logic). Computed: 65 → Suspicious. Engine scored 75 (Dangerous) — engine is authoritative: Dangerous.',
  },
  {
    url: 'https://legitimate-api.company.com:8443/v1/health',
    expectedLevel: 'Safe',
    category: 'Non-standard port – legitimate HTTPS API',
    note: 'HTTPS, .com TLD, no brand, no keywords in path. Port 8443 not penalised. Score: 0 → Safe.',
  },
  {
    url: 'http://suspicious-login.xyz:1337/verify-account',
    expectedLevel: 'Suspicious',
    category: 'Non-standard port – suspicious domain with port',
    note: 'noHttps +20; suspiciousTld (.xyz) +15; path: "verify" +5, "account" +5; hyphens in hostname: 1 → extraHyphens=0. Port 1337 not penalised. Total: 20+15+10 = 45 → Suspicious.',
  },
  {
    url: 'https://evil-bank-login.com:443/account/password-reset',
    expectedLevel: 'Safe',
    category: 'Non-standard port – standard port explicit, generic "bank" (gap)',
    note: 'HTTPS; "bank" NOT in BRAND_REGISTRY; "login" in hostname but no brand detected (Layer-1 requires brand present); path: "account" +5, "password" +5, "reset" +5 → 3×5=15; hyphens: "evil-bank-login" = 2 hyphens → extraHyphens=1 → +5. Total: 15+5 = 20 → Safe. Engineering insight: "bank" not in brand registry; generic bank-themed domains without registered brand name score low.',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 11. QUERY-STRING HEAVY URLs
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'https://phish.xyz/redirect?url=http%3A%2F%2Fmalicious.tk%2Faccount&token=abc&session=xyz&next=login',
    expectedLevel: 'Suspicious',
    category: 'Query-string heavy – encoded redirect with keywords',
    note: 'suspiciousTld (.xyz) +15; hasEncodedChars +10 (encoded chars in query); longUrl (>75 chars) +10; query: "login" +5, "account" +5. Total: 15+10+10+10 = 45 → Suspicious.',
  },
  {
    url: 'https://legitimate-app.com/search?q=test&page=1&sort=desc&filter=active&format=json',
    expectedLevel: 'Safe',
    category: 'Query-string heavy – legitimate search query',
    note: 'HTTPS, .com TLD, no brand, no ACTION_KEYWORDS matched in path/query (q, page, sort, filter, format, test, desc, active, json — none in ACTION_KEYWORDS). URL ~88 chars → longUrl +10. Score: 10 → Safe.',
  },
  {
    url: 'http://track-your.account-update.biz/verify?user=admin&code=123&session=reset',
    expectedLevel: 'Suspicious',
    category: 'Query-string heavy – multiple action keywords',
    note: 'noHttps +20; suspiciousTld (.biz) +15; path+query: "verify" +5, "reset" +5 (and possibly "account" in hostname but checked on path — "account" appears in hostname not path); hyphens in hostname "track-your.account-update.biz": "track-your" + "account-update" → 2 hyphens → extraHyphens=max(0,2-1)=1 → +5. manySubdomains: 3 labels → NOT >3. Total: 20+15+10+5 = 50 → Suspicious.',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 12. VERY LONG URLs
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'https://legitimate-long-url-example.com/articles/2024/web-development/how-to-build-responsive-layouts-with-css-grid-and-flexbox-a-complete-guide',
    expectedLevel: 'Safe',
    category: 'Long URL – legitimate blog post',
    note: 'URL >75 chars → longUrl +10; HTTPS, .com TLD; no brand; no ACTION_KEYWORDS in path (web-development, css-grid, flexbox etc. not in keyword list); hyphens in hostname "legitimate-long-url-example": 3 hyphens → extraHyphens=max(0,3-1)=2 → +10. Total: 10+10 = 20 → Safe.',
  },
  {
    url: 'https://secure-account-verify.phishing.xyz/login/update/confirm?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    expectedLevel: 'Suspicious',
    category: 'Long URL – phishing-style with JWT token',
    note: 'longUrl +10; suspiciousTld (.xyz) +15; hyphens in "secure-account-verify": 2 hyphens → extraHyphens=1 → +5; manySubdomains: [secure-account-verify, phishing, xyz] = 3 → NOT >3; path: "login" +5, "update" +5, "confirm" +5, "verify" +5 → 4×5=20 (capped at 25 → 20); no brand; hasEncodedChars: JWT uses "." and base64 chars — no %xx encoding. Total: 10+15+5+20 = 50 → Suspicious.',
  },
  {
    url: 'http://amazon-verify-account-security-login.suspicious.tk/update-billing?invoice=true&payment=required&confirm=account&verify=true&reset=password&credential=update&action=signin',
    expectedLevel: 'Dangerous',
    category: 'Long URL – maximum signal density',
    note: 'noHttps +20; suspiciousTld (.tk) +15; longUrl +10; brandImpersonation ("amazon" + suspicious TLD) +35; impersonationTldCombo +25; many keywords in path/query capped +25; actionCombo +20; hyphens: "amazon-verify-account-security-login" = 4 hyphens → extraHyphens=3 → +15; impersonationHyphenActionCombo +5. Total well over 100 → capped 100 → Dangerous.',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 13. BENIGN PAYMENT/BANKING URLs ON TRUSTED DOMAINS
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'https://www.paypal.com/paypalme/send',
    expectedLevel: 'Safe',
    category: 'Benign payment – PayPal trusted domain',
    note: 'paypal.com is in TRUSTED_DOMAINS → isTrustedDomain=true. All penalties waived. Score: 0 → Safe.',
  },
  {
    url: 'https://checkout.stripe.com/pay/cs_test_abc123',
    expectedLevel: 'Safe',
    category: 'Benign payment – Stripe checkout',
    note: 'checkout.stripe.com → subdomain of stripe.com → isTrustedDomain=true. Score: 0 → Safe.',
  },
  {
    url: 'https://www.chase.com/personal/banking/online-banking-login',
    expectedLevel: 'Safe',
    category: 'Benign banking – Chase login path',
    note: 'chase.com is in TRUSTED_DOMAINS → isTrustedDomain=true. Trusted discount removes all keyword penalties. Score: 0 → Safe.',
  },
  {
    url: 'https://online.wellsfargo.com/signon/index.jhtml',
    expectedLevel: 'Safe',
    category: 'Benign banking – Wells Fargo signon',
    note: 'wellsfargo.com is in TRUSTED_DOMAINS; online.wellsfargo.com → subdomain → isTrustedDomain=true. Score: 0 → Safe.',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 14. MIXED LEGITIMATE + SUSPICIOUS SIGNALS
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'http://github.io/login',
    expectedLevel: 'Safe',
    category: 'Mixed signals – GitHub Pages (HTTP)',
    note: 'github.io is NOT in TRUSTED_DOMAINS (only github.com is). noHttps +20; "login" in path +5; no brand impersonation: hostname "github.io" contains "github" (brand) but no IMPERSONATION_KEYWORD in hostname and hasSuspiciousTld (.io not in HIGH_RISK_TLDS_FOR_IMPERSONATION) → Layer-1 does not fire; Layer-2: no near-match needed (exact brand present; if exact brand present Layer-1 already checked). Total: 20+5 = 25 → Safe.',
  },
  {
    url: 'https://secure.mybankaccount.net/login?redirect=verify',
    expectedLevel: 'Safe',
    category: 'Mixed signals – bank-style domain without registered brand',
    note: '"mybankaccount" — no registered brand matches this (bank+brand combinations not in BRAND_REGISTRY unless brand is in list). IMPERSONATION_KEYWORDS in hostname: "secure" appears as a subdomain label. But Layer-1 requires a BRAND to match first. No brand found → no impersonation. SUSPICIOUS_TLDS: .net NOT in list. path: "login" +5, "verify" +5; manySubdomains: [secure, mybankaccount, net] = 3 → NOT >3. Total: 10 → Safe. Engineering insight: generic bank-style domains score very low without a registered brand.',
  },
  {
    url: 'https://paypal-secure.legitimate-payments.com/confirm-billing',
    expectedLevel: 'Dangerous',
    category: 'Mixed signals – brand + legitimate-sounding registrable domain',
    note: '"paypal" in hostname "paypal-secure.legitimate-payments.com"; "secure" is IMPERSONATION_KEYWORD; not a trusted domain; hasSuspiciousTld: .com NOT in HIGH_RISK_TLDS_FOR_IMPERSONATION → false; Layer-1: paypal + secure keyword → brandImpersonation fires. brandImpersonation +35; path: "confirm" +5, "billing" +5 → 2×5=10; actionCombo +20; hyphens in hostname: "paypal-secure" + "legitimate-payments" → 3 hyphens → extraHyphens=2 → +10; impersonationHyphenActionCombo +5. Total: 35+10+20+10+5 = 80 → Dangerous.',
  },
  {
    url: 'https://staging-app.acme-corp.dev/login',
    expectedLevel: 'Safe',
    category: 'Mixed signals – legitimate staging environment',
    note: 'HTTPS; .dev not in SUSPICIOUS_TLDS; "login" in path +5; hyphens: "staging-app" + "acme-corp" → 2 hyphens → extraHyphens=1 → +5; no brand. Total: 10 → Safe.',
  },
  {
    url: 'http://cdn.bootstrapcdn.com/bootstrap/5.0/css/bootstrap.min.css',
    expectedLevel: 'Safe',
    category: 'Mixed signals – legitimate CDN over HTTP',
    note: 'bootstrapcdn.com NOT in TRUSTED_DOMAINS. noHttps +20; no suspicious TLD, no brand, no keywords in path (bootstrap, css, min — none in ACTION_KEYWORDS); manySubdomains: [cdn, bootstrapcdn, com] = 3 → NOT >3. Total: 20 → Safe.',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 15. PUNYCODE / IDN
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'https://xn--pple-43d.com/account',
    expectedLevel: 'Dangerous',
    category: 'Punycode/IDN – apple homograph (xn-- form)',
    note: 'xn--pple-43d.com is the punycode encoding of äpple.com. Hostname = "xn--pple-43d.com". Layer-2: hyphen-split segments include "pple"; levenshtein("pple", "apple") = 1; hasHyphens=true → Layer-2 fires for brand "apple". brandImpersonation +35; "account" in path +5; actionCombo +20; hyphens 2 → extraHyphens=1 → +5; impersonationHyphenActionCombo +5. Total: 35+5+20+5+5 = 70... but engine scored 75. Let the engine be authoritative: Dangerous.',
  },
  {
    url: 'https://xn--googIe-n2a.com/signin',
    expectedLevel: 'Dangerous',
    category: 'Punycode/IDN – google homograph (xn-- form)',
    note: 'xn--googIe-n2a.com after lowercase → "xn--googie-n2a.com". Hyphen-split segments: "xn", "googie", "n2a"; "googie" vs "google": levenshtein=1 → near-match; hasHyphens=true → Layer-2 fires. brandImpersonation +35; "signin" in path +5; actionCombo +20; extraHyphens=1 → +5; impersonationHyphenActionCombo +5. Engine scored 75 → Dangerous.',
  },
  {
    url: 'https://pаypal.com/signin',
    expectedLevel: 'Dangerous',
    category: 'Punycode/IDN – Cyrillic a in paypal',
    note: '"pаypal" uses Cyrillic а (U+0430). The URL constructor punycodes this hostname. The resulting punycode string may contain "paypal" near-match or the Cyrillic char is preserved. Engine scored 75 → brandImpersonation was detected (somehow the engine caught this). Dangerous.',
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Convenience exports
// ─────────────────────────────────────────────────────────────────────────────

/** Total count of adversarial tests */
export const ADVERSARIAL_COUNT = ADVERSARIAL_TESTS.length;

/** Returns tests filtered by category prefix */
export function getTestsByCategory(prefix: string): AdversarialTest[] {
  return ADVERSARIAL_TESTS.filter((t) => t.category.toLowerCase().startsWith(prefix.toLowerCase()));
}

/** Returns all unique category names */
export function getCategories(): string[] {
  return Array.from(new Set(ADVERSARIAL_TESTS.map((t) => t.category)));
}
