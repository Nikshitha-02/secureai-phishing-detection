/**
 * evaluation/dataset.ts
 * ─────────────────────
 * Labeled ground-truth dataset for evaluating the SecureAI phishing detector.
 *
 * GROUND TRUTH DEFINITIONS
 * ─────────────────────────
 * SAFE        – Legitimate, well-known website or a realistic URL that a real
 *               user might visit with no cause for alarm. Includes real login
 *               pages of trusted companies.
 *
 * SUSPICIOUS  – URL with one or two weak signals but not definitively phishing.
 *               Examples: URL shorteners (hide destination), HTTP on unknown
 *               domain, unusual TLD for an otherwise benign-looking site,
 *               long URL with no obvious malicious pattern.
 *
 * PHISHING    – URL constructed to deceive users into providing credentials or
 *               visiting a malicious page. Examples: brand impersonation,
 *               typosquatting, free TLD + brand keyword, IP-based login pages,
 *               misleading subdomain tricks.
 *
 * IMPORTANT
 * ─────────
 * - Ground truth is assigned by human expert reasoning, NOT from the detector.
 * - URLs are treated as strings only. They are NEVER visited or fetched.
 * - No real credentials or secrets are embedded.
 * - URLs do NOT represent real pages that were actually tested.
 *
 * DETECTOR MAPPING
 * ─────────────────
 * The detector uses RiskLevel: 'Safe' | 'Suspicious' | 'Dangerous'
 * Mapping to ground truth:
 *   'Safe'      → SAFE
 *   'Suspicious'→ SUSPICIOUS
 *   'Dangerous' → PHISHING
 *
 * This mapping is used for metric calculation.
 */

export type GroundTruth = 'SAFE' | 'SUSPICIOUS' | 'PHISHING';

export interface DatasetEntry {
  url: string;
  groundTruth: GroundTruth;
  /** Human-readable note explaining why this label was assigned */
  note: string;
}

export const DATASET: DatasetEntry[] = [
  // ═══════════════════════════════════════════════════════════════════════════
  // SAFE — 28 entries
  // Major legitimate websites, real login pages, known subdomains, HTTPS only
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'https://google.com',
    groundTruth: 'SAFE',
    note: 'Top-level trusted domain, HTTPS',
  },
  {
    url: 'https://www.google.com',
    groundTruth: 'SAFE',
    note: 'www subdomain of trusted domain',
  },
  {
    url: 'https://mail.google.com/mail/u/0/',
    groundTruth: 'SAFE',
    note: 'Legitimate Google Mail subdomain',
  },
  {
    url: 'https://accounts.google.com/signin/v2/identifier',
    groundTruth: 'SAFE',
    note: 'Real Google login page — trusted domain, contains "signin" keyword but trusted',
  },
  {
    url: 'https://github.com/login',
    groundTruth: 'SAFE',
    note: 'Real GitHub login page — trusted domain with login path',
  },
  {
    url: 'https://github.com/microsoft/vscode',
    groundTruth: 'SAFE',
    note: 'Well-known repo URL — trusted domain',
  },
  {
    url: 'https://stackoverflow.com/questions/tagged/javascript',
    groundTruth: 'SAFE',
    note: 'Popular developer Q&A site, trusted',
  },
  {
    url: 'https://www.amazon.com/gp/cart/view.html',
    groundTruth: 'SAFE',
    note: 'Real Amazon shopping cart — trusted domain',
  },
  {
    url: 'https://www.paypal.com/signin',
    groundTruth: 'SAFE',
    note: 'Real PayPal sign-in — trusted domain with signin path keyword',
  },
  {
    url: 'https://www.linkedin.com/login',
    groundTruth: 'SAFE',
    note: 'Real LinkedIn login — trusted domain',
  },
  {
    url: 'https://netflix.com/login',
    groundTruth: 'SAFE',
    note: 'Real Netflix login — trusted domain with login path',
  },
  {
    url: 'https://discord.com/login',
    groundTruth: 'SAFE',
    note: 'Real Discord login — trusted domain',
  },
  {
    url: 'https://npmjs.com/package/react',
    groundTruth: 'SAFE',
    note: 'NPM package page — trusted domain',
  },
  {
    url: 'https://docs.microsoft.com/en-us/azure/security/',
    groundTruth: 'SAFE',
    note: 'Microsoft Docs subdomain — trusted domain',
  },
  {
    url: 'https://portal.azure.com/',
    groundTruth: 'SAFE',
    note: 'Real Azure portal — azure.com trusted',
  },
  {
    url: 'https://outlook.live.com/mail/0/',
    groundTruth: 'SAFE',
    note: 'Outlook mail — live.com trusted',
  },
  {
    url: 'https://stripe.com/docs/payments',
    groundTruth: 'SAFE',
    note: 'Stripe developer docs — trusted domain',
  },
  {
    url: 'https://app.slack.com/client',
    groundTruth: 'SAFE',
    note: 'Slack app subdomain — trusted domain',
  },
  {
    url: 'https://zoom.us/signin',
    groundTruth: 'SAFE',
    note: 'Real Zoom sign-in — trusted domain',
  },
  {
    url: 'https://www.reddit.com/r/programming',
    groundTruth: 'SAFE',
    note: 'Reddit subreddit — trusted domain',
  },
  {
    url: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
    groundTruth: 'SAFE',
    note: 'YouTube video — trusted domain with query string',
  },
  {
    url: 'https://web.whatsapp.com/',
    groundTruth: 'SAFE',
    note: 'WhatsApp Web — trusted domain',
  },
  {
    url: 'https://www.apple.com/shop/buy-iphone',
    groundTruth: 'SAFE',
    note: 'Apple store page — trusted domain',
  },
  {
    url: 'https://id.apple.com/account/reset/iforgot.action',
    groundTruth: 'SAFE',
    note: 'Real Apple ID reset — trusted subdomain of apple.com',
  },
  {
    url: 'https://www.dropbox.com/login',
    groundTruth: 'SAFE',
    note: 'Real Dropbox login — trusted domain',
  },
  {
    url: 'https://figma.com/login',
    groundTruth: 'SAFE',
    note: 'Real Figma login — trusted domain',
  },
  {
    url: 'https://notion.so/login',
    groundTruth: 'SAFE',
    note: 'Real Notion login — trusted domain',
  },
  {
    url: 'https://proton.me/mail',
    groundTruth: 'SAFE',
    note: 'ProtonMail — trusted domain',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // SUSPICIOUS — 24 entries
  // Weak signals: shorteners, HTTP, unusual TLD, long URL, odd subdomains
  // Not definitively malicious but warrants caution
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'http://bit.ly/3xAb2Yz',
    groundTruth: 'SUSPICIOUS',
    note: 'URL shortener hides destination; HTTP (not HTTPS)',
  },
  {
    url: 'https://tinyurl.com/y7k3mfpq',
    groundTruth: 'SUSPICIOUS',
    note: 'URL shortener — destination unknown',
  },
  {
    url: 'https://rb.gy/qx8rjt',
    groundTruth: 'SUSPICIOUS',
    note: 'URL shortener service',
  },
  {
    url: 'http://example.com/login',
    groundTruth: 'SUSPICIOUS',
    note: 'HTTP (no HTTPS), unknown domain with login path',
  },
  {
    url: 'http://mysite.biz/account/settings',
    groundTruth: 'SUSPICIOUS',
    note: 'HTTP + .biz TLD + account path keyword',
  },
  {
    url: 'https://cheap-hosting.xyz/signup',
    groundTruth: 'SUSPICIOUS',
    note: '.xyz TLD is flagged as suspicious; signup keyword',
  },
  {
    url: 'http://deals.info/free-voucher?code=WIN100',
    groundTruth: 'SUSPICIOUS',
    note: 'HTTP + .info TLD + free/winner-type path',
  },
  {
    url: 'https://login.someunknownsite.online/user/verify',
    groundTruth: 'SUSPICIOUS',
    note: '.online TLD + login subdomain + verify path',
  },
  {
    url: 'https://www.newstartup.club/register',
    groundTruth: 'SUSPICIOUS',
    note: '.club TLD — cheap to register, used in some campaigns',
  },
  {
    url: 'https://track.marketing-email.live/unsubscribe?id=abc123',
    groundTruth: 'SUSPICIOUS',
    note: '.live TLD + tracking link pattern',
  },
  {
    url: 'https://api.someservice.cc/oauth/callback',
    groundTruth: 'SUSPICIOUS',
    note: '.cc TLD is suspicious',
  },
  {
    url: 'https://www.company-portal.biz/employee/login?redirect=/dashboard',
    groundTruth: 'SUSPICIOUS',
    note: '.biz TLD + login + long URL',
  },
  {
    url: 'http://192.168.100.5/admin',
    groundTruth: 'SUSPICIOUS',
    note: 'Private IP address — could be internal network device or local exploit',
  },
  {
    url: 'https://cutt.ly/TwZ8kQp',
    groundTruth: 'SUSPICIOUS',
    note: 'URL shortener',
  },
  {
    url: 'https://is.gd/Xm7yBa',
    groundTruth: 'SUSPICIOUS',
    note: 'URL shortener',
  },
  {
    url: 'https://unknown-blog.info/2024/01/how-to-reset-your-password-step-by-step-guide-tutorial-complete',
    groundTruth: 'SUSPICIOUS',
    note: 'Unusually long URL + .info TLD + password keyword',
  },
  {
    url: 'http://newsletter.click/open?m=abc&u=xyz&c=123&utm_source=email',
    groundTruth: 'SUSPICIOUS',
    note: '.click TLD + HTTP',
  },
  {
    url: 'https://downloads.work/tool?ref=partner&id=99182736',
    groundTruth: 'SUSPICIOUS',
    note: '.work TLD, generic download domain',
  },
  {
    url: 'https://cdn.staticfiles.pw/assets/script.js',
    groundTruth: 'SUSPICIOUS',
    note: '.pw (Palau) TLD, commonly abused',
  },
  {
    url: 'https://app.newservice.vip/dashboard',
    groundTruth: 'SUSPICIOUS',
    note: '.vip TLD — low-cost, abused in spam campaigns',
  },
  {
    url: 'https://my-account-portal.com/reset-password?token=abc123xyz',
    groundTruth: 'SUSPICIOUS',
    note: 'Generic domain with reset-password path + token; hyphens in domain',
  },
  {
    url: 'https://user.online-platform.site/profile/verify',
    groundTruth: 'SUSPICIOUS',
    note: '.site TLD + verify path',
  },
  {
    url: 'https://files.download.stream/setup.exe',
    groundTruth: 'SUSPICIOUS',
    note: '.stream TLD, executable download pattern',
  },
  {
    url: 'https://m.unknown-store.fun/checkout?item=shirt&qty=1',
    groundTruth: 'SUSPICIOUS',
    note: '.fun TLD for an e-commerce site',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // PHISHING — 28 entries
  // Brand impersonation, typosquatting, IP login pages, misleading subdomains
  // ═══════════════════════════════════════════════════════════════════════════

  {
    url: 'https://paypa1-secure.login.verify-account.tk',
    groundTruth: 'PHISHING',
    note: 'PayPal lookalike with "1" for "l", free TLD, multiple phishing keywords',
  },
  {
    url: 'https://google-login.xyz/signin?redirect=gmail',
    groundTruth: 'PHISHING',
    note: 'Google brand impersonation, .xyz TLD, signin path',
  },
  {
    url: 'http://192.168.1.1/login',
    groundTruth: 'PHISHING',
    note: 'Raw private IP address with login path — classic router hijack / LAN phishing',
  },
  {
    url: 'http://203.0.113.45/paypal/login.php',
    groundTruth: 'PHISHING',
    note: 'Public raw IP + PayPal brand path + login path',
  },
  {
    url: 'https://secure-paypal-login.com/verify-account',
    groundTruth: 'PHISHING',
    note: 'PayPal impersonation with hyphens, secure/login/verify keywords',
  },
  {
    url: 'https://paypal-update-billing.ml',
    groundTruth: 'PHISHING',
    note: 'PayPal brand + free TLD .ml + update/billing keywords',
  },
  {
    url: 'https://signin.amazon-account-verify.tk/ap/signin',
    groundTruth: 'PHISHING',
    note: 'Amazon impersonation with free TLD, account-verify, signin',
  },
  {
    url: 'https://amazon-prime-renewal.gq/payment',
    groundTruth: 'PHISHING',
    note: 'Amazon brand + free TLD + payment path',
  },
  {
    url: 'https://microsoft-account-security.live/password/reset',
    groundTruth: 'PHISHING',
    note: 'Microsoft brand + .live TLD (suspicious) + password/reset keywords',
  },
  {
    url: 'https://login-microsoftonline.com.verify-email.ml/auth',
    groundTruth: 'PHISHING',
    note: 'Microsoft subdomain trick, free TLD .ml, auth/verify keywords',
  },
  {
    url: 'https://apple-id-suspended-verify.xyz/account/recover',
    groundTruth: 'PHISHING',
    note: 'Apple brand + .xyz TLD + suspended/verify/account/recover keywords',
  },
  {
    url: 'https://icloud-account-unlock.cf/login',
    groundTruth: 'PHISHING',
    note: 'iCloud/Apple brand + .cf free TLD + unlock/login',
  },
  {
    url: 'https://facebook-login.support-team.xyz/checkpoint',
    groundTruth: 'PHISHING',
    note: 'Facebook brand + support + .xyz TLD + checkpoint path',
  },
  {
    url: 'https://instagram-verify-account.ml/',
    groundTruth: 'PHISHING',
    note: 'Instagram brand + .ml TLD + verify/account',
  },
  {
    url: 'https://netfIix-billing-update.com/account/payment',
    groundTruth: 'PHISHING',
    note: 'Netflix typosquatting (capital I for lowercase l) + billing/payment keywords',
  },
  {
    url: 'https://netflix-subscription-renewal.tk/signin',
    groundTruth: 'PHISHING',
    note: 'Netflix brand + .tk TLD + subscription/renewal/signin keywords',
  },
  {
    url: 'https://login.secure.paypal-helpdesk.com/update',
    groundTruth: 'PHISHING',
    note: 'Deep subdomain PayPal impersonation, helpdesk keyword, update path',
  },
  {
    url: 'https://bankofamerica-secure-login.gq/verify',
    groundTruth: 'PHISHING',
    note: 'Bank of America brand + free TLD + secure/login/verify',
  },
  {
    url: 'https://wellsfargo-account-update.ml/signin',
    groundTruth: 'PHISHING',
    note: 'Wells Fargo brand + free TLD + account/update/signin',
  },
  {
    url: 'https://chase-online-banking-secure.xyz/login/credential',
    groundTruth: 'PHISHING',
    note: 'Chase bank impersonation, online/banking/secure/login/credential, .xyz',
  },
  {
    url: 'https://github-security-alert.ml/account/verify',
    groundTruth: 'PHISHING',
    note: 'GitHub brand + .ml TLD + security/alert/account/verify',
  },
  {
    url: 'https://discord-nitro-free.site/claim',
    groundTruth: 'PHISHING',
    note: 'Discord brand + free keyword + .site TLD — common gaming phishing pattern',
  },
  {
    url: 'https://dropbox-shared-document.xyz/login?file=invoice_2024.pdf',
    groundTruth: 'PHISHING',
    note: 'Dropbox impersonation + .xyz + invoice/login keyword + fake document lure',
  },
  {
    url: 'https://accounts.google.com.signin-recovery.xyz/recover',
    groundTruth: 'PHISHING',
    note: 'Subdomain trick: looks like accounts.google.com but actual domain is signin-recovery.xyz',
  },
  {
    url: 'https://www.paypal.com.secure-payment-alert.ml/login',
    groundTruth: 'PHISHING',
    note: 'Subdomain trick: paypal.com embedded as subdomain of .ml domain',
  },
  {
    url: 'https://support.apple.com.account-locked-verify.tk/unlock',
    groundTruth: 'PHISHING',
    note: 'Subdomain trick: apple.com embedded as subdomain of .tk domain',
  },
  {
    url: 'https://free-gift-claim.xyz/winner?user=target&prize=iphone',
    groundTruth: 'PHISHING',
    note: 'Prize scam URL — .xyz TLD + free/winner/prize in path/query',
  },
  {
    url: 'http://login-update.bankofamerica-secure.net/account/confirm',
    groundTruth: 'PHISHING',
    note: 'HTTP + Bank of America brand + secure/login/update/account/confirm',
  },
];
