/**
 * features/dashboard/mockData.ts
 *
 * Static mock data used while the real backend API is not yet connected.
 *
 * IMPORTANT: All functions and objects here are intentionally shaped to match
 * the types in @/types/dashboard.ts so that the only change required for
 * backend integration is replacing these calls with real API service calls.
 */

import type { DashboardStats, RecentScan, ScanResult, SecurityCheck } from '@/types/dashboard';

// ─── Dashboard Statistics ─────────────────────────────────────────────────────

export const MOCK_STATS: DashboardStats = {
  totalScans: 142,
  safeUrls: 118,
  suspiciousUrls: 17,
  highRiskUrls: 7,
};

// ─── Recent Scans ─────────────────────────────────────────────────────────────

export const MOCK_RECENT_SCANS: RecentScan[] = [
  {
    id: '1',
    url: 'https://google.com',
    riskScore: 3,
    riskLevel: 'safe',
    scannedAt: '2025-07-26T10:30:00Z',
  },
  {
    id: '2',
    url: 'https://paypa1-secure.login.verify-account.tk',
    riskScore: 94,
    riskLevel: 'dangerous',
    scannedAt: '2025-07-26T09:15:00Z',
  },
  {
    id: '3',
    url: 'https://bit.ly/3xAb2Yz',
    riskScore: 55,
    riskLevel: 'suspicious',
    scannedAt: '2025-07-25T22:40:00Z',
  },
  {
    id: '4',
    url: 'https://github.com/microsoft/vscode',
    riskScore: 5,
    riskLevel: 'safe',
    scannedAt: '2025-07-25T18:00:00Z',
  },
  {
    id: '5',
    url: 'http://free-gift-claim.xyz/winner',
    riskScore: 88,
    riskLevel: 'dangerous',
    scannedAt: '2025-07-25T14:22:00Z',
  },
  {
    id: '6',
    url: 'https://npmjs.com/package/react',
    riskScore: 8,
    riskLevel: 'safe',
    scannedAt: '2025-07-24T11:05:00Z',
  },
  {
    id: '7',
    url: 'http://login-update.bankofamerica-secure.net',
    riskScore: 91,
    riskLevel: 'dangerous',
    scannedAt: '2025-07-24T08:30:00Z',
  },
];

// ─── Security Tips ────────────────────────────────────────────────────────────

export const SECURITY_TIPS: string[] = [
  'Never click links in unsolicited emails — type addresses directly in your browser.',
  'Check for HTTPS and verify the domain carefully before entering any credentials.',
  'Legitimate banks and services never ask for your password via email or SMS.',
  'Use a password manager to avoid re-using passwords across different sites.',
  'Enable two-factor authentication on all accounts that support it.',
  'Hover over links before clicking to preview the actual destination URL.',
  'Be suspicious of any URL that creates urgency — "Your account will be closed!"',
  'Official company domains never use free subdomains like .tk, .ml, or .ga.',
];

/** Returns a deterministic tip for the current day. */
export function getDailyTip(): string {
  const dayIndex = new Date().getDay(); // 0–6
  return SECURITY_TIPS[dayIndex % SECURITY_TIPS.length];
}

// ─── Mock Scan Result Builder ─────────────────────────────────────────────────

/**
 * Generates a mock ScanResult for a given URL.
 * The risk score is pseudo-randomised based on URL characteristics so that
 * obviously suspicious URLs score higher.
 *
 * Replace this function with a real API call when the backend is ready.
 */
export function generateMockScanResult(url: string): ScanResult {
  const lower = url.toLowerCase();

  // Simple heuristics to make the mock feel realistic
  const isHttps = lower.startsWith('https://');
  const hasIpAddress = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(lower);
  const isLongUrl = url.length > 100;
  const suspiciousKeywords = [
    'login',
    'verify',
    'secure',
    'update',
    'account',
    'confirm',
    'paypal',
    'bank',
    'password',
    'free',
    'winner',
    'prize',
    'claim',
    'urgent',
  ];
  const hasSuspiciousKeyword = suspiciousKeywords.some((kw) => lower.includes(kw));
  const freeTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click'];
  const hasFreeTLD = freeTLDs.some((tld) => lower.includes(tld));

  // Count subdomains (parts between protocol and TLD)
  const domainMatch = lower.match(/https?:\/\/([^/]+)/);
  const domainParts = domainMatch ? domainMatch[1].split('.') : [];
  const subdomainCount = Math.max(0, domainParts.length - 2);
  const hasManySubdomains = subdomainCount > 2;

  // Calculate score
  let score = 10;
  if (!isHttps) score += 20;
  if (hasIpAddress) score += 30;
  if (isLongUrl) score += 10;
  if (hasSuspiciousKeyword) score += 20;
  if (hasFreeTLD) score += 25;
  if (hasManySubdomains) score += 15;
  score = Math.min(score, 100);

  // Build checks
  const checks: SecurityCheck[] = [
    {
      label: 'HTTPS',
      value: isHttps ? 'Enabled' : 'Not enabled',
      passed: isHttps,
    },
    {
      label: 'Domain Age',
      value: 'Unknown',
      passed: true,
    },
    {
      label: 'IP Address URL',
      value: hasIpAddress ? 'Yes — suspicious' : 'No',
      passed: !hasIpAddress,
    },
    {
      label: 'URL Length',
      value: isLongUrl ? 'Unusually long' : 'Normal',
      passed: !isLongUrl,
    },
    {
      label: 'Suspicious Keywords',
      value: hasSuspiciousKeyword ? 'Detected' : 'None',
      passed: !hasSuspiciousKeyword,
    },
    {
      label: 'Subdomains',
      value: String(subdomainCount),
      passed: !hasManySubdomains,
    },
  ];

  // Derive risk level
  let riskLevel: ScanResult['riskLevel'];
  if (score < 30) {
    riskLevel = 'safe';
  } else if (score < 65) {
    riskLevel = 'suspicious';
  } else {
    riskLevel = 'dangerous';
  }

  // Build verdict
  const verdicts: Record<ScanResult['riskLevel'], string> = {
    safe: 'This website appears safe. No common phishing indicators were detected.',
    suspicious:
      'This URL has some suspicious characteristics. Exercise caution before entering any personal data.',
    dangerous:
      'This URL shows multiple strong indicators of a phishing attack. Do not visit this website.',
  };

  return {
    url,
    riskScore: score,
    riskLevel,
    verdict: verdicts[riskLevel],
    checks,
    scannedAt: new Date().toISOString(),
  };
}
