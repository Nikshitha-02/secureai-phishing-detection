/**
 * scan.test.ts
 * ────────────
 * Self-contained integration test for the phishing detection engine.
 *
 * Run with:
 *   npx ts-node-dev --transpile-only src/tests/scan.test.ts
 *   OR after build:
 *   npm run test
 *
 * Tests the 8 canonical URLs and verifies they fall within expected score
 * ranges and risk levels.
 *
 * Exit code 0 = all tests passed
 * Exit code 1 = one or more tests failed
 */

import { scanUrl } from '../services/scan.service';
import type { RiskLevel } from '../models/scan.model';

// ─────────────────────────────────────────────────────────────────────────────
// Test framework (minimal, no external dependencies)
// ─────────────────────────────────────────────────────────────────────────────

interface TestCase {
  url: string;
  description: string;
  expectedLevel: RiskLevel;
  minScore: number;
  maxScore: number;
}

const RESET  = '\x1b[0m';
const GREEN  = '\x1b[32m';
const RED    = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN   = '\x1b[36m';
const BOLD   = '\x1b[1m';

// ─────────────────────────────────────────────────────────────────────────────
// Test cases
// ─────────────────────────────────────────────────────────────────────────────

const TEST_CASES: TestCase[] = [
  {
    url: 'https://google.com',
    description: 'Trusted domain — should be Safe with near-zero score',
    expectedLevel: 'Safe',
    minScore: 0,
    maxScore: 5,
  },
  {
    url: 'https://github.com',
    description: 'Trusted domain — should be Safe',
    expectedLevel: 'Safe',
    minScore: 0,
    maxScore: 10,
  },
  {
    url: 'http://bit.ly/test',
    description: 'HTTP + URL shortener — should be Suspicious',
    expectedLevel: 'Suspicious',
    minScore: 31,
    maxScore: 70,
  },
  {
    url: 'http://secure-login-paypal-update.tk',
    description: 'HTTP + suspicious TLD + brand impersonation — should be Dangerous',
    expectedLevel: 'Dangerous',
    minScore: 71,
    maxScore: 100,
  },
  {
    url: 'http://192.168.1.1/login',
    description: 'Raw IP address — should be Dangerous',
    expectedLevel: 'Dangerous',
    minScore: 71,
    maxScore: 100,
  },
  {
    url: 'https://mail.google.com',
    description: 'Trusted subdomain of google.com — should be Safe',
    expectedLevel: 'Safe',
    minScore: 0,
    maxScore: 10,
  },
  {
    url: 'https://google-login.xyz',
    description: 'Brand impersonation (google + login + .xyz) — should be Dangerous',
    expectedLevel: 'Dangerous',
    minScore: 71,
    maxScore: 100,
  },
  {
    url: 'https://docs.google.com',
    description: 'Another trusted subdomain of google.com — should be Safe',
    expectedLevel: 'Safe',
    minScore: 0,
    maxScore: 10,
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Test runner
// ─────────────────────────────────────────────────────────────────────────────

async function runTests(): Promise<void> {
  console.log(`\n${BOLD}${CYAN}═══════════════════════════════════════════════════════${RESET}`);
  console.log(`${BOLD}${CYAN}  SecureAI Phishing Detection Engine — Test Suite${RESET}`);
  console.log(`${BOLD}${CYAN}═══════════════════════════════════════════════════════${RESET}\n`);

  let passed = 0;
  let failed = 0;

  for (const tc of TEST_CASES) {
    let result;
    try {
      // Pass a dummy userId for tests — persistence is a no-op when
      // SUPABASE_SERVICE_ROLE_KEY is not configured in the test environment.
      result = await scanUrl(tc.url, 'test-user-id');
    } catch (err) {
      console.log(`${RED}✗ FAIL${RESET} — ${tc.url}`);
      console.log(`       Error: ${(err as Error).message}`);
      failed++;
      continue;
    }

    const scoreOk = result.riskScore >= tc.minScore && result.riskScore <= tc.maxScore;
    const levelOk = result.riskLevel === tc.expectedLevel;
    const ok = scoreOk && levelOk;

    if (ok) {
      console.log(`${GREEN}✓ PASS${RESET} — ${tc.url}`);
      console.log(
        `       Score: ${BOLD}${result.riskScore}${RESET}  Level: ${BOLD}${result.riskLevel}${RESET}`,
      );
      passed++;
    } else {
      console.log(`${RED}✗ FAIL${RESET} — ${tc.url}`);
      console.log(`       Description  : ${tc.description}`);
      if (!scoreOk) {
        console.log(
          `       Score        : got ${BOLD}${result.riskScore}${RESET}` +
            `, expected [${tc.minScore}–${tc.maxScore}]`,
        );
      }
      if (!levelOk) {
        console.log(
          `       Risk Level   : got ${BOLD}${result.riskLevel}${RESET}` +
            `, expected ${BOLD}${tc.expectedLevel}${RESET}`,
        );
      }
      failed++;
    }

    // Print checks summary and recommendations
    console.log(`       Trusted      : ${result.checks.isTrustedDomain}`);
    if (result.checks.brandImpersonation) {
      console.log(
        `       Impersonation: ${result.checks.brandImpersonation.brand} → ${result.checks.brandImpersonation.hostname}`,
      );
    }
    console.log(`       Recommendations:`);
    result.recommendations.forEach((r) => console.log(`         • ${r}`));
    console.log();
  }

  // ── Summary ────────────────────────────────────────────────────────────────
  console.log(`${BOLD}${CYAN}═══════════════════════════════════════════════════════${RESET}`);
  const total = passed + failed;
  if (failed === 0) {
    console.log(`${GREEN}${BOLD}  All ${total} tests passed ✓${RESET}`);
  } else {
    console.log(
      `${YELLOW}${BOLD}  ${passed}/${total} passed  |  ${failed} failed${RESET}`,
    );
  }
  console.log(`${BOLD}${CYAN}═══════════════════════════════════════════════════════${RESET}\n`);

  // Fail the process so CI pipelines can detect failures
  if (failed > 0) process.exit(1);
}

runTests().catch((err: unknown) => {
  console.error('Unexpected error in test runner:', err);
  process.exit(1);
});
