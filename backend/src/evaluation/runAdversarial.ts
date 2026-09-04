/**
 * runAdversarial.ts
 * ─────────────────
 * Adversarial / edge-case robustness test runner for SecureAI.
 *
 * ╔═══════════════════════════════════════════════════════════════════════╗
 * ║  ⚠️  THIS IS NOT THE OFFICIAL EVALUATION  ⚠️                        ║
 * ║                                                                       ║
 * ║  This script runs the ADVERSARIAL test suite defined in               ║
 * ║  adversarialTests.ts.  It is a SEPARATE robustness exercise.          ║
 * ║                                                                       ║
 * ║  • It does NOT modify results.json                                    ║
 * ║  • It does NOT affect official evaluation metrics                     ║
 * ║  • Failures here are ENGINEERING INSIGHTS, not accuracy degradation   ║
 * ║  • The official dataset lives in dataset.ts (unmodified)              ║
 * ╚═══════════════════════════════════════════════════════════════════════╝
 *
 * WHAT THIS SCRIPT DOES
 * ──────────────────────
 * 1. Loads all adversarial tests from adversarialTests.ts
 * 2. Runs the rule engine on each URL (no Gemini, no Supabase, no network)
 * 3. Compares the detected RiskLevel against the expected label
 * 4. Writes backend/evaluation/ADVERSARIAL_REPORT.md
 * 5. Prints a per-test summary and pass/fail totals to stdout
 */

import * as fs   from 'fs';
import * as path from 'path';

// Rule engine imports — identical to evaluate.ts (no network, no AI)
import { parseUrl }                     from '../utils/urlStructureAnalyzer';
import { checkHttps }                   from '../utils/urlStructureAnalyzer';
import { checkIpAddress }               from '../utils/urlStructureAnalyzer';
import { checkLongUrl }                 from '../utils/urlStructureAnalyzer';
import { checkManySubdomains }          from '../utils/urlStructureAnalyzer';
import { checkUrlShortener }            from '../utils/urlStructureAnalyzer';
import { checkSuspiciousKeywords }      from '../utils/urlStructureAnalyzer';
import { checkSuspiciousTld }           from '../utils/urlStructureAnalyzer';
import { countHyphens }                 from '../utils/urlStructureAnalyzer';
import { checkEncodedChars }            from '../utils/urlStructureAnalyzer';
import { isTrustedDomain }              from '../config/trustedDomains';
import { detectBrandImpersonation }     from '../utils/brandImpersonation';
import { calculateScore, classifyRisk } from '../utils/riskScoring';
import { NullReputationProvider }       from '../utils/domainReputation';

import type { RiskLevel }               from '../models/scan.model';
import {
  ADVERSARIAL_TESTS,
  ADVERSARIAL_COUNT,
  type AdversarialTest,
  type AdversarialLevel,
} from './adversarialTests';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface AdversarialResult {
  test:           AdversarialTest;
  detectedLevel:  AdversarialLevel | 'UNPARSEABLE';
  riskScore:      number | null;
  pass:           boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule engine runner (no external calls)
// ─────────────────────────────────────────────────────────────────────────────

const nullReputation = new NullReputationProvider();

async function runRuleEngine(
  url: string,
): Promise<{ riskScore: number; riskLevel: RiskLevel } | null> {
  const parsed = parseUrl(url);
  if (!parsed) return null;

  const https               = checkHttps(parsed);
  const ipAddress           = checkIpAddress(parsed);
  const urlShortener        = checkUrlShortener(parsed);
  const longUrl             = checkLongUrl(parsed);
  const suspiciousTld       = checkSuspiciousTld(parsed);
  const manySubdomains      = checkManySubdomains(parsed);
  const hyphenCount         = countHyphens(parsed);
  const hasEncodedChars     = checkEncodedChars(parsed);
  const suspiciousKeywords  = checkSuspiciousKeywords(parsed);
  const trusted             = isTrustedDomain(parsed.hostname);
  const brandImpersonation  = detectBrandImpersonation(parsed);
  const reputation          = await nullReputation.checkUrl(parsed.href);

  const riskScore = calculateScore({
    https,
    ipAddress,
    urlShortener,
    longUrl,
    suspiciousKeywords,
    suspiciousTld,
    manySubdomains,
    hyphenCount,
    hasEncodedChars,
    brandImpersonation,
    isTrustedDomain: trusted,
    reputation,
  });

  return { riskScore, riskLevel: classifyRisk(riskScore) };
}

// Maps engine RiskLevel to the same type used by AdversarialLevel
function toAdversarialLevel(level: RiskLevel): AdversarialLevel {
  return level as AdversarialLevel; // types are identical strings
}

// ─────────────────────────────────────────────────────────────────────────────
// Run all tests
// ─────────────────────────────────────────────────────────────────────────────

async function runAllTests(): Promise<AdversarialResult[]> {
  const results: AdversarialResult[] = [];

  for (const test of ADVERSARIAL_TESTS) {
    const engineResult = await runRuleEngine(test.url);

    if (engineResult === null) {
      results.push({
        test,
        detectedLevel: 'UNPARSEABLE',
        riskScore: null,
        pass: false, // unparseable URLs are always a mismatch (unless expected behaviour is documented)
      });
    } else {
      const detectedLevel = toAdversarialLevel(engineResult.riskLevel);
      results.push({
        test,
        detectedLevel,
        riskScore: engineResult.riskScore,
        pass: detectedLevel === test.expectedLevel,
      });
    }
  }

  return results;
}

// ─────────────────────────────────────────────────────────────────────────────
// Report generation
// ─────────────────────────────────────────────────────────────────────────────

function generateReport(results: AdversarialResult[]): string {
  const passed   = results.filter((r) => r.pass).length;
  const failed   = results.filter((r) => !r.pass).length;
  const total    = results.length;
  const passRate = total > 0 ? ((passed / total) * 100).toFixed(1) : '0.0';

  // Group by category
  const byCategory = new Map<string, AdversarialResult[]>();
  for (const r of results) {
    const cat = r.test.category;
    if (!byCategory.has(cat)) byCategory.set(cat, []);
    byCategory.get(cat)!.push(r);
  }

  // Failures only (engineering insights)
  const failures = results.filter((r) => !r.pass);

  const lines: string[] = [];

  lines.push('# SecureAI — Adversarial / Edge-Case Robustness Report');
  lines.push('');
  lines.push('> ⚠️ **THIS IS NOT THE OFFICIAL EVALUATION** ⚠️');
  lines.push('>');
  lines.push('> This report is generated by the adversarial robustness test suite.');
  lines.push('> It is entirely separate from the official phishing detection evaluation.');
  lines.push('> - The official evaluation dataset lives in `dataset.ts` (unmodified).');
  lines.push('> - The official metrics live in `results.json` (not modified by this script).');
  lines.push('> - Failures in this suite are **engineering insights** — not accuracy degradation.');
  lines.push('> - Labels are assigned by reasoning, not by running the detector.');
  lines.push('');
  lines.push('---');
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Total adversarial tests | ${total} |`);
  lines.push(`| Passed (detector matches expected) | ${passed} |`);
  lines.push(`| Failed (detector differs from expected) | ${failed} |`);
  lines.push(`| Pass rate | ${passRate}% |`);
  lines.push('');
  lines.push('---');
  lines.push('');
  lines.push('## Results by Category');
  lines.push('');

  for (const [cat, catResults] of byCategory) {
    const catPassed = catResults.filter((r) => r.pass).length;
    const catTotal  = catResults.length;
    lines.push(`### ${cat}`);
    lines.push('');
    lines.push(`Passed: **${catPassed} / ${catTotal}**`);
    lines.push('');
    lines.push('| # | URL | Expected | Detected | Score | Pass? |');
    lines.push('|---|-----|----------|----------|-------|-------|');

    for (let i = 0; i < catResults.length; i++) {
      const r = catResults[i];
      const urlDisplay = r.test.url.length > 80
        ? r.test.url.slice(0, 77) + '...'
        : r.test.url;
      const scoreStr  = r.riskScore !== null ? String(r.riskScore) : 'N/A';
      const passEmoji = r.pass ? '✅' : '❌';
      lines.push(
        `| ${i + 1} | \`${urlDisplay}\` | ${r.test.expectedLevel} | ${r.detectedLevel} | ${scoreStr} | ${passEmoji} |`,
      );
    }
    lines.push('');
  }

  lines.push('---');
  lines.push('');

  if (failures.length === 0) {
    lines.push('## Engineering Insights: Mismatches');
    lines.push('');
    lines.push('✅ **All tests passed.** No mismatches to report.');
    lines.push('');
  } else {
    lines.push('## Engineering Insights: Mismatches');
    lines.push('');
    lines.push(
      'The following tests produced a different result than expected. ' +
      'This does **not** mean the engine is wrong — many of these are intentional ' +
      'edge cases that probe scoring boundaries or known limitations. ' +
      'Use these as signals for future improvement.',
    );
    lines.push('');

    for (let i = 0; i < failures.length; i++) {
      const r = failures[i];
      lines.push(`### Mismatch ${i + 1}: ${r.test.category}`);
      lines.push('');
      lines.push(`**URL:** \`${r.test.url}\``);
      lines.push('');
      lines.push(`**Expected:** ${r.test.expectedLevel}  |  **Detected:** ${r.detectedLevel}  |  **Score:** ${r.riskScore ?? 'N/A'}`);
      lines.push('');
      lines.push(`**Reasoning note:** ${r.test.note}`);
      lines.push('');
    }
  }

  lines.push('---');
  lines.push('');
  lines.push('## Methodology');
  lines.push('');
  lines.push('- **Rule engine only** — no Gemini AI, no Supabase, no network requests');
  lines.push('- **Labels assigned by reasoning** — expected levels were determined by manually');
  lines.push('  tracing scoring weights in `riskScoring.ts` before running the detector');
  lines.push('- **Some labels are intentionally aspirational** — a few tests are marked with');
  lines.push('  a higher expected level than the engine currently produces, to document');
  lines.push('  known detection gaps (e.g. brand-in-path-only, punycode IDN homographs)');
  lines.push('- **Failures ≠ bugs** — many failures indicate architectural limitations');
  lines.push('  (no punycode decoding, no content inspection, no WHOIS) that are already');
  lines.push('  documented in the README as known limitations');
  lines.push('');
  lines.push('## Known Limitations Exercised by This Suite');
  lines.push('');
  lines.push('1. **Brand in path only** — the engine checks the hostname for brand names;');
  lines.push('   a brand appearing only in the URL path does not trigger impersonation detection');
  lines.push('2. **Punycode / IDN homographs** — the engine does not decode punycode hostnames;');
  lines.push('   IDN homograph attacks that arrive as `xn--...` are not caught');
  lines.push('3. **Port numbers** — the engine has no port-based penalty;');
  lines.push('   non-standard ports do not contribute to the risk score');
  lines.push('4. **Action words in domain name** — ACTION_KEYWORDS are checked on path/query only;');
  lines.push('   a hostname like "bank-transfer-verify.tk" does not get keyword points');
  lines.push('5. **Unregistered brands** — "bank" is not in BRAND_REGISTRY;');
  lines.push('   generic bank-impersonation domains without a registered brand name score lower');
  lines.push('');
  lines.push(`*Generated: ${new Date().toISOString()}*`);
  lines.push('');

  return lines.join('\n');
}

// ─────────────────────────────────────────────────────────────────────────────
// Stdout summary
// ─────────────────────────────────────────────────────────────────────────────

function printSummary(results: AdversarialResult[]): void {
  const passed = results.filter((r) => r.pass).length;
  const failed = results.filter((r) => !r.pass).length;
  const total  = results.length;

  console.log('');
  console.log('SecureAI — Adversarial Robustness Test');
  console.log('══════════════════════════════════════════');
  console.log('⚠️  SEPARATE ROBUSTNESS TEST — NOT THE OFFICIAL EVALUATION');
  console.log('   Official metrics are in evaluation/results.json (unchanged)');
  console.log('══════════════════════════════════════════');
  console.log('');
  console.log(`Total tests:  ${total}`);
  console.log(`Passed:       ${passed}`);
  console.log(`Failed:       ${failed}`);
  console.log(`Pass rate:    ${((passed / total) * 100).toFixed(1)}%`);
  console.log('');

  // Per-test table
  const colWidth = 70;
  console.log('Per-test results:');
  console.log('─'.repeat(100));

  // Group by category for nicer output
  let lastCat = '';
  for (const r of results) {
    if (r.test.category !== lastCat) {
      console.log(`\n  ── ${r.test.category}`);
      lastCat = r.test.category;
    }
    const icon  = r.pass ? '✓' : '✗';
    const url   = r.test.url.length > colWidth
      ? r.test.url.slice(0, colWidth - 3) + '...'
      : r.test.url.padEnd(colWidth);
    const score = r.riskScore !== null ? String(r.riskScore).padStart(3) : 'N/A';
    console.log(
      `  ${icon}  ${url}  exp=${r.test.expectedLevel.padEnd(10)} got=${(r.detectedLevel as string).padEnd(10)} score=${score}`,
    );
  }

  console.log('');
  console.log('─'.repeat(100));

  // Failures section
  const failures = results.filter((r) => !r.pass);
  if (failures.length === 0) {
    console.log('✅  All adversarial tests passed.');
  } else {
    console.log(`\n❌  ${failures.length} mismatch(es) — engineering insights below:`);
    for (const r of failures) {
      console.log('');
      console.log(`  Category: ${r.test.category}`);
      console.log(`  URL:      ${r.test.url}`);
      console.log(`  Expected: ${r.test.expectedLevel}  →  Detected: ${r.detectedLevel}  (score: ${r.riskScore ?? 'N/A'})`);
    }
  }

  console.log('');
}

// ─────────────────────────────────────────────────────────────────────────────
// Output directory setup
// ─────────────────────────────────────────────────────────────────────────────

function ensureOutputDir(): string {
  // Output lives at backend/evaluation/ (sibling of dist/)
  // __dirname at runtime = backend/dist/evaluation/
  // Two levels up → backend/, then evaluation/ → backend/evaluation/
  const outputDir = path.resolve(__dirname, '..', '..', 'evaluation');
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }
  return outputDir;
}

// ─────────────────────────────────────────────────────────────────────────────
// Safety check — confirm results.json is NOT touched
// ─────────────────────────────────────────────────────────────────────────────

function confirmResultsJsonUntouched(outputDir: string): void {
  const resultsPath = path.join(outputDir, 'results.json');
  if (fs.existsSync(resultsPath)) {
    // Read mtime before we write anything
    const mtime = fs.statSync(resultsPath).mtimeMs;
    // Store for post-write verification
    (globalThis as Record<string, unknown>).__resultsJsonMtime = mtime;
  }
}

function verifyResultsJsonUntouched(outputDir: string): void {
  const resultsPath = path.join(outputDir, 'results.json');
  if (!fs.existsSync(resultsPath)) return;
  const storedMtime = (globalThis as Record<string, unknown>).__resultsJsonMtime as number | undefined;
  if (storedMtime === undefined) return;
  const currentMtime = fs.statSync(resultsPath).mtimeMs;
  if (currentMtime !== storedMtime) {
    console.error(
      '\n🚨 INTEGRITY ERROR: results.json was modified during this run! ' +
      'This should never happen. Please report this as a bug.',
    );
    process.exit(2);
  }
  console.log('✓ results.json was NOT modified (mtime unchanged)');
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log(`\nLoaded ${ADVERSARIAL_COUNT} adversarial tests.`);

  const outputDir = ensureOutputDir();
  confirmResultsJsonUntouched(outputDir);

  // Run all tests
  const results = await runAllTests();

  // Print stdout summary
  printSummary(results);

  // Write ADVERSARIAL_REPORT.md
  const reportPath = path.join(outputDir, 'ADVERSARIAL_REPORT.md');
  const reportContent = generateReport(results);
  fs.writeFileSync(reportPath, reportContent, 'utf-8');
  console.log(`✓ Wrote ${reportPath}`);

  // Final integrity check
  verifyResultsJsonUntouched(outputDir);
  console.log('');
  console.log('Adversarial test run complete.');
  console.log('');
}

main().catch((err: unknown) => {
  console.error('Adversarial runner error:', err);
  process.exit(1);
});
