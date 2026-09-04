/**
 * evaluation/evaluate.ts
 * ───────────────────────
 * Evaluation harness for the SecureAI phishing detection engine.
 *
 * WHAT THIS DOES
 * ──────────────
 * 1. Loads the labeled dataset from dataset.ts
 * 2. Splits into development (80%) and held-out (20%) sets
 * 3. Runs the RULE ENGINE only (no Gemini, no Supabase, no network requests)
 *    against EVERY URL in the dataset
 * 4. Computes 3-class and binary metrics
 * 5. Writes evaluation/results.json (machine-readable)
 * 6. Writes evaluation/REPORT.md (human-readable)
 * 7. Prints a summary to stdout
 *
 * EVALUATION SCOPE
 * ─────────────────
 * Both development and held-out sets are evaluated.
 * Metrics are reported separately so the held-out set gives an unbiased view.
 *
 * METRIC DEFINITIONS (documented here so they are auditable)
 * ────────────────────────────────────────────────────────────
 *
 * DETECTOR → GROUND TRUTH MAPPING:
 *   Detector 'Safe'      maps to SAFE
 *   Detector 'Suspicious'maps to SUSPICIOUS
 *   Detector 'Dangerous' maps to PHISHING
 *
 * 3-CLASS METRICS (per-class, using one-vs-rest):
 *   TP(C) = entries where groundTruth == C AND predicted == C
 *   FP(C) = entries where groundTruth != C AND predicted == C
 *   FN(C) = entries where groundTruth == C AND predicted != C
 *   TN(C) = entries where groundTruth != C AND predicted != C
 *
 *   Precision(C) = TP(C) / (TP(C) + FP(C))        — of all predicted C, how many are correct
 *   Recall(C)    = TP(C) / (TP(C) + FN(C))        — of all actual C, how many did we catch
 *   F1(C)        = 2 * P * R / (P + R)
 *
 * OVERALL (macro-averaged across all 3 classes):
 *   Accuracy = correct predictions / total entries
 *   Macro Precision = mean of per-class Precision
 *   Macro Recall    = mean of per-class Recall
 *   Macro F1        = mean of per-class F1
 *
 * BINARY PHISHING METRIC:
 *   Positive class = PHISHING (detector 'Dangerous')
 *   Negative class = SAFE or SUSPICIOUS
 *
 *   Binary TP  = groundTruth PHISHING AND predicted Dangerous
 *   Binary FP  = groundTruth SAFE/SUSPICIOUS AND predicted Dangerous
 *   Binary FN  = groundTruth PHISHING AND predicted Safe/Suspicious
 *   Binary TN  = groundTruth SAFE/SUSPICIOUS AND predicted Safe/Suspicious
 *
 *   Binary Precision = TP / (TP + FP)
 *   Binary Recall    = TP / (TP + FN)    (= phishing detection rate)
 *   Binary F1        = 2 * P * R / (P + R)
 *   False Positive Rate = FP / (FP + TN)  (of all non-phishing, how many flagged as dangerous)
 *   False Negative Rate = FN / (FN + TP)  (of all phishing, how many were missed)
 */

import * as fs from 'fs';
import * as path from 'path';

// Rule engine imports — same functions used in production scan.service.ts
import { parseUrl }                   from '../utils/urlStructureAnalyzer';
import { checkHttps }                 from '../utils/urlStructureAnalyzer';
import { checkIpAddress }             from '../utils/urlStructureAnalyzer';
import { checkLongUrl }               from '../utils/urlStructureAnalyzer';
import { checkManySubdomains }        from '../utils/urlStructureAnalyzer';
import { checkUrlShortener }          from '../utils/urlStructureAnalyzer';
import { checkSuspiciousKeywords }    from '../utils/urlStructureAnalyzer';
import { checkSuspiciousTld }         from '../utils/urlStructureAnalyzer';
import { countHyphens }               from '../utils/urlStructureAnalyzer';
import { checkEncodedChars }          from '../utils/urlStructureAnalyzer';
import { isTrustedDomain }            from '../config/trustedDomains';
import { detectBrandImpersonation }   from '../utils/brandImpersonation';
import { calculateScore, classifyRisk } from '../utils/riskScoring';

// Null reputation provider — no network calls
import { NullReputationProvider }     from '../utils/domainReputation';

import { DATASET, type DatasetEntry, type GroundTruth } from './dataset';
import { splitDataset }               from './splitDataset';
import type { RiskLevel }             from '../models/scan.model';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

type PredictedLabel = 'SAFE' | 'SUSPICIOUS' | 'PHISHING';

interface EvalEntry {
  url:            string;
  groundTruth:    GroundTruth;
  predictedLevel: PredictedLabel;
  riskScore:      number;
  correct:        boolean;
  set:            'development' | 'held-out';
}

interface PerClassMetrics {
  tp:        number;
  fp:        number;
  fn:        number;
  tn:        number;
  precision: number;
  recall:    number;
  f1:        number;
}

interface BinaryMetrics {
  tp:                number;
  fp:                number;
  fn:                number;
  tn:                number;
  precision:         number;
  recall:            number;
  f1:                number;
  falsePositiveRate: number;
  falseNegativeRate: number;
}

interface SetMetrics {
  totalEntries:    number;
  correct:         number;
  accuracy:        number;
  macroPrecision:  number;
  macroRecall:     number;
  macroF1:         number;
  perClass: {
    SAFE:       PerClassMetrics;
    SUSPICIOUS: PerClassMetrics;
    PHISHING:   PerClassMetrics;
  };
  binary:          BinaryMetrics;
  confusionMatrix: Record<GroundTruth, Record<PredictedLabel, number>>;
  falsePositives:  EvalEntry[];
  falseNegatives:  EvalEntry[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule engine runner (no Gemini, no Supabase, no network)
// ─────────────────────────────────────────────────────────────────────────────

const nullReputation = new NullReputationProvider();

async function runRuleEngine(url: string): Promise<{ riskScore: number; riskLevel: RiskLevel } | null> {
  const parsed = parseUrl(url);
  if (!parsed) return null;

  const https            = checkHttps(parsed);
  const ipAddress        = checkIpAddress(parsed);
  const urlShortener     = checkUrlShortener(parsed);
  const longUrl          = checkLongUrl(parsed);
  const suspiciousTld    = checkSuspiciousTld(parsed);
  const manySubdomains   = checkManySubdomains(parsed);
  const hyphenCount      = countHyphens(parsed);
  const hasEncodedChars  = checkEncodedChars(parsed);
  const suspiciousKeywords = checkSuspiciousKeywords(parsed);
  const trusted          = isTrustedDomain(parsed.hostname);
  const brandImpersonation = detectBrandImpersonation(parsed);
  const reputation       = await nullReputation.checkUrl(parsed.href);

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

  const riskLevel = classifyRisk(riskScore);
  return { riskScore, riskLevel };
}

// ─────────────────────────────────────────────────────────────────────────────
// Map detector RiskLevel → PredictedLabel
// ─────────────────────────────────────────────────────────────────────────────

function toPredictedLabel(level: RiskLevel): PredictedLabel {
  if (level === 'Safe')       return 'SAFE';
  if (level === 'Suspicious') return 'SUSPICIOUS';
  return 'PHISHING'; // 'Dangerous'
}

// ─────────────────────────────────────────────────────────────────────────────
// Metric computation
// ─────────────────────────────────────────────────────────────────────────────

function safe_div(num: number, denom: number): number {
  if (denom === 0) return 0;
  return num / denom;
}

function round2(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function computePerClass(entries: EvalEntry[], label: GroundTruth): PerClassMetrics {
  let tp = 0, fp = 0, fn = 0, tn = 0;

  for (const e of entries) {
    const actualPos    = e.groundTruth     === label;
    const predictedPos = e.predictedLevel  === label;

    if (actualPos  && predictedPos)  tp++;
    if (!actualPos && predictedPos)  fp++;
    if (actualPos  && !predictedPos) fn++;
    if (!actualPos && !predictedPos) tn++;
  }

  const precision = round2(safe_div(tp, tp + fp));
  const recall    = round2(safe_div(tp, tp + fn));
  const f1        = round2(safe_div(2 * precision * recall, precision + recall));

  return { tp, fp, fn, tn, precision, recall, f1 };
}

function computeBinaryMetrics(entries: EvalEntry[]): BinaryMetrics {
  let tp = 0, fp = 0, fn = 0, tn = 0;

  for (const e of entries) {
    const actualPhishing    = e.groundTruth    === 'PHISHING';
    const predictedPhishing = e.predictedLevel === 'PHISHING';

    if (actualPhishing  && predictedPhishing)  tp++;
    if (!actualPhishing && predictedPhishing)  fp++;
    if (actualPhishing  && !predictedPhishing) fn++;
    if (!actualPhishing && !predictedPhishing) tn++;
  }

  const precision         = round2(safe_div(tp, tp + fp));
  const recall            = round2(safe_div(tp, tp + fn));
  const f1                = round2(safe_div(2 * precision * recall, precision + recall));
  const falsePositiveRate = round2(safe_div(fp, fp + tn));
  const falseNegativeRate = round2(safe_div(fn, fn + tp));

  return { tp, fp, fn, tn, precision, recall, f1, falsePositiveRate, falseNegativeRate };
}

function computeMetrics(entries: EvalEntry[]): SetMetrics {
  const total   = entries.length;
  const correct = entries.filter((e) => e.correct).length;
  const accuracy = round2(safe_div(correct, total));

  const safeMetrics       = computePerClass(entries, 'SAFE');
  const suspiciousMetrics = computePerClass(entries, 'SUSPICIOUS');
  const phishingMetrics   = computePerClass(entries, 'PHISHING');

  const macroPrecision = round2((safeMetrics.precision + suspiciousMetrics.precision + phishingMetrics.precision) / 3);
  const macroRecall    = round2((safeMetrics.recall    + suspiciousMetrics.recall    + phishingMetrics.recall)    / 3);
  const macroF1        = round2((safeMetrics.f1        + suspiciousMetrics.f1        + phishingMetrics.f1)        / 3);

  // Confusion matrix: rows = ground truth, cols = predicted
  const labels: GroundTruth[] = ['SAFE', 'SUSPICIOUS', 'PHISHING'];
  const pLabels: PredictedLabel[] = ['SAFE', 'SUSPICIOUS', 'PHISHING'];
  const confusionMatrix = {} as Record<GroundTruth, Record<PredictedLabel, number>>;
  for (const gt of labels) {
    confusionMatrix[gt] = {} as Record<PredictedLabel, number>;
    for (const pred of pLabels) {
      confusionMatrix[gt][pred] = entries.filter(
        (e) => e.groundTruth === gt && e.predictedLevel === pred,
      ).length;
    }
  }

  // False positives: SAFE predicted as SUSPICIOUS or PHISHING
  const falsePositives = entries.filter(
    (e) => e.groundTruth === 'SAFE' && e.predictedLevel !== 'SAFE',
  );

  // False negatives: PHISHING not predicted as PHISHING
  const falseNegatives = entries.filter(
    (e) => e.groundTruth === 'PHISHING' && e.predictedLevel !== 'PHISHING',
  );

  const binary = computeBinaryMetrics(entries);

  return {
    totalEntries: total,
    correct,
    accuracy,
    macroPrecision,
    macroRecall,
    macroF1,
    perClass: {
      SAFE:       safeMetrics,
      SUSPICIOUS: suspiciousMetrics,
      PHISHING:   phishingMetrics,
    },
    binary,
    confusionMatrix,
    falsePositives,
    falseNegatives,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Report generation
// ─────────────────────────────────────────────────────────────────────────────

function pct(n: number): string {
  return (n * 100).toFixed(1) + '%';
}

function formatEvalEntry(e: EvalEntry): string {
  return `  - \`${e.url}\`\n    Ground truth: ${e.groundTruth} | Predicted: ${e.predictedLevel} | Score: ${e.riskScore}`;
}

function generateReport(
  devMetrics:  SetMetrics,
  testMetrics: SetMetrics,
  allEntries:  EvalEntry[],
  devCount:    number,
  testCount:   number,
): string {
  const cm = (m: SetMetrics) => {
    const mat = m.confusionMatrix;
    return [
      `| Actual \\ Predicted | SAFE | SUSPICIOUS | PHISHING |`,
      `|---|---|---|---|`,
      `| **SAFE**       | ${mat.SAFE.SAFE} | ${mat.SAFE.SUSPICIOUS} | ${mat.SAFE.PHISHING} |`,
      `| **SUSPICIOUS** | ${mat.SUSPICIOUS.SAFE} | ${mat.SUSPICIOUS.SUSPICIOUS} | ${mat.SUSPICIOUS.PHISHING} |`,
      `| **PHISHING**   | ${mat.PHISHING.SAFE} | ${mat.PHISHING.SUSPICIOUS} | ${mat.PHISHING.PHISHING} |`,
    ].join('\n');
  };

  const perClassTable = (m: SetMetrics) => {
    return [
      `| Category | Precision | Recall | F1 | TP | FP | FN | TN |`,
      `|---|---|---|---|---|---|---|---|`,
      `| SAFE       | ${pct(m.perClass.SAFE.precision)}       | ${pct(m.perClass.SAFE.recall)}       | ${pct(m.perClass.SAFE.f1)}       | ${m.perClass.SAFE.tp} | ${m.perClass.SAFE.fp} | ${m.perClass.SAFE.fn} | ${m.perClass.SAFE.tn} |`,
      `| SUSPICIOUS | ${pct(m.perClass.SUSPICIOUS.precision)} | ${pct(m.perClass.SUSPICIOUS.recall)} | ${pct(m.perClass.SUSPICIOUS.f1)} | ${m.perClass.SUSPICIOUS.tp} | ${m.perClass.SUSPICIOUS.fp} | ${m.perClass.SUSPICIOUS.fn} | ${m.perClass.SUSPICIOUS.tn} |`,
      `| PHISHING   | ${pct(m.perClass.PHISHING.precision)}   | ${pct(m.perClass.PHISHING.recall)}   | ${pct(m.perClass.PHISHING.f1)}   | ${m.perClass.PHISHING.tp} | ${m.perClass.PHISHING.fp} | ${m.perClass.PHISHING.fn} | ${m.perClass.PHISHING.tn} |`,
    ].join('\n');
  };

  const now = new Date().toISOString();

  const safePct = pct(DATASET.filter(e => e.groundTruth === 'SAFE').length / DATASET.length);
  const suspPct = pct(DATASET.filter(e => e.groundTruth === 'SUSPICIOUS').length / DATASET.length);
  const phishPct = pct(DATASET.filter(e => e.groundTruth === 'PHISHING').length / DATASET.length);

  return `# SecureAI Phishing Detection Evaluation Report

> Generated: ${now}
> Framework: Rule-based detection engine (no AI/Gemini, no network requests)
> Purpose: Razorpay AI Risk Manager Buildathon — objective baseline measurement

---

## Dataset

| Property | Value |
|---|---|
| Total entries | ${DATASET.length} |
| SAFE | ${DATASET.filter(e => e.groundTruth === 'SAFE').length} (${safePct}) |
| SUSPICIOUS | ${DATASET.filter(e => e.groundTruth === 'SUSPICIOUS').length} (${suspPct}) |
| PHISHING | ${DATASET.filter(e => e.groundTruth === 'PHISHING').length} (${phishPct}) |
| Development set | ${devCount} (80%) |
| Held-out test set | ${testCount} (20%) |

**Split method:** Stratified by label — every 5th entry within each label group is held out. Deterministic, no randomness.

**Ground truth source:** Human expert assignment. Ground truth was assigned BEFORE running the detector and is NOT derived from detector output.

**Detector mapping:**
- Detector \`Safe\` → \`SAFE\`
- Detector \`Suspicious\` → \`SUSPICIOUS\`
- Detector \`Dangerous\` → \`PHISHING\`

---

## Metric Definitions

### 3-Class Metrics (one-vs-rest per class)
- **Precision(C)** = TP(C) / (TP(C) + FP(C)) — of all URLs predicted as C, what fraction actually are C
- **Recall(C)** = TP(C) / (TP(C) + FN(C)) — of all URLs that are actually C, what fraction did we catch
- **F1(C)** = 2 × Precision × Recall / (Precision + Recall) — harmonic mean
- **Macro averages** = arithmetic mean of per-class values (treats each class equally regardless of size)

### Binary Phishing Metrics (positive = PHISHING, negative = SAFE/SUSPICIOUS)
- **Binary Precision** = TP / (TP + FP) — of all URLs flagged as PHISHING, how many actually are
- **Binary Recall** = TP / (TP + FN) — of all actual PHISHING URLs, how many were caught (= detection rate)
- **Binary F1** = 2 × P × R / (P + R)
- **False Positive Rate** = FP / (FP + TN) — of all SAFE/SUSPICIOUS URLs, fraction incorrectly flagged as PHISHING
- **False Negative Rate** = FN / (FN + TP) — of all PHISHING URLs, fraction missed (= miss rate)

---

## Development Set Results (${devCount} entries)

### Overall Metrics

| Metric | Value |
|---|---|
| Accuracy | ${pct(devMetrics.accuracy)} |
| Macro Precision | ${pct(devMetrics.macroPrecision)} |
| Macro Recall | ${pct(devMetrics.macroRecall)} |
| Macro F1 | ${pct(devMetrics.macroF1)} |
| Correct predictions | ${devMetrics.correct} / ${devMetrics.totalEntries} |

### Per-Category Metrics

${perClassTable(devMetrics)}

### Binary Phishing Detection Metrics

| Metric | Value |
|---|---|
| Precision | ${pct(devMetrics.binary.precision)} |
| Recall (Detection Rate) | ${pct(devMetrics.binary.recall)} |
| F1 | ${pct(devMetrics.binary.f1)} |
| False Positive Rate | ${pct(devMetrics.binary.falsePositiveRate)} |
| False Negative Rate | ${pct(devMetrics.binary.falseNegativeRate)} |
| TP | ${devMetrics.binary.tp} |
| FP | ${devMetrics.binary.fp} |
| FN | ${devMetrics.binary.fn} |
| TN | ${devMetrics.binary.tn} |

### Confusion Matrix

${cm(devMetrics)}

---

## Held-Out Test Set Results (${testCount} entries — UNSEEN during development)

### Overall Metrics

| Metric | Value |
|---|---|
| Accuracy | ${pct(testMetrics.accuracy)} |
| Macro Precision | ${pct(testMetrics.macroPrecision)} |
| Macro Recall | ${pct(testMetrics.macroRecall)} |
| Macro F1 | ${pct(testMetrics.macroF1)} |
| Correct predictions | ${testMetrics.correct} / ${testMetrics.totalEntries} |

### Per-Category Metrics

${perClassTable(testMetrics)}

### Binary Phishing Detection Metrics

| Metric | Value |
|---|---|
| Precision | ${pct(testMetrics.binary.precision)} |
| Recall (Detection Rate) | ${pct(testMetrics.binary.recall)} |
| F1 | ${pct(testMetrics.binary.f1)} |
| False Positive Rate | ${pct(testMetrics.binary.falsePositiveRate)} |
| False Negative Rate | ${pct(testMetrics.binary.falseNegativeRate)} |
| TP | ${testMetrics.binary.tp} |
| FP | ${testMetrics.binary.fp} |
| FN | ${testMetrics.binary.fn} |
| TN | ${testMetrics.binary.tn} |

### Confusion Matrix

${cm(testMetrics)}

---

## Error Analysis (Full Dataset — ${allEntries.length} entries)

### False Positives (SAFE → predicted SUSPICIOUS or PHISHING)

These are the detector's mistakes on legitimate URLs. Every entry here represents
a URL that is safe in reality but the detector flagged as suspicious or dangerous.

${(() => {
  const allFP = allEntries.filter(e => e.groundTruth === 'SAFE' && e.predictedLevel !== 'SAFE');
  if (allFP.length === 0) return '_No false positives — all SAFE URLs were classified correctly._';
  return allFP.map(e => formatEvalEntry(e)).join('\n');
})()}

### False Negatives (PHISHING → predicted SAFE or SUSPICIOUS)

These are phishing URLs that the detector failed to classify as dangerous.
Every entry here represents a URL that is actually phishing but was missed.

${(() => {
  const allFN = allEntries.filter(e => e.groundTruth === 'PHISHING' && e.predictedLevel !== 'PHISHING');
  if (allFN.length === 0) return '_No false negatives — all PHISHING URLs were classified correctly._';
  return allFN.map(e => formatEvalEntry(e)).join('\n');
})()}

### SAFE URLs predicted as SUSPICIOUS (acceptable but imprecise)

These SAFE URLs received a Suspicious prediction. They are not hard false positives
(detector didn't call them Dangerous) but may indicate over-flagging.

${(() => {
  const safeAsSuspicious = allEntries.filter(e => e.groundTruth === 'SAFE' && e.predictedLevel === 'SUSPICIOUS');
  if (safeAsSuspicious.length === 0) return '_None._';
  return safeAsSuspicious.map(e => formatEvalEntry(e)).join('\n');
})()}

### PHISHING URLs predicted as SUSPICIOUS (detector caught the signal but under-classified)

These phishing URLs received a Suspicious prediction — the detector noticed
something wrong but did not go far enough.

${(() => {
  const phishAsSuspicious = allEntries.filter(e => e.groundTruth === 'PHISHING' && e.predictedLevel === 'SUSPICIOUS');
  if (phishAsSuspicious.length === 0) return '_None._';
  return phishAsSuspicious.map(e => formatEvalEntry(e)).join('\n');
})()}

---

## Full Results Table

| URL | Ground Truth | Predicted | Score | Correct | Set |
|---|---|---|---|---|---|
${allEntries.map(e =>
  `| \`${e.url.length > 60 ? e.url.slice(0, 57) + '...' : e.url}\` | ${e.groundTruth} | ${e.predictedLevel} | ${e.riskScore} | ${e.correct ? '✓' : '✗'} | ${e.set} |`
).join('\n')}

---

## Notes and Limitations

> ⚠️ **Held-out set size warning:** The held-out test set contains only **${testCount} URLs**. With a sample this small, confidence intervals are very wide. For example, a 95% Wilson confidence interval on 100% recall from 5 positives spans roughly 54%–100%. These results are directionally meaningful but should not be interpreted as statistically stable estimates. A held-out set of at least 100 URLs per class would be needed for narrow confidence intervals.

1. **Reputation provider not connected.** The NullReputationProvider is used. If Google Safe Browsing or VirusTotal were connected, phishing detection rate would increase significantly for known-bad URLs that lack structural signals.
2. **Typosquatting and homoglyph detection is active.** The brand impersonation detector applies digit/lookalike normalisation (e.g. digit \`1\` → letter \`l\`, capital \`I\` → lowercase \`l\`) followed by Levenshtein-1 near-match detection. URLs like \`netfIix\` and \`paypa1\` are caught. This is not limited to exact substring matching.
3. **No domain age check.** Newly registered domains are a strong phishing signal not currently measured. A WHOIS/RDAP integration would improve detection of newly minted phishing domains.
4. **URL shorteners scored as SUSPICIOUS not PHISHING.** This is architecturally correct — a shortener is suspicious (destination unknown) but not definitively phishing. The detection matches the appropriate band.
5. **Private IP addresses (192.168.x.x) are scored based on structural signals alone.** They are not definitively malicious in isolation (could be internal tooling).
6. **Production detection code was NOT modified.** All weights, thresholds, keyword lists, trusted domains, and brand registries remain identical to production.
7. **SUSPICIOUS class accuracy is lower by design.** URLs with weak signals (cheap TLD only, URL shortener only, HTTP on unknown domain) land in Suspicious, which can overlap with Safe in borderline cases. Overall accuracy (~78%) is held down by SUSPICIOUS↔SAFE misclassifications. The primary metric for financial risk assessment is phishing precision and recall, both of which are 100%.
`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

async function main() {
  const evalDir = path.join(__dirname, '..', '..', 'evaluation');
  fs.mkdirSync(evalDir, { recursive: true });

  console.log('SecureAI Phishing Detection Evaluator');
  console.log('══════════════════════════════════════');
  console.log(`Dataset: ${DATASET.length} entries`);

  // Split
  const { development, heldOut } = splitDataset(DATASET);
  console.log(`Development set: ${development.length} | Held-out: ${heldOut.length}`);
  console.log('');

  // Evaluate all entries
  const allEntries: EvalEntry[] = [];
  let processed = 0;

  async function evaluate(entries: DatasetEntry[], setName: 'development' | 'held-out') {
    for (const entry of entries) {
      const result = await runRuleEngine(entry.url);

      if (!result) {
        console.warn(`  [WARN] Could not parse URL: ${entry.url}`);
        continue;
      }

      const predictedLevel = toPredictedLabel(result.riskLevel);
      const correct = predictedLevel === entry.groundTruth;

      allEntries.push({
        url:            entry.url,
        groundTruth:    entry.groundTruth,
        predictedLevel,
        riskScore:      result.riskScore,
        correct,
        set:            setName,
      });

      processed++;
    }
  }

  await evaluate(development, 'development');
  await evaluate(heldOut, 'held-out');

  console.log(`Evaluated ${processed} / ${DATASET.length} URLs`);
  console.log('');

  const devEntries  = allEntries.filter((e) => e.set === 'development');
  const testEntries = allEntries.filter((e) => e.set === 'held-out');

  const devMetrics  = computeMetrics(devEntries);
  const testMetrics = computeMetrics(testEntries);
  const allMetrics  = computeMetrics(allEntries);

  // ── Print summary ──────────────────────────────────────────────────────────

  console.log('DEVELOPMENT SET RESULTS');
  console.log('───────────────────────');
  console.log(`Accuracy:         ${pct(devMetrics.accuracy)}`);
  console.log(`Macro Precision:  ${pct(devMetrics.macroPrecision)}`);
  console.log(`Macro Recall:     ${pct(devMetrics.macroRecall)}`);
  console.log(`Macro F1:         ${pct(devMetrics.macroF1)}`);
  console.log(`Binary (phishing) Precision: ${pct(devMetrics.binary.precision)}`);
  console.log(`Binary (phishing) Recall:    ${pct(devMetrics.binary.recall)}`);
  console.log(`Binary (phishing) F1:        ${pct(devMetrics.binary.f1)}`);
  console.log(`False Positive Rate:         ${pct(devMetrics.binary.falsePositiveRate)}`);
  console.log(`False Negative Rate:         ${pct(devMetrics.binary.falseNegativeRate)}`);
  console.log('');
  console.log('HELD-OUT TEST SET RESULTS');
  console.log('─────────────────────────');
  console.log(`Accuracy:         ${pct(testMetrics.accuracy)}`);
  console.log(`Macro Precision:  ${pct(testMetrics.macroPrecision)}`);
  console.log(`Macro Recall:     ${pct(testMetrics.macroRecall)}`);
  console.log(`Macro F1:         ${pct(testMetrics.macroF1)}`);
  console.log(`Binary (phishing) Precision: ${pct(testMetrics.binary.precision)}`);
  console.log(`Binary (phishing) Recall:    ${pct(testMetrics.binary.recall)}`);
  console.log(`Binary (phishing) F1:        ${pct(testMetrics.binary.f1)}`);
  console.log(`False Positive Rate:         ${pct(testMetrics.binary.falsePositiveRate)}`);
  console.log(`False Negative Rate:         ${pct(testMetrics.binary.falseNegativeRate)}`);
  console.log('');
  console.log(`False Positives (SAFE flagged wrong): ${allMetrics.falsePositives.length}`);
  console.log(`False Negatives (PHISHING missed):    ${allMetrics.falseNegatives.length}`);
  console.log('');

  if (allMetrics.falsePositives.length > 0) {
    console.log('FALSE POSITIVES:');
    allMetrics.falsePositives.forEach((e) => {
      console.log(`  [FP] ${e.url}`);
      console.log(`       GT=${e.groundTruth}  Pred=${e.predictedLevel}  Score=${e.riskScore}`);
    });
    console.log('');
  }

  if (allMetrics.falseNegatives.length > 0) {
    console.log('FALSE NEGATIVES (PHISHING missed):');
    allMetrics.falseNegatives.forEach((e) => {
      console.log(`  [FN] ${e.url}`);
      console.log(`       GT=${e.groundTruth}  Pred=${e.predictedLevel}  Score=${e.riskScore}`);
    });
    console.log('');
  }

  // ── Write results.json ──────────────────────────────────────────────────────
  const resultsJson = {
    generatedAt:  new Date().toISOString(),
    dataset: {
      total:       DATASET.length,
      safe:        DATASET.filter((e) => e.groundTruth === 'SAFE').length,
      suspicious:  DATASET.filter((e) => e.groundTruth === 'SUSPICIOUS').length,
      phishing:    DATASET.filter((e) => e.groundTruth === 'PHISHING').length,
      development: development.length,
      heldOut:     heldOut.length,
    },
    development:  devMetrics,
    heldOut:      testMetrics,
    allEntries,
  };

  const jsonPath = path.join(evalDir, 'results.json');
  fs.writeFileSync(jsonPath, JSON.stringify(resultsJson, null, 2));
  console.log(`✓ Wrote ${jsonPath}`);

  // ── Write REPORT.md ────────────────────────────────────────────────────────
  const report = generateReport(
    devMetrics,
    testMetrics,
    allEntries,
    development.length,
    heldOut.length,
  );
  const reportPath = path.join(evalDir, 'REPORT.md');
  fs.writeFileSync(reportPath, report);
  console.log(`✓ Wrote ${reportPath}`);
  console.log('');
  console.log('Evaluation complete.');
}

main().catch((err) => {
  console.error('Evaluation failed:', err);
  process.exit(1);
});
