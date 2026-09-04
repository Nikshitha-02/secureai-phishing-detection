/**
 * services/gemini.service.ts
 * ──────────────────────────
 * AI explanation layer — the only file that talks to Google Gemini.
 *
 * Responsibility:
 *   Given a completed scan result (produced entirely by the rule engine),
 *   ask Gemini to explain it in plain human language.
 *
 * Gemini's role is PURELY explanatory.
 * It does NOT decide whether a URL is phishing.
 * The rule engine's verdict (riskLevel, riskScore) is the source of truth.
 *
 * ─── Failure handling ────────────────────────────────────────────────────────
 * Every possible Gemini failure mode is handled gracefully:
 *   - 400, 401, 403, 404, 429, 500, 502, 503  → deterministic fallback
 *   - Network error / ECONNRESET / ENOTFOUND   → deterministic fallback
 *   - Timeout (GEMINI_TIMEOUT_MS)              → deterministic fallback
 *   - Empty response                           → deterministic fallback
 *   - Any unexpected thrown value              → deterministic fallback
 *
 * In every failure case:
 *   • POST /api/scan returns HTTP 200 with the full security result
 *   • aiExplanation is a useful dynamic description (not a static error string)
 *   • aiExplanationProvider = "deterministic"
 *   • The scan result is persisted normally
 *   • The frontend NEVER times out waiting for Gemini
 *
 * ─── Timeout mechanism ───────────────────────────────────────────────────────
 * The Gemini SDK does not expose an AbortSignal option in all versions, so we
 * use Promise.race() with a timer promise.  The timer rejects after
 * GEMINI_TIMEOUT_MS milliseconds (default 5 000 ms), which causes the race to
 * settle on the fallback path immediately — the slow Gemini fetch continues
 * in the background but its result is discarded.
 *
 * ─── Swapping AI providers ───────────────────────────────────────────────────
 * To swap Gemini for another provider (OpenAI, Anthropic, Cohere…):
 *   1. Create a new class implementing IAiExplainer
 *   2. Change getAiExplainer() to return the new class
 *   3. No other files need to change
 */

import { GoogleGenerativeAI } from '@google/generative-ai';
import { config } from '../config/env';
import type { ScanResponse } from '../models/scan.model';

// ─────────────────────────────────────────────────────────────────────────────
// Provider types
// ─────────────────────────────────────────────────────────────────────────────

/** Which layer produced the explanation in the scan response. */
export type AiExplanationProvider = 'gemini' | 'deterministic';

export interface ExplanationResult {
  explanation: string;
  provider: AiExplanationProvider;
}

// ─────────────────────────────────────────────────────────────────────────────
// Provider interface
// ─────────────────────────────────────────────────────────────────────────────

export interface IAiExplainer {
  /** Never throws. Always returns a non-empty explanation + provider label. */
  generateExplanation(scanResult: ScanResponse): Promise<ExplanationResult>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Dynamic deterministic explanation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Builds a plain-language explanation from the rule-engine result.
 *
 * Used when Gemini is unavailable, too slow, or returns an error.
 * The text is fully dynamic — derived from the actual scan signals.
 * Never returns a generic "unavailable" message.
 */
export function buildDeterministicExplanation(scan: ScanResponse): string {
  const { riskLevel, riskScore, checks } = scan;

  // Collect the triggered signals in human-readable form
  const signals: string[] = [];

  if (checks.brandImpersonation) {
    signals.push(
      `the domain appears to impersonate the "${checks.brandImpersonation.brand}" brand`,
    );
  }
  if (checks.ipAddress) {
    signals.push('the hostname is a raw IP address rather than a registered domain name');
  }
  if (!checks.https) {
    signals.push('the connection is unencrypted (HTTP instead of HTTPS)');
  }
  if (checks.suspiciousTld) {
    signals.push('the top-level domain is associated with high-risk or abused registrations');
  }
  if (checks.urlShortener) {
    signals.push('the URL passes through a shortener service that hides the real destination');
  }
  if (checks.manySubdomains) {
    signals.push('the hostname uses excessive subdomain nesting');
  }
  if (checks.hyphenCount > 2) {
    signals.push(`the domain contains ${checks.hyphenCount} hyphens, a common pattern in machine-generated phishing domains`);
  }
  if (checks.hasEncodedChars) {
    signals.push('the URL contains percent-encoded characters that can be used to obfuscate malicious paths');
  }
  if (checks.suspiciousKeywords.length > 0) {
    const kws = checks.suspiciousKeywords.slice(0, 3).join(', ');
    signals.push(`the URL contains action-oriented keywords (${kws}) commonly used in phishing lures`);
  }
  if (checks.reputation.status === 'malicious') {
    signals.push(
      `the domain was flagged as malicious by ${checks.reputation.source ?? 'the reputation provider'}`,
    );
  }

  // Build the explanation text
  if (riskLevel === 'Safe') {
    if (signals.length === 0) {
      return (
        `SecureAI examined this URL and found no significant risk indicators. ` +
        `The domain is recognised as trusted, the connection uses HTTPS, and no ` +
        `suspicious patterns were detected. It is safe to proceed.`
      );
    }
    return (
      `SecureAI examined this URL and found only minor signals: ${signals.join('; ')}. ` +
      `The overall risk score is ${riskScore}/100, which falls within the safe range. ` +
      `No action is required, but you may wish to verify the destination.`
    );
  }

  if (signals.length === 0) {
    // Shouldn't happen — non-safe URLs always trigger at least one signal
    return (
      `SecureAI assigned a risk score of ${riskScore}/100 to this URL, ` +
      `placing it in the ${riskLevel} category. Exercise caution before proceeding.`
    );
  }

  const signalSummary =
    signals.length === 1
      ? signals[0]
      : signals.slice(0, -1).join('; ') + '; and ' + signals[signals.length - 1];

  if (riskLevel === 'Suspicious') {
    return (
      `SecureAI flagged this URL as Suspicious (score: ${riskScore}/100) because ` +
      `${signalSummary}. ` +
      `While not definitively malicious, these signals warrant caution. ` +
      `Verify the destination independently before entering any credentials or personal information.`
    );
  }

  // Dangerous
  return (
    `SecureAI classified this URL as Dangerous (score: ${riskScore}/100) because ` +
    `${signalSummary}. ` +
    `Do not enter any credentials, payment details, or personal information on this page. ` +
    `If you arrived here from an email or message, that communication may be a phishing attempt.`
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Error classifier (logging only — never affects the return path)
// ─────────────────────────────────────────────────────────────────────────────

function logAndClassifyError(context: string, err: unknown): string {
  const e = err as Record<string, unknown>;
  const name    = String(e?.name    ?? 'UnknownError');
  const message = String(e?.message ?? err);
  const cause   = e?.cause as Record<string, unknown> | undefined;
  const status  = (e?.status as number | undefined) ??
                  (e?.httpStatus as number | undefined) ??
                  (cause?.status as number | undefined);

  console.error(`[${context}] ─── ERROR ───────────────────────────────`);
  console.error(`  name      : ${name}`);
  console.error(`  message   : ${message}`);
  console.error(`  HTTP status: ${status ?? '(not available)'}`);
  if (cause) {
    console.error(`  cause.code: ${cause.code ?? '—'}`);
  }
  const stack = String(e?.stack ?? '');
  if (stack) {
    stack.split('\n').slice(0, 4).forEach(l => console.error(`    ${l}`));
  }
  console.error(`[${context}] ────────────────────────────────────────`);

  const msg = message + ' ' + String(cause?.code ?? '') + ' ' + String(cause?.message ?? '');

  if (name === 'GeminiTimeout') return 'timeout';
  if (msg.includes('429') || msg.includes('RESOURCE_EXHAUSTED') || msg.includes('quota')) return 'quota_exceeded';
  if (msg.includes('503') || msg.includes('Service Unavailable') || msg.includes('overloaded') || msg.includes('high demand')) return 'service_unavailable';
  if (msg.includes('502') || msg.includes('Bad Gateway'))    return 'bad_gateway';
  if (msg.includes('500'))                                   return 'server_error';
  if (msg.includes('404') || msg.includes('no longer available')) return 'model_not_found';
  if (msg.includes('401') || msg.includes('403') || msg.includes('API_KEY') || msg.includes('permission')) return 'auth_failed';
  if (msg.includes('400'))                                   return 'bad_request';
  if (
    (name === 'TypeError' && message.toLowerCase().includes('fetch')) ||
    msg.includes('ECONNREFUSED') || msg.includes('ENOTFOUND') ||
    msg.includes('ECONNRESET')  || msg.includes('ETIMEDOUT')
  ) return 'network_failure';

  return 'unknown';
}

// ─────────────────────────────────────────────────────────────────────────────
// Prompt builder
// ─────────────────────────────────────────────────────────────────────────────

export function buildExplanationPrompt(scan: ScanResponse): string {
  const { url, riskScore, riskLevel, checks, recommendations } = scan;

  const triggeredChecks: string[] = [];

  if (!checks.https)          triggeredChecks.push('Uses HTTP (not HTTPS) — connection is unencrypted');
  if (checks.ipAddress)       triggeredChecks.push('Hostname is a raw IP address');
  if (checks.urlShortener)    triggeredChecks.push('URL passes through a shortener service');
  if (checks.longUrl)         triggeredChecks.push('URL is unusually long');
  if (checks.suspiciousTld)   triggeredChecks.push('Uses a high-risk top-level domain');
  if (checks.manySubdomains)  triggeredChecks.push('Hostname has excessive subdomains');
  if (checks.hasEncodedChars) triggeredChecks.push('URL contains percent-encoded characters');
  if (checks.hyphenCount > 2) triggeredChecks.push(`Hostname has ${checks.hyphenCount} hyphens`);
  if (checks.suspiciousKeywords.length > 0) {
    triggeredChecks.push(
      `Contains phishing keywords: ${checks.suspiciousKeywords.slice(0, 4).join(', ')}`,
    );
  }
  if (checks.brandImpersonation) {
    triggeredChecks.push(
      `Appears to impersonate "${checks.brandImpersonation.brand}" brand`,
    );
  }
  if (checks.reputation.status === 'malicious') {
    triggeredChecks.push(
      `Flagged as malicious by ${checks.reputation.source ?? 'reputation provider'}`,
    );
  }

  const triggeredSection =
    triggeredChecks.length > 0
      ? triggeredChecks.map((c) => `- ${c}`).join('\n')
      : '- No significant checks triggered';

  const recommendationsSection =
    recommendations.length > 0
      ? recommendations.map((r) => `- ${r}`).join('\n')
      : '- None';

  return `You are a cybersecurity assistant. Analyze the following phishing scan result and explain it in clear, non-technical language for an everyday user.

SCAN RESULT:
URL: ${url}
Risk Score: ${riskScore} / 100
Risk Level: ${riskLevel}

Triggered Checks:
${triggeredSection}

Security Recommendations:
${recommendationsSection}

Instructions:
1. Explain WHY this URL is ${riskLevel === 'Safe' ? 'considered safe' : 'suspicious or dangerous'}.
2. Identify which triggered indicators are most dangerous (if any).
3. Describe what risks the user faces if they visit this URL.
4. Tell the user exactly what they should do next.

Rules:
- Keep your response under 150 words.
- Do NOT invent any facts. Only explain the scan results provided above.
- Write in plain English. No bullet points. Use flowing paragraphs.
- Do not repeat the URL or the risk score in your response.
- Be direct and helpful, not alarmist.`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Gemini implementation — with hard timeout + immediate fallback
// ─────────────────────────────────────────────────────────────────────────────

class GeminiExplainer implements IAiExplainer {
  private readonly model;
  private readonly modelName: string;
  private readonly timeoutMs: number;

  constructor(apiKey: string, modelName: string, timeoutMs: number) {
    const genAI = new GoogleGenerativeAI(apiKey);
    this.modelName = modelName;
    this.timeoutMs = timeoutMs;
    this.model = genAI.getGenerativeModel({ model: modelName });
  }

  async generateExplanation(scanResult: ScanResponse): Promise<ExplanationResult> {
    const prompt = buildExplanationPrompt(scanResult);
    const start = Date.now();

    try {
      // ── Hard timeout via Promise.race ─────────────────────────────────────
      // The Gemini SDK wraps the native fetch — we cannot inject an AbortSignal
      // through the public API in all SDK versions. Promise.race gives us a
      // reliable upper bound: if Gemini takes longer than timeoutMs the timeout
      // promise rejects first and we fall through to the deterministic path.
      // The underlying fetch continues in the background but its result is
      // discarded — it cannot affect the response we already sent.

      let timeoutHandle: ReturnType<typeof setTimeout> | undefined;

      const timeoutPromise = new Promise<never>((_resolve, reject) => {
        timeoutHandle = setTimeout(() => {
          const e = new Error(
            `Gemini did not respond within ${this.timeoutMs}ms — using deterministic fallback`,
          );
          e.name = 'GeminiTimeout';
          reject(e);
        }, this.timeoutMs);
      });

      const geminiPromise = this.model.generateContent(prompt);

      // Race: whichever settles first wins
      const result = await Promise.race([geminiPromise, timeoutPromise]);

      // Clear the timeout so the Node process is not kept alive by the timer
      if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);

      const elapsed = Date.now() - start;
      const text = result.response.text().trim();

      if (!text) {
        console.warn(
          `[GeminiExplainer] Empty response from model "${this.modelName}" ` +
          `(${elapsed}ms) — using deterministic fallback`,
        );
        return {
          explanation: buildDeterministicExplanation(scanResult),
          provider: 'deterministic',
        };
      }

      console.log(
        `[GeminiExplainer] ✓ Explanation received from "${this.modelName}" in ${elapsed}ms`,
      );
      return { explanation: text, provider: 'gemini' };

    } catch (err) {
      const elapsed = Date.now() - start;
      const reason = logAndClassifyError(
        `GeminiExplainer model=${this.modelName} (${elapsed}ms)`,
        err,
      );

      // Log a concise action line per failure type
      const advice: Record<string, string> = {
        timeout:          `⚠ Gemini timed out after ${elapsed}ms — deterministic fallback used.`,
        quota_exceeded:   '⚠ Gemini quota exhausted (429) — deterministic fallback used.',
        service_unavailable: '⚠ Gemini returned 503 (high demand) — deterministic fallback used immediately.',
        bad_gateway:      '⚠ Gemini returned 502 — deterministic fallback used.',
        server_error:     '⚠ Gemini returned 500 — deterministic fallback used.',
        model_not_found:  `✗ Model "${this.modelName}" not found (404) — update GEMINI_MODEL in .env.`,
        auth_failed:      '✗ Gemini auth failed (401/403) — check GEMINI_API_KEY.',
        bad_request:      '⚠ Gemini rejected the request (400) — deterministic fallback used.',
        network_failure:  '⚠ Gemini network failure — deterministic fallback used.',
        unknown:          '⚠ Unexpected Gemini error — deterministic fallback used.',
      };
      console.warn(`[GeminiExplainer] ${advice[reason] ?? advice.unknown}`);

      return {
        explanation: buildDeterministicExplanation(scanResult),
        provider: 'deterministic',
      };
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// No-op explainer (when API key not configured)
// ─────────────────────────────────────────────────────────────────────────────

class NoopExplainer implements IAiExplainer {
  async generateExplanation(scanResult: ScanResponse): Promise<ExplanationResult> {
    return {
      explanation: buildDeterministicExplanation(scanResult),
      provider: 'deterministic',
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Startup health check
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Sends a tiny prompt to Gemini at startup to verify API key + model.
 * Does NOT throw — health-check failure never crashes the server.
 * Uses its own short timeout to avoid blocking startup.
 */
export async function runGeminiHealthCheck(apiKey: string, modelName: string): Promise<void> {
  const HEALTH_TIMEOUT_MS = 8000; // generous for startup — not a user request
  console.log(`[Gemini] Running startup health check (model: ${modelName}) ...`);

  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: modelName });

    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    const timeoutPromise = new Promise<never>((_resolve, reject) => {
      timeoutHandle = setTimeout(() => {
        const e = new Error(`Health check timed out after ${HEALTH_TIMEOUT_MS}ms`);
        e.name = 'GeminiTimeout';
        reject(e);
      }, HEALTH_TIMEOUT_MS);
    });

    const result = await Promise.race([
      model.generateContent('Reply with only the word: OK'),
      timeoutPromise,
    ]);
    if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);

    const text = result.response.text().trim();
    if (text) {
      console.log(`[Gemini] ✓ Connection successful. Model response: "${text}"`);
    } else {
      console.warn(`[Gemini] ⚠ Health check got empty response — model may be degraded.`);
    }
  } catch (err) {
    const reason = logAndClassifyError('Gemini health check', err);

    const advice: Record<string, string> = {
      timeout:
        `⚠ Health check timed out — Gemini is reachable but slow. ` +
        `Scan explanations will use the deterministic fallback if Gemini exceeds ${config.GEMINI_TIMEOUT_MS}ms.`,
      quota_exceeded:
        '⚠ Quota exhausted — AI explanations will use the deterministic fallback until the quota resets. ' +
        'The rule engine, scan results, and persistence work normally.',
      service_unavailable:
        '⚠ Gemini returned 503 (high demand) — AI explanations will fall back to deterministic. ' +
        'The scanner itself is unaffected.',
      model_not_found:
        `✗ Model "${modelName}" not found (404) — update GEMINI_MODEL in backend/.env.`,
      auth_failed:
        '✗ Authentication failed — regenerate GEMINI_API_KEY at https://aistudio.google.com/app/apikey',
      network_failure:
        '✗ Network failure — check internet access. Test: curl https://generativelanguage.googleapis.com',
      unknown:
        '✗ Unexpected error — see full error dump above.',
    };
    console.warn(`[Gemini] ${advice[reason] ?? advice.unknown}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Factory
// ─────────────────────────────────────────────────────────────────────────────

export function getAiExplainer(): IAiExplainer {
  if (config.GEMINI_API_KEY) {
    return new GeminiExplainer(
      config.GEMINI_API_KEY,
      config.GEMINI_MODEL,
      config.GEMINI_TIMEOUT_MS,
    );
  }

  console.warn(
    '[gemini.service] GEMINI_API_KEY not set — using deterministic explanations. ' +
    'Add GEMINI_API_KEY to .env to enable Gemini.',
  );
  return new NoopExplainer();
}

/**
 * Convenience wrapper used by scan.service.ts.
 * Returns a full ExplanationResult (explanation + provider label).
 * Never throws.
 */
export async function generateExplanation(scanResult: ScanResponse): Promise<ExplanationResult> {
  const explainer = getAiExplainer();
  return explainer.generateExplanation(scanResult);
}
