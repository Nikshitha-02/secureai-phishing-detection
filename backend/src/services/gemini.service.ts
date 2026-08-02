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
// Provider interface
// ─────────────────────────────────────────────────────────────────────────────

export interface IAiExplainer {
  generateExplanation(scanResult: ScanResponse): Promise<string>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

export const AI_UNAVAILABLE_MESSAGE = 'AI explanation is temporarily unavailable.';

const GEMINI_ENDPOINT_BASE = 'https://generativelanguage.googleapis.com';

// ─────────────────────────────────────────────────────────────────────────────
// Error classifier
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Extracts the fullest possible diagnostic from any thrown value and logs it.
 * Returns a short human-readable reason string for callers.
 */
function logAndClassifyError(context: string, err: unknown): string {
  const e = err as Record<string, unknown>;
  const name    = String(e?.name    ?? 'UnknownError');
  const message = String(e?.message ?? err);
  const cause   = e?.cause as Record<string, unknown> | undefined;
  const status  = (e?.status as number | undefined) ??
                  (e?.httpStatus as number | undefined) ??
                  (cause?.status as number | undefined);

  // Full dump — always print so nothing is hidden
  console.error(`[${context}] ─── ERROR ───────────────────────────────`);
  console.error(`  name      : ${name}`);
  console.error(`  message   : ${message}`);
  console.error(`  HTTP status: ${status ?? '(not available)'}`);

  if (cause) {
    console.error(`  cause.name   : ${cause.name ?? '—'}`);
    console.error(`  cause.message: ${cause.message ?? '—'}`);
    console.error(`  cause.code   : ${cause.code ?? '—'}`);
  }

  // Stack — trim to first 6 frames to keep logs readable
  const stack = String(e?.stack ?? '');
  if (stack) {
    console.error(`  stack (first 6 lines):`);
    stack.split('\n').slice(0, 6).forEach(l => console.error(`    ${l}`));
  }
  console.error(`[${context}] ────────────────────────────────────────`);

  // ── Classify into a short reason ─────────────────────────────────────────

  // 429 — quota exhausted (can be wrapped inside "fetch failed")
  if (message.includes('429') || message.includes('RESOURCE_EXHAUSTED') || message.includes('quota')) {
    console.error(
      `[${context}] DIAGNOSIS: Free-tier quota exhausted (429 RESOURCE_EXHAUSTED).\n` +
      `  The daily or per-minute request limit for model "${config.GEMINI_MODEL}" has been reached.\n` +
      `  Free-tier limits: https://ai.google.dev/gemini-api/docs/rate-limits\n` +
      `  Resolution: Wait for the quota to reset (daily limit resets at midnight US/Pacific),\n` +
      `              or upgrade to a paid API key, or switch to a model with remaining quota.`
    );
    return 'quota_exceeded';
  }

  // 404 — model not available for this key tier
  if (message.includes('404') || message.includes('no longer available')) {
    console.error(
      `[${context}] DIAGNOSIS: Model not found (404).\n` +
      `  Model "${config.GEMINI_MODEL}" is not available for this API key tier.\n` +
      `  Resolution: Change GEMINI_MODEL in backend/.env to a supported model.`
    );
    return 'model_not_found';
  }

  // 401 / 403 — bad API key
  if (message.includes('401') || message.includes('403') || message.includes('API_KEY') || message.includes('permission')) {
    console.error(
      `[${context}] DIAGNOSIS: Authentication failed (401/403).\n` +
      `  The GEMINI_API_KEY may be invalid, revoked, or missing required permissions.\n` +
      `  Resolution: Regenerate the key at https://aistudio.google.com/app/apikey`
    );
    return 'auth_failed';
  }

  // fetch failed / ECONNREFUSED / ENOTFOUND — network issues
  if (
    name === 'TypeError' && message.toLowerCase().includes('fetch') ||
    message.includes('ECONNREFUSED') ||
    message.includes('ENOTFOUND') ||
    message.includes('ECONNRESET') ||
    message.includes('ETIMEDOUT') ||
    (cause && String(cause.code).startsWith('E'))
  ) {
    const causeCode = cause?.code ?? cause?.message ?? 'unknown';
    console.error(
      `[${context}] DIAGNOSIS: Network / connectivity failure.\n` +
      `  The SDK could not reach ${GEMINI_ENDPOINT_BASE}\n` +
      `  Underlying cause: ${causeCode}\n` +
      `  Possible reasons:\n` +
      `    • No internet connection\n` +
      `    • DNS resolution failure (ENOTFOUND)\n` +
      `    • Firewall / corporate proxy blocking outbound HTTPS\n` +
      `    • VPN intercepting TLS (SSL certificate error)\n` +
      `    • Proxy not configured in NODE env (set HTTPS_PROXY if behind a proxy)\n` +
      `  Resolution: Test with: curl https://generativelanguage.googleapis.com`
    );
    return 'network_failure';
  }

  console.error(`[${context}] DIAGNOSIS: Unexpected error — see full dump above.`);
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
// Gemini implementation
// ─────────────────────────────────────────────────────────────────────────────

class GeminiExplainer implements IAiExplainer {
  private readonly model;
  private readonly modelName: string;

  constructor(apiKey: string, modelName: string) {
    const genAI = new GoogleGenerativeAI(apiKey);
    this.modelName = modelName;
    this.model = genAI.getGenerativeModel({ model: modelName });
  }

  async generateExplanation(scanResult: ScanResponse): Promise<string> {
    const prompt = buildExplanationPrompt(scanResult);

    try {
      const result = await this.model.generateContent(prompt);
      const text = result.response.text().trim();
      if (!text) return AI_UNAVAILABLE_MESSAGE;
      return text;
    } catch (err) {
      logAndClassifyError(`GeminiExplainer model=${this.modelName}`, err);
      return AI_UNAVAILABLE_MESSAGE;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// No-op explainer
// ─────────────────────────────────────────────────────────────────────────────

class NoopExplainer implements IAiExplainer {
  async generateExplanation(_scanResult: ScanResponse): Promise<string> {
    return AI_UNAVAILABLE_MESSAGE;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Startup health check
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Sends a tiny prompt to Gemini at startup to verify the full stack works:
 * API key → model → network → response.
 *
 * Does NOT throw — a health-check failure must never crash the server.
 * Result is purely informational; it does not affect request handling.
 */
export async function runGeminiHealthCheck(apiKey: string, modelName: string): Promise<void> {
  console.log(`[Gemini] Running startup health check (model: ${modelName}) ...`);

  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: modelName });
    const result = await model.generateContent('Reply with only the word: OK');
    const text = result.response.text().trim();

    if (text) {
      console.log(`[Gemini] ✓ Connection successful. Model response: "${text}"`);
    } else {
      console.warn(`[Gemini] ⚠ Health check got empty response — model may be degraded.`);
    }
  } catch (err) {
    const reason = logAndClassifyError('Gemini health check', err);

    // Print a final, action-oriented line based on classified reason
    const advice: Record<string, string> = {
      quota_exceeded:
        '⚠ Quota exhausted — AI explanations will return the fallback message until the quota resets. ' +
        'The rest of the API (rule engine, scan results) works normally.',
      model_not_found:
        '✗ Model unavailable — update GEMINI_MODEL in backend/.env to a supported model.',
      auth_failed:
        '✗ Authentication failed — regenerate GEMINI_API_KEY at https://aistudio.google.com/app/apikey',
      network_failure:
        '✗ Network failure — check internet access and firewall. ' +
        'Test with: curl https://generativelanguage.googleapis.com',
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
    return new GeminiExplainer(config.GEMINI_API_KEY, config.GEMINI_MODEL);
  }

  console.warn(
    '[gemini.service] GEMINI_API_KEY not set — AI explanations disabled. ' +
    'Add GEMINI_API_KEY to .env to enable.',
  );
  return new NoopExplainer();
}

export async function generateExplanation(scanResult: ScanResponse): Promise<string> {
  const explainer = getAiExplainer();
  return explainer.generateExplanation(scanResult);
}
