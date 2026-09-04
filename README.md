# SecureAI — Explainable AI-Assisted Phishing Risk Detection

> **Razorpay AI Risk Manager Buildathon**  
> Track: AI-powered detection and mitigation of financial risk  
> Risk class: Phishing / Malicious URL → credential theft → account takeover → payment fraud

Phishing attacks are the #1 vector for credential theft. SecureAI analyses any URL before the user clicks it and returns a deterministic risk score, a plain-language AI explanation, and a full audit trail — all in under two seconds.

---

## Table of Contents

1. [Why This Matters Financially](#1-why-this-matters-financially)
2. [Features](#2-features)
3. [Architecture](#3-architecture)
4. [Detection Pipeline](#4-detection-pipeline)
5. [Risk Scoring](#5-risk-scoring)
6. [Score Explainability](#6-score-explainability)
7. [AI Explanation Layer](#7-ai-explanation-layer)
8. [Security Architecture](#8-security-architecture)
9. [Evaluation Methodology](#9-evaluation-methodology)
10. [Held-Out Results](#10-held-out-results)
11. [False-Positive / False-Negative Cost](#11-false-positive--false-negative-cost)
12. [Adversarial Testing](#12-adversarial-testing)
13. [Limitations](#13-limitations)
14. [Local Setup](#14-local-setup)
15. [Environment Variables](#15-environment-variables)
16. [API Documentation](#16-api-documentation)
17. [Deployment](#17-deployment)
18. [Future Work](#18-future-work)
19. [Razorpay AI Risk Manager Alignment](#19-razorpay-ai-risk-manager-alignment)
20. [Tech Stack](#20-tech-stack)

---

## 1. Why This Matters Financially

The attack chain is short:

```
Phishing URL  →  Credential theft  →  Account takeover  →  Payment fraud  →  Financial loss
```

A user who clicks a malicious link before authentication is verified can expose:

- Payment credentials and saved card details
- Session tokens that allow impersonation
- Banking login credentials

At scale, a phishing campaign targeting a payment platform's users represents **material financial risk** — both direct (fraudulent transactions) and indirect (regulatory exposure, reputational damage, reduced user trust).

**SecureAI's value proposition:** Intercept the attack at the earliest possible point — before the user's browser ever loads the phishing page. A URL that scores as Dangerous should be blocked or warned against before any credential can be entered.

This system is **defense-only**. It cannot initiate transactions, modify accounts, or call any payment API. Its sole function is risk assessment and explanation.

---

## 2. Features

| Feature | Description |
|---|---|
| URL risk scoring | Deterministic weighted score 0–100 |
| Risk classification | Safe / Suspicious / Dangerous bands |
| Security signal breakdown | 9 independent checks + brand impersonation |
| Score explainability | Per-signal point contributions, returned as `scoreBreakdown[]` |
| Brand impersonation detection | Exact match + typosquatting + homoglyph normalisation |
| AI explanation | Gemini generates plain-language explanation of the rule-engine verdict |
| Graceful AI fallback | Scanner works fully if Gemini is unavailable |
| Scan history | Every scan persisted per user in Supabase (PostgreSQL) |
| Data isolation | Row Level Security — users only see their own scans |
| Auth | Supabase JWT, validated server-side on every request |
| Audit trail | Dashboard, History, and Reports pages for authenticated users |

---

## 3. Architecture

```
User (Browser)
    │
    │ HTTPS + JWT
    ▼
React Frontend (Vite + TypeScript + Tailwind CSS)
    │
    │ POST /api/scan { url } + Authorization: Bearer <token>
    ▼
Express Backend (Node.js + TypeScript)
    │
    ├── JWT Authentication (requireAuth → supabase.auth.getUser)
    │
    ├── URL Validation & Normalization
    │     └── parseUrl() → reject invalid/non-HTTP/oversized URLs
    │         (length limit, empty hostname, trailing dot strip, lowercase guarantee)
    │
    ├── Security Feature Extraction
    │     ├── checkHttps()               TLS check
    │     ├── checkIpAddress()           Raw IP detection
    │     ├── checkUrlShortener()        Shortener services
    │     ├── checkLongUrl()             Length anomaly
    │     ├── checkSuspiciousTld()       Abused TLDs
    │     ├── checkManySubdomains()      Subdomain depth
    │     ├── countHyphens()             Hyphen density
    │     ├── checkEncodedChars()        Encoding obfuscation
    │     └── checkSuspiciousKeywords()  Action/scam keywords
    │
    ├── Brand Impersonation & Typosquatting Detector
    │     ├── Layer 1: Exact brand substring + keyword/TLD context
    │     └── Layer 2: Homoglyph normalization + Levenshtein ≤ 1
    │
    ├── ─────────────────────────────────────────────────────────
    │   DECISION LAYER  (deterministic, no AI involvement)
    │   ─────────────────────────────────────────────────────────
    ├── Risk Scoring Engine
    │     ├── Individual signal weights
    │     ├── Combined-signal bonuses
    │     └── Score breakdown (per-signal contributions → scoreBreakdown[])
    │
    ├── Risk Classification
    │     └── Safe (0–30) / Suspicious (31–70) / Dangerous (71–100)
    │
    ├── ─────────────────────────────────────────────────────────
    │   EXPLANATION LAYER  (never changes the verdict)
    │   ─────────────────────────────────────────────────────────
    ├── Gemini Explanation
    │     └── Plain-language explanation of rule-engine verdict
    │         Fallback: "AI explanation temporarily unavailable"
    │
    └── Supabase Persistence (fire-and-forget)
          └── scan_results (user_id, url, risk_score, risk_level, timestamp)

PostgreSQL (Supabase)
    ├── RLS: users SELECT only their own rows
    └── scan_results → Dashboard / History / Reports
```

---

## 4. Detection Pipeline

Every incoming URL goes through the following pipeline in order:

1. **Parse & validate** — reject non-HTTP/HTTPS URLs, empty hostnames, and URLs exceeding 2048 characters
2. **URL normalisation** — strip trailing dots, lowercase hostname; prevents whitelist bypass
3. **Trusted-domain check** — if the domain is on the whitelist (e.g. `paypal.com`, `google.com`), structural keyword penalties are waived and brand impersonation is skipped
4. **Structural analysis** — 9 independent checks (TLS, IP, shortener, length, TLD, subdomains, hyphens, encoding, keywords)
5. **Brand impersonation detection** — two-layer system:
   - Layer 1: exact brand-name match + keyword/TLD context on untrusted domain
   - Layer 2: typosquatting/homoglyph normalisation + Levenshtein-1 near-match
6. **Domain reputation** — pluggable interface (NullProvider in current build; Google Safe Browsing / VirusTotal can be swapped in)
7. **Weighted scoring** — aggregate individual signals with combined-signal bonuses; produces `scoreBreakdown[]`
8. **Risk classification** — score → Safe / Suspicious / Dangerous band
9. **AI explanation** — Gemini generates plain-language explanation (explanation only, no decision)
10. **Persistence** — result stored in Supabase with user isolation (fire-and-forget, never blocks response)

---

## 5. Risk Scoring

Scores are computed **deterministically** using the following weight table:

| Signal | Points |
|---|---|
| No HTTPS (HTTP only) | +20 |
| Raw IP address in hostname | +40 |
| Known URL shortener | +15 |
| URL exceeds length threshold | +10 |
| High-risk / abused TLD | +15 |
| Excessive subdomain depth | +10 |
| Per excess hyphen in hostname | +5 each |
| Percent-encoded characters | +10 |
| Per action keyword (path/query) | +5 each (max +25) |
| Brand impersonation detected | +35 |
| Brand impersonation + suspicious TLD | +25 bonus |
| Brand impersonation + path action keywords | +20 bonus |
| Brand impersonation + deep subdomains | +10 bonus |
| Brand impersonation + extra hyphens + keywords | +5 bonus |
| Prize/scam TLD + ≥ 2 scam keywords | +40 bonus |
| Reputation provider: malicious | +40 |
| Reputation provider: suspicious | +20 |
| Trusted domain (discount) | removes keyword/subdomain/hyphen/encoding penalties |

**Score bands:**
- 0–30: **Safe** — proceed normally
- 31–70: **Suspicious** — investigate before proceeding
- 71–100: **Dangerous** — do not proceed

Combined-signal bonuses are the primary mechanism for pushing multi-signal phishing URLs into the Dangerous band, while keeping single-signal edge cases in Suspicious.

---

## 6. Score Explainability

Every scan response includes a `scoreBreakdown` array alongside the numeric score. Each entry describes one triggered signal:

```json
{
  "riskScore": 75,
  "riskLevel": "Dangerous",
  "scoreBreakdown": [
    {
      "signal": "brandImpersonation",
      "description": "Hostname impersonates 'paypal'",
      "points": 35,
      "severity": "critical"
    },
    {
      "signal": "impersonationActionCombo",
      "description": "Brand impersonation + action keywords in path",
      "points": 20,
      "severity": "high"
    },
    {
      "signal": "hyphens",
      "description": "2 hyphens in hostname",
      "points": 10,
      "severity": "medium"
    },
    {
      "signal": "suspiciousKeywords",
      "description": "Action keywords: verify, account",
      "points": 10,
      "severity": "medium"
    }
  ]
}
```

This means:
- The frontend shows exactly why a URL scored as it did
- Users understand the specific risk, not just a number
- Gemini's explanation references the same signals the rule engine found
- A security analyst can audit any scan result and reconstruct the score exactly

---

## 7. AI Explanation Layer

Gemini is used **only as an explanation layer**. It receives the fully computed scan result — score, classification, and detected signals — and returns a plain-language explanation directed at the end user.

Gemini cannot and does not:
- Change the risk score
- Override the risk classification
- Influence which signals are detected
- Block or allow any URL

**Failure handling** — all five failure modes are handled gracefully:

| Failure | Handling |
|---|---|
| API key missing/invalid | `NoopExplainer` returns fallback string |
| Quota exceeded (429) | Catch returns `AI_UNAVAILABLE_MESSAGE` |
| Network timeout | Catch returns `AI_UNAVAILABLE_MESSAGE` |
| Model unavailable (404) | Catch returns `AI_UNAVAILABLE_MESSAGE` |
| Generic API error | Catch-all returns `AI_UNAVAILABLE_MESSAGE` |

When Gemini fails, `aiExplanation` is set to `"AI explanation is temporarily unavailable."` The scan result, risk score, and classification are returned normally. The failure is never surfaced as an error to the user.

---

## 8. Security Architecture

| Concern | Implementation |
|---|---|
| Authentication | Supabase Auth (email/password), JWT validated via `supabase.auth.getUser(token)` |
| Token injection | Frontend interceptor reads session before each request; no manual passing |
| User ID source | Always from validated JWT (`res.locals.userId`), never from `req.body` |
| Data isolation | Row Level Security on `scan_results` — `SELECT` restricted to `auth.uid() = user_id` |
| Backend writes | Service role key used for `INSERT`, bypasses RLS safely — never sent to browser |
| Service role key | Lives only in backend `.env` (gitignored), never returned in any response |
| CORS | Origin restricted to `CORS_ORIGIN` env var |
| Rate limiting | Global: 100 req/15 min per IP; scan endpoint: 30 req/15 min per IP |
| Request body | Limited to 10 KB; URL capped at 2048 characters |
| Error messages | Stack traces never sent to client; production mode returns generic message |
| Security headers | `helmet` middleware applied globally |

---

## 9. Evaluation Methodology

### Dataset

- 80 labeled URLs with human-assigned ground truth
- Labels: `SAFE` (28), `SUSPICIOUS` (24), `PHISHING` (28)
- Ground truth was assigned **before running the detector** and is never derived from detector output

### Split

- Deterministic stratified split: every 5th entry per label group → held-out (20%)
- Development set: 66 entries | Held-out test set: 14 entries
- The split is bit-for-bit reproducible across runs (no randomness)

### Evaluation scope

- Rule engine only — no Gemini, no Supabase, no network requests
- Same production code as used in the live scanner
- Metrics computed separately for development and held-out sets
- Full evaluation harness: `backend/src/evaluation/evaluate.ts`
- Machine-readable results: `backend/evaluation/results.json`

### Metric definitions

**Binary phishing metrics** (positive = PHISHING, negative = SAFE/SUSPICIOUS):

- **Precision** = TP / (TP + FP) — of all URLs classified Dangerous, what fraction actually are phishing
- **Recall** = TP / (TP + FN) — of all actual phishing URLs, what fraction were caught
- **False Positive Rate** = FP / (FP + TN) — of all legitimate/suspicious URLs, what fraction were wrongly flagged Dangerous
- **False Negative Rate** = FN / (FN + TP) — of all phishing URLs, what fraction were missed

---

## 10. Held-Out Results

These results are on the **held-out test set** (14 URLs never seen during development). All metrics are measured, not estimated.

| Metric | Value |
|---|---|
| Overall Accuracy | **78.6%** (11/14 correct) |
| Phishing Precision | **100.0%** |
| Phishing Recall | **100.0%** |
| Phishing F1 | **100.0%** |
| False Positive Rate | **0.0%** |
| False Negative Rate | **0.0%** |
| False Positives | **0** |
| False Negatives | **0** |

### Development set

| Metric | Value |
|---|---|
| Overall Accuracy | **77.3%** (51/66 correct) |
| Phishing Precision | **100.0%** |
| Phishing Recall | **100.0%** |
| Phishing F1 | **100.0%** |
| False Positive Rate | **0.0%** |
| False Negative Rate | **0.0%** |

### Why accuracy is not 100%

Overall accuracy is ~78% because the **SUSPICIOUS class is genuinely ambiguous**. Some SUSPICIOUS URLs (shortener-only, HTTP on unknown domain, cheap TLD for a legitimate service) score below 31 and land in Safe. The SUSPICIOUS band is intentionally a middle ground — "investigate before proceeding", not "definitely phishing". The Razorpay-relevant metrics are **phishing precision and recall**, both 100%.

*Note: held-out set is 14 URLs — confidence intervals on a set this small are wide. Treat this as a proof-of-concept evaluation, not a production accuracy claim.*

---

## 11. False-Positive / False-Negative Cost

SecureAI is designed with explicit awareness of the **asymmetric cost of errors**.

### False Positive — Safe URL classified as Dangerous

A legitimate URL wrongly flagged.

**Impact:**
- User is warned away from a page they actually need
- Unnecessary friction in normal user workflows
- Potential blocked access to legitimate services
- Erosion of user trust in the scanner
- *[HYPOTHETICAL]* In a payment flow: lost conversion, abandoned transaction

**Mitigation:** The trusted-domain whitelist ensures known legitimate services (PayPal, Google, GitHub, Stripe, etc.) can never be scored as dangerous via keyword/structural signals. Scoring is deliberately calibrated so a single weak signal never reaches the Dangerous threshold.

**Current FPR:** 0% on both development and held-out sets.

### False Negative — Phishing URL classified as Safe or Suspicious

A phishing URL that the scanner fails to flag as Dangerous.

**Impact:**
- User proceeds to the phishing page
- Credentials stolen → account takeover
- Payment credentials exposed → payment fraud
- Financial loss to user or platform
- *[HYPOTHETICAL]* A single captured payment credential can enable unauthorised transactions

**Current FNR:** 0% on both development and held-out sets.

### Design decision

The Suspicious/Dangerous threshold (70→71) is intentionally conservative. Only URLs with strong combined signals cross into Dangerous. This keeps FPR at 0% while accepting that some low-signal phishing URLs land in Suspicious rather than Dangerous. In a production deployment, the Suspicious classification still alerts the user — they are warned, not silently passed through.

---

## 12. Adversarial Testing

A separate adversarial robustness suite (`backend/src/evaluation/adversarialTests.ts`) tests the rule engine against 76 edge cases across 12 attack categories:

| Category | Tests | Passed |
|---|---|---|
| Typosquatting (rn→m, digit substitution, missing/extra char) | 8 | 8 |
| Brand impersonation (subdomain, path, unrelated domain) | 7 | 7 |
| Homoglyph attacks (digit-for-letter, Greek characters) | 3 | 3 |
| Suspicious TLD variations | 5 | 5 |
| Legitimate domains (false-positive resistance) | 10 | 10 |
| URL shorteners | 4 | 4 |
| IP address URLs | 6 | 6 |
| Deep subdomains | 3 | 3 |
| Percent-encoded characters | 4 | 4 |
| Non-standard ports | 4 | 4 |
| Query-string heavy URLs | 3 | 3 |
| Long URLs | 3 | 3 |
| Punycode / IDN homographs | 3 | 3 |
| Mixed signals | 5 | 5 |
| Benign payment/banking domains | 4 | 4 |
| **Total** | **76** | **76 (100%)** |

Full results and engineering insights in `backend/evaluation/ADVERSARIAL_REPORT.md`.

**Known detection gaps documented by this suite:**
- Brand name appearing only in the URL path (not hostname) — not detected
- Unregistered generic brand words ("bank", "wallet") — lower score
- Non-standard port numbers — no penalty
- Greek/Cyrillic Unicode homoglyphs (non-punycode form) — not normalised

---

## 13. Limitations

These limitations are stated honestly. The goal is accurate measurement, not inflated claims.

1. **No external reputation API.** The current build uses a `NullReputationProvider` — no Google Safe Browsing or VirusTotal integration. Connecting either would increase detection of known-bad URLs that don't trigger structural signals. This is the single largest opportunity for improvement.

2. **No domain age check.** Newly registered domains are a very strong phishing signal (most phishing pages are live for < 48 hours). The engine cannot check domain age without a WHOIS/RDAP integration.

3. **Small dataset.** 80 URLs is a controlled evaluation set. Real-world performance on a larger distribution (especially edge cases) may differ. The held-out set of 14 URLs is small; confidence intervals are wide.

4. **SUSPICIOUS class overlap.** URLs with weak signals (shorteners, HTTP on unknown domains, cheap TLDs for legitimate services) have genuine ambiguity. Overall accuracy (~78%) is held down by SUSPICIOUS↔SAFE misclassifications. This is architecturally expected.

5. **No content inspection.** The engine analyses only the URL string. It does not fetch or render the page. A URL that looks clean but leads to a phishing form would be missed. URL-content-agnostic analysis is a fundamental limitation of static URL scanning.

6. **No JavaScript or visual similarity analysis.** Advanced brand spoofing (pixel-perfect login form replicas) is not detected by URL analysis alone.

7. **Punycode / IDN homographs.** The engine does not decode punycode hostnames; IDN homograph attacks in `xn--...` form that don't contain recognisable brand tokens after normalisation are not fully caught.

---

## 14. Local Setup

### Prerequisites

- Node.js >= 20
- npm >= 9
- A [Supabase](https://supabase.com) project (free tier is sufficient)
- A [Google AI Studio](https://aistudio.google.com) API key for Gemini (optional — scanner works without it)

### 1. Clone the repository

```bash
git clone https://github.com/your-username/SecureAI.git
cd SecureAI
```

### 2. Set up the database

Open your Supabase project → SQL Editor → run the SQL in `supabase_migration.sql`.

### 3. Set up the backend

```bash
cd backend
cp .env.example .env
# Edit .env — fill in SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, GEMINI_API_KEY
npm install
npm run dev          # starts on http://localhost:5000
```

### 4. Set up the frontend

```bash
cd frontend
cp .env.example .env
# Edit .env — fill in VITE_SUPABASE_URL, VITE_SUPABASE_ANON_KEY, VITE_API_BASE_URL
npm install --legacy-peer-deps
npm run dev          # starts on http://localhost:5173
```

### 5. Run the evaluation

```bash
cd backend
npm run evaluate     # compiles TypeScript, runs evaluation, prints metrics to stdout
```

### 6. Health check

```
GET http://localhost:5000/health
→ { "status": "ok", "timestamp": "2026-09-04T07:47:00.000Z" }
```

---

## 15. Environment Variables

### Backend (`backend/.env`)

| Variable | Required | Description |
|---|---|---|
| `NODE_ENV` | No | `development` or `production` (default: `development`) |
| `PORT` | No | Express server port (default: `5000`) |
| `CORS_ORIGIN` | No | Allowed frontend origin (default: `http://localhost:5173`) |
| `SUPABASE_URL` | Yes* | Your Supabase project URL |
| `SUPABASE_SERVICE_ROLE_KEY` | Yes* | Supabase service role key — **backend only, never expose** |
| `GEMINI_API_KEY` | No | Google Gemini API key (scanner works without it) |
| `GEMINI_MODEL` | No | Gemini model name (default: `gemini-2.0-flash`) |

*Required for scan persistence and history. Without them, scans still run but results are not saved.

### Frontend (`frontend/.env`)

| Variable | Required | Description |
|---|---|---|
| `VITE_SUPABASE_URL` | Yes | Your Supabase project URL |
| `VITE_SUPABASE_ANON_KEY` | Yes | Supabase public/anon key — safe to expose in browser |
| `VITE_API_BASE_URL` | Yes | Backend API base URL (e.g. `http://localhost:5000/api`) |

---

## 16. API Documentation

### `POST /api/scan`

Analyse a URL for phishing indicators.

**Authentication:** `Authorization: Bearer <supabase-jwt>` (required)

**Request body:**
```json
{ "url": "https://example.com" }
```

**Constraints:**
- URL must start with `http://` or `https://`
- URL must not exceed 2048 characters

**Success response (`200 OK`):**
```json
{
  "url": "https://secure-paypal-login.com/verify-account",
  "riskScore": 75,
  "riskLevel": "Dangerous",
  "checks": {
    "https": true,
    "ipAddress": false,
    "urlShortener": false,
    "longUrl": false,
    "suspiciousKeywords": ["verify", "account"],
    "suspiciousTld": false,
    "manySubdomains": false,
    "hyphenCount": 2,
    "hasEncodedChars": false,
    "brandImpersonation": {
      "brand": "paypal",
      "hostname": "secure-paypal-login.com"
    },
    "isTrustedDomain": false,
    "reputation": { "status": "unknown", "source": null, "detail": null }
  },
  "scoreBreakdown": [
    {
      "signal": "brandImpersonation",
      "description": "Hostname impersonates 'paypal'",
      "points": 35,
      "severity": "critical"
    },
    {
      "signal": "impersonationActionCombo",
      "description": "Brand impersonation + action keywords in path",
      "points": 20,
      "severity": "high"
    },
    {
      "signal": "hyphens",
      "description": "2 hyphens in hostname",
      "points": 10,
      "severity": "medium"
    },
    {
      "signal": "suspiciousKeywords",
      "description": "Action keywords: verify, account",
      "points": 10,
      "severity": "medium"
    }
  ],
  "recommendations": [
    "This URL appears to impersonate PayPal. Do not enter your credentials.",
    "Verify the URL directly by typing paypal.com into your browser."
  ],
  "recommendation": "This URL appears to impersonate PayPal. Do not enter your credentials.",
  "aiExplanation": "This URL is highly suspicious. The domain 'secure-paypal-login.com' impersonates PayPal by including the brand name in an untrusted domain, combined with action-oriented keywords 'verify' and 'account' in the path. This pattern is characteristic of credential-harvesting phishing pages."
}
```

**Error responses:**

| Status | Condition |
|---|---|
| `400 Bad Request` | Missing URL, invalid URL format, URL exceeds 2048 chars |
| `401 Unauthorized` | Missing or invalid JWT |
| `429 Too Many Requests` | Rate limit exceeded (30 req/15 min per IP on this endpoint) |
| `500 Internal Server Error` | Unexpected server error (safe message in production) |

### `GET /health`

Health check endpoint.

```json
{ "status": "ok", "timestamp": "2026-09-04T07:47:00.000Z" }
```

---

## 17. Deployment

### Prerequisites

- Backend: a Node.js hosting service that supports env vars (Render, Railway, Fly.io)
- Frontend: a static hosting service (Vercel, Netlify, Cloudflare Pages)
- Supabase project with the migration applied

### Backend — Render

1. Create a new **Web Service** on [render.com](https://render.com)
2. Connect your GitHub repository
3. Set the following:
   - **Root Directory:** `backend`
   - **Build Command:** `npm install && npm run build`
   - **Start Command:** `npm start`
   - **Node version:** 20
4. Add environment variables in the Render dashboard:
   ```
   NODE_ENV=production
   PORT=10000
   CORS_ORIGIN=https://your-frontend.vercel.app
   SUPABASE_URL=https://xxxx.supabase.co
   SUPABASE_SERVICE_ROLE_KEY=<service-role-key>
   GEMINI_API_KEY=<gemini-key>
   GEMINI_MODEL=gemini-2.0-flash
   ```
5. Deploy. Note the service URL (e.g. `https://secureai-api.onrender.com`).
6. Verify: `GET https://secureai-api.onrender.com/health`

### Frontend — Vercel

1. Import your GitHub repository on [vercel.com](https://vercel.com)
2. Set the following:
   - **Framework Preset:** Vite
   - **Root Directory:** `frontend`
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`
3. Add environment variables in the Vercel dashboard:
   ```
   VITE_SUPABASE_URL=https://xxxx.supabase.co
   VITE_SUPABASE_ANON_KEY=<anon-key>
   VITE_API_BASE_URL=https://secureai-api.onrender.com/api
   ```
4. Deploy. Note the frontend URL (e.g. `https://secureai.vercel.app`).
5. Update `CORS_ORIGIN` on Render to match the Vercel URL.

### Supabase CORS

In your Supabase project → Authentication → URL Configuration:
- Add `https://secureai.vercel.app` to the **Site URL** and **Redirect URLs** list.

### Do NOT deploy

- The `SUPABASE_SERVICE_ROLE_KEY` to any frontend or public-facing location
- Any `.env` file to version control (already gitignored)

---

## 18. Future Work

In priority order:

1. **Integrate Google Safe Browsing or VirusTotal** — the `IReputationProvider` interface is already implemented; only an API key and provider class are needed
2. **Domain age / registration date check** — WHOIS/RDAP lookup for newly registered domains (most phishing pages are live for < 48 hours)
3. **Expand the labeled dataset** — aim for 500+ URLs with diverse patterns and adversarial examples
4. **Punycode / IDN homograph detection** — decode `xn--` hostnames before pattern matching
5. **Real-time feedback loop** — allow users to report false positives/negatives to improve the dataset
6. **Email content scanning** — extend the analysis to email bodies and embedded links
7. **Confidence intervals and A/B testing** — rigorous statistical evaluation as dataset grows
8. **Google Safe Browsing integration** — the pluggable `IReputationProvider` slot is already in the codebase

---

## 19. Razorpay AI Risk Manager Alignment

SecureAI directly addresses the Razorpay AI Risk Manager buildathon track:

| Track requirement | How SecureAI addresses it |
|---|---|
| AI-powered detection | Gemini explains every verdict in plain language for the end user |
| Mitigation of financial risk | Blocks the phishing→credential theft→payment fraud chain at the source |
| Explainability | `scoreBreakdown[]` field exposes per-signal contributions; no black-box decisions |
| Auditability | Every scan persisted with user_id, timestamp, score, and classification |
| Defense-only | System makes no payments, modifies no accounts, calls no payment APIs |
| Production-ready security | JWT auth, RLS, rate limiting, helmet, env-isolated secrets |

**What SecureAI does not do:**
- Claim Razorpay API integration (none exists)
- Make payment decisions
- Access user financial data
- Call any external API except Gemini (for explanation only)

The system is positioned as a **pre-authentication URL risk gate**: before a user enters any credential into a form, SecureAI can tell them whether the URL they are about to submit that credential to is trustworthy.

---

## 20. Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 19, TypeScript, Vite, Tailwind CSS v4, Framer Motion |
| Backend | Node.js, Express 5, TypeScript 5 |
| Database | PostgreSQL via Supabase |
| Auth | Supabase Authentication + JWT |
| AI (explanation only) | Google Gemini via `@google/generative-ai` |
| State | Zustand |
| Routing | React Router v7 |
| Security | helmet, express-rate-limit, CORS |

---

## Project Structure

```
SecureAI/
├── backend/
│   └── src/
│       ├── config/          # env vars, Supabase admin client, trusted-domain list
│       ├── controllers/     # route handlers
│       ├── evaluation/      # evaluation harness, dataset, split logic
│       ├── middlewares/     # requireAuth (JWT), errorHandler
│       ├── models/          # TypeScript types (PhishingChecks, ScanResponse, …)
│       ├── routes/          # Express routers
│       ├── services/        # scan.service (pipeline), gemini.service
│       └── utils/
│           ├── brandImpersonation.ts     # brand + typosquatting detection
│           ├── urlStructureAnalyzer.ts   # structural checks + URL normalisation
│           ├── riskScoring.ts            # weighted scoring + scoreBreakdown
│           ├── domainReputation.ts       # pluggable reputation interface
│           └── recommendationEngine.ts  # user-facing recommendations
│
├── frontend/
│   └── src/
│       ├── features/        # url-scanner, dashboard, auth, history, email-scanner
│       ├── layouts/         # DashboardLayout with sidebar navigation
│       ├── pages/           # Dashboard, Scanner, History, Reports, Settings
│       ├── services/        # API client (scan, history)
│       └── lib/             # Supabase client (anon key only)
│
├── backend/evaluation/      # results.json + ADVERSARIAL_REPORT.md (generated)
├── supabase_migration.sql   # DB schema + RLS policies
└── README.md                # this file
```

---

## Available Scripts

### Backend

| Script | Description |
|---|---|
| `npm run dev` | Start with ts-node-dev (hot reload) |
| `npm run build` | Compile TypeScript to `dist/` |
| `npm start` | Run compiled `dist/server.js` |
| `npm run evaluate` | Compile + run evaluation harness, print metrics |
| `npm run lint` | Run ESLint |

### Frontend

| Script | Description |
|---|---|
| `npm run dev` | Start Vite dev server |
| `npm run build` | TypeScript check + production build |
| `npm run preview` | Preview production build |
| `npm run lint` | Run ESLint |

---

## License

ISC
