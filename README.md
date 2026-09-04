# SecureAI — Explainable AI-Assisted Phishing Risk Detection

> **An explainable cybersecurity application for detecting phishing and malicious URLs using deterministic security heuristics with optional AI-generated explanations.**

SecureAI analyzes URLs before users interact with potentially dangerous websites. It produces a deterministic risk score from 0–100, a Safe / Suspicious / Dangerous classification, an explainable breakdown of detected security signals, and a plain-language security explanation.

The security decision is made entirely by the deterministic rule engine. Google Gemini is used only as an optional explanation layer and can never change the risk score or verdict.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Why SecureAI](#2-why-secureai)
3. [Features](#3-features)
4. [Architecture](#4-architecture)
5. [Detection Pipeline](#5-detection-pipeline)
6. [Risk Scoring](#6-risk-scoring)
7. [Score Explainability](#7-score-explainability)
8. [AI Explanation Layer](#8-ai-explanation-layer)
9. [Security Architecture](#9-security-architecture)
10. [Evaluation Methodology](#10-evaluation-methodology)
11. [Evaluation Results](#11-evaluation-results)
12. [Error Costs](#12-error-costs)
13. [Adversarial Testing](#13-adversarial-testing)
14. [Limitations](#14-limitations)
15. [Local Setup](#15-local-setup)
16. [Environment Variables](#16-environment-variables)
17. [API Documentation](#17-api-documentation)
18. [Deployment](#18-deployment)
19. [Future Work](#19-future-work)
20. [Tech Stack](#20-tech-stack)
21. [Project Structure](#21-project-structure)
22. [Available Scripts](#22-available-scripts)
23. [License](#23-license)

---

## 1. Overview

Phishing attacks commonly begin with a malicious URL designed to trick users into revealing credentials, payment information, or other sensitive data.

SecureAI provides a pre-navigation security check:

```text
Suspicious URL
      ↓
URL validation & normalization
      ↓
Security signal extraction
      ↓
Brand impersonation detection
      ↓
Deterministic risk scoring
      ↓
Safe / Suspicious / Dangerous
      ↓
Explainable score breakdown
      ↓
Optional AI-generated explanation
      ↓
Secure scan history
```

The core security decision does not depend on an AI model or external reputation service.

This makes the scanner deterministic, auditable, reproducible, and resilient when AI services are unavailable.

---

## 2. Why SecureAI

Many AI-assisted security applications send an input directly to an LLM and use the generated response as the final decision.

SecureAI takes a different approach.

### Deterministic Decision Layer

The rule engine analyzes measurable URL characteristics such as:

- HTTPS usage
- IP-based hostnames
- URL shorteners
- URL length
- suspicious top-level domains
- excessive subdomains
- hostname hyphens
- encoded characters
- phishing action keywords
- scam-related keywords
- brand impersonation
- typosquatting
- homoglyph normalization
- combined security signals

The resulting score is deterministic and reproducible.

### AI Explanation Layer

Gemini receives the already-computed security result and converts it into a human-readable explanation.

Gemini:

- does not calculate the score
- does not select the verdict
- does not modify security signals
- does not override the rule engine

If Gemini is unavailable, SecureAI automatically uses a deterministic fallback explanation.

This separation keeps AI useful without making it a single point of failure for the security decision.

---

## 3. Features

| Feature | Description |
|---|---|
| URL risk scoring | Deterministic weighted score from 0–100 |
| Risk classification | Safe / Suspicious / Dangerous |
| Security signal analysis | Multiple independent URL security checks |
| Score explainability | Per-signal point contributions |
| Brand impersonation detection | Brand matching, typosquatting and homoglyph normalization |
| AI explanation | Gemini generates plain-language explanations |
| AI fallback | Deterministic explanation when Gemini is unavailable |
| Scan history | Authenticated scans persisted in Supabase |
| User data isolation | Row Level Security ensures users only access their own scans |
| Authentication | Supabase Authentication with server-side JWT validation |
| Reports | Statistics generated from persisted scan history |
| API protection | CORS, Helmet, rate limiting and input limits |
| Evaluation framework | Reproducible labeled dataset with held-out testing |
| Adversarial testing | Dedicated robustness suite covering multiple attack patterns |

---

## 4. Architecture

```text
                         User
                          │
                          ▼
                ┌──────────────────┐
                │ React Frontend   │
                │ TypeScript/Vite  │
                └────────┬─────────┘
                         │
                    HTTPS + JWT
                         │
                         ▼
                ┌──────────────────┐
                │ Express Backend  │
                │ Node.js/TS       │
                └────────┬─────────┘
                         │
              ┌──────────┴──────────┐
              │                     │
              ▼                     ▼
       Authentication         URL Validation
       & Authorization         & Normalization
              │                     │
              └──────────┬──────────┘
                         ▼
              ┌──────────────────────┐
              │ Security Analysis    │
              │                      │
              │ HTTPS                │
              │ IP Detection         │
              │ URL Shortener        │
              │ URL Length           │
              │ Suspicious TLD       │
              │ Subdomains           │
              │ Hyphens              │
              │ Encoding             │
              │ Keywords             │
              └──────────┬───────────┘
                         ▼
              ┌──────────────────────┐
              │ Brand Impersonation  │
              │ & Typosquatting      │
              └──────────┬───────────┘
                         ▼
              ┌──────────────────────┐
              │ Deterministic Risk   │
              │ Scoring Engine       │
              └──────────┬───────────┘
                         │
                  Score + Verdict
                         │
              ┌──────────┴───────────┐
              │                      │
              ▼                      ▼
       Score Breakdown        Optional Gemini
                                  Explanation
                                      │
                                ┌─────┴─────┐
                                │           │
                             Success      Failure
                                │           │
                             Gemini     Deterministic
                             result       fallback
                                │           │
              └─────────────────┴───────────┘
                         │
                         ▼
                ┌──────────────────┐
                │ Supabase         │
                │ PostgreSQL + RLS │
                └──────────────────┘
```

### Core Architectural Principle

```text
              SECURITY DECISION
                     │
                     ▼
             Deterministic Engine
                     │
              ┌──────┴──────┐
              ▼             ▼
           Score          Verdict
              │
              ▼
        Explanation Layer
              │
        ┌─────┴─────┐
        ▼           ▼
     Gemini     Deterministic
                fallback
```

**AI never controls the security decision.**

---

## 5. Detection Pipeline

Every incoming URL passes through the following pipeline.

### Step 1 — Parse and Validate

SecureAI rejects:

- empty URLs
- malformed URLs
- unsupported protocols
- URLs without valid hostnames
- URLs exceeding the configured length limit

Only HTTP and HTTPS URLs are analyzed.

### Step 2 — Normalize

The hostname is normalized to reduce simple bypass techniques.

Normalization includes:

- lowercase hostname handling
- trailing-dot handling
- URL parsing

IPv4 and IPv6 addresses are handled separately from subdomain analysis so that IP address components are not incorrectly counted as subdomains.

### Step 3 — Trusted-Domain Check

Known trusted domains can avoid certain structural penalties.

This prevents legitimate domains from being incorrectly penalized simply because their URLs contain words that would otherwise appear suspicious.

### Step 4 — Structural Analysis

The scanner checks:

- HTTPS
- raw IP addresses
- URL shorteners
- URL length
- suspicious TLDs
- subdomain depth
- hostname hyphens
- encoded characters
- suspicious action/scam keywords

### Step 5 — Brand Impersonation

SecureAI uses a dedicated brand impersonation detector.

It can identify patterns such as:

```text
paypal  →  paypa1
netflix →  netfIix
```

The detector uses:

- brand registry
- hostname analysis
- homoglyph normalization
- Levenshtein distance
- hostname labels
- hyphen-separated hostname segments
- contextual phishing signals

### Step 6 — Risk Scoring

Individual signals are combined using deterministic weights and selected combination bonuses.

### Step 7 — Risk Classification

The final score is mapped to:

```text
0–30   → Safe
31–70  → Suspicious
71–100 → Dangerous
```

### Step 8 — AI Explanation

Gemini may generate a plain-language explanation based on the already-computed result.

### Step 9 — Persistence

Authenticated scan results are stored in Supabase with user isolation.

---

## 6. Risk Scoring

SecureAI uses a deterministic weighted scoring system.

| Signal | Points |
|---|---:|
| HTTP instead of HTTPS | +20 |
| Raw IP address | +40 |
| Known URL shortener | +15 |
| Long URL | +10 |
| High-risk / abused TLD | +15 |
| Excessive subdomain depth | +10 |
| Excess hostname hyphens | +5 each |
| Percent-encoded characters | +10 |
| Action keyword | +5 each, capped |
| Brand impersonation | +35 |
| Brand impersonation + suspicious TLD | +25 bonus |
| Brand impersonation + action keywords | +20 bonus |
| Brand impersonation + deep subdomains | +10 bonus |
| Brand impersonation + extra hyphens + keywords | +5 bonus |
| Prize/scam combination | +40 bonus |

The final score is capped at 100.

### Risk Bands

| Score | Classification | Meaning |
|---:|---|---|
| 0–30 | Safe | No significant phishing indicators detected |
| 31–70 | Suspicious | Signals warrant caution and verification |
| 71–100 | Dangerous | Strong indicators of phishing or malicious infrastructure |

The scoring engine is deterministic, meaning the same URL and configuration produce the same result.

---

## 7. Score Explainability

Every scan returns a `scoreBreakdown` array.

Example:

```json
{
  "riskScore": 90,
  "riskLevel": "Dangerous",
  "scoreBreakdown": [
    {
      "signal": "brandImpersonation",
      "description": "Hostname appears to impersonate the \"paypal\" brand",
      "points": 35,
      "severity": "critical"
    },
    {
      "signal": "impersonationTldCombo",
      "description": "Brand impersonation combined with a high-risk TLD",
      "points": 25,
      "severity": "critical"
    },
    {
      "signal": "suspiciousTld",
      "description": "Domain uses a high-risk or commonly abused top-level domain",
      "points": 15,
      "severity": "medium"
    }
  ]
}
```

This provides:

- transparent scoring
- user-readable explanations
- auditability
- easier debugging
- easier evaluation
- consistency between the backend and frontend

The explanation layer receives the same detected signals rather than independently deciding what makes a URL risky.

---

## 8. AI Explanation Layer

Google Gemini is used only to generate a natural-language explanation.

### Gemini Receives

- URL analysis result
- risk score
- risk classification
- detected security signals

### Gemini Cannot

- change the score
- change the classification
- add security signals
- remove security signals
- override the rule engine

### Failure Handling

SecureAI treats Gemini as an optional service.

| Failure | Handling |
|---|---|
| Missing API key | Deterministic fallback |
| Invalid API key | Deterministic fallback |
| Rate limit / 429 | Deterministic fallback |
| Service unavailable / 503 | Deterministic fallback |
| Model unavailable | Deterministic fallback |
| Network timeout | Deterministic fallback |
| Unexpected API error | Deterministic fallback |

The scanner itself remains operational when Gemini fails.

### Timeout Protection

Gemini requests are bounded by:

```text
GEMINI_TIMEOUT_MS
```

The current configuration uses:

```text
5000 ms
```

This prevents an unavailable AI service from blocking the scanning experience indefinitely.

### Provider Attribution

The application tracks whether the explanation came from:

```text
gemini
```

or:

```text
deterministic
```

This prevents the interface from incorrectly claiming that Gemini generated an explanation when the fallback was used.

---

## 9. Security Architecture

| Concern | Implementation |
|---|---|
| Authentication | Supabase Authentication |
| Authorization | Server-side JWT validation |
| User identity | Derived from validated JWT |
| Data isolation | Supabase Row Level Security |
| Database | PostgreSQL via Supabase |
| Service-role key | Backend only |
| CORS | Configurable allowed origin |
| Rate limiting | API and scan endpoint limits |
| Request body | Limited request size |
| URL length | Maximum 2048 characters |
| HTTP security headers | Helmet |
| Error handling | Production-safe error responses |
| Secrets | Environment variables |
| URL fetching | No arbitrary server-side page fetching |

### Authentication Flow

```text
User Login
    ↓
Supabase Authentication
    ↓
JWT
    ↓
Frontend
    ↓
Authorization: Bearer <JWT>
    ↓
Backend
    ↓
supabase.auth.getUser(token)
    ↓
Authenticated user ID
    ↓
Scan persistence
```

The backend never trusts a user ID supplied in the request body.

### Data Isolation

Scan records contain the authenticated user's ID.

Supabase Row Level Security restricts users to their own records.

The backend service-role key is never exposed to the browser.

---

## 10. Evaluation Methodology

SecureAI includes a reproducible evaluation framework.

### Dataset

Current dataset:

- 80 labeled URLs
- 28 SAFE
- 24 SUSPICIOUS
- 28 PHISHING

Ground-truth labels are assigned independently from detector output.

### Dataset Split

A deterministic stratified split is used.

```text
80 total URLs
│
├── Development: 66
│
└── Held-out: 14
```

The held-out set is not used for development tuning.

The split is reproducible across runs.

### Evaluation Scope

The evaluation measures the deterministic rule engine only.

It does not depend on:

- Gemini
- Supabase
- external reputation APIs
- network access

This ensures that the security evaluation measures the actual decision engine.

### Metrics

#### Accuracy

```text
Correct predictions / Total predictions
```

#### Precision

```text
TP / (TP + FP)
```

Of all URLs classified as phishing, how many were actually phishing?

#### Recall

```text
TP / (TP + FN)
```

Of all actual phishing URLs, how many were detected?

#### F1

```text
2 × Precision × Recall / (Precision + Recall)
```

#### False Positive Rate

```text
FP / (FP + TN)
```

#### False Negative Rate

```text
FN / (FN + TP)
```

---

## 11. Evaluation Results

### Held-Out Test Set

The current held-out set contains 14 URLs.

| Metric | Result |
|---|---:|
| Overall Accuracy | **78.6%** |
| Phishing Precision | **100.0%** |
| Phishing Recall | **100.0%** |
| Phishing F1 | **100.0%** |
| False Positive Rate | **0.0%** |
| False Negative Rate | **0.0%** |
| False Positives | **0** |
| False Negatives | **0** |

### Development Set

| Metric | Result |
|---|---:|
| Overall Accuracy | **77.3%** |
| Phishing Precision | **100.0%** |
| Phishing Recall | **100.0%** |
| Phishing F1 | **100.0%** |
| False Positive Rate | **0.0%** |
| False Negative Rate | **0.0%** |

### Important Interpretation

The 100% phishing precision and recall values are measured on this controlled dataset.

They should **not** be interpreted as proof of 100% real-world phishing detection.

The held-out dataset contains only 14 URLs, so statistical uncertainty is substantial.

Overall accuracy is lower because the SUSPICIOUS class is intentionally a middle category and can overlap with Safe URLs when only weak signals are present.

The evaluation is therefore best understood as a reproducible proof-of-concept benchmark rather than a production performance guarantee.

---

## 12. Error Costs

SecureAI considers the asymmetric cost of classification errors.

### False Positive

A legitimate URL is incorrectly classified as Dangerous.

Potential impact:

- unnecessary user friction
- blocked access to legitimate services
- reduced trust in the scanner
- interrupted workflows

### False Negative

A phishing URL is incorrectly classified as Safe or insufficiently warned.

Potential impact:

- user may visit a phishing page
- credentials may be exposed
- accounts may be compromised
- financial information may be exposed

### Design Approach

The scoring system requires strong or combined signals before assigning the Dangerous classification.

Single weak indicators generally remain below the Dangerous threshold.

The Suspicious classification provides an intermediate warning for URLs that contain signals requiring additional verification.

---

## 13. Adversarial Testing

A dedicated adversarial robustness suite tests the rule engine against 76 edge cases across 15 categories.

| Category | Tests | Passed |
|---|---:|---:|
| Typosquatting | 8 | 8 |
| Brand impersonation | 7 | 7 |
| Homoglyph attacks | 3 | 3 |
| Suspicious TLD variations | 5 | 5 |
| Legitimate domains | 10 | 10 |
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
| **Total** | **76** | **76** |

Full results are documented in:

```text
backend/evaluation/ADVERSARIAL_REPORT.md
```

### Known Detection Gaps

The adversarial suite also documents cases where the current implementation has limitations:

- brand names appearing only in the URL path
- generic brand-related words without strong context
- non-standard port numbers
- some Greek/Cyrillic Unicode homoglyphs
- full Punycode/IDN handling

These are documented as future improvements rather than hidden limitations.

---

## 14. Limitations

These limitations are stated explicitly to avoid overstating the capabilities of the current system.

### 1. No External Reputation API

The current build does not depend on an external malicious-URL reputation database.

This means URLs that look structurally normal but are already known to be malicious may not be detected.

A reputation provider can be added later through the existing provider architecture.

### 2. No Domain Age Check

The system currently does not check domain registration age.

Newly registered domains can be an important phishing indicator, but this requires an external WHOIS/RDAP-style integration.

### 3. Small Evaluation Dataset

The current evaluation contains 80 URLs.

The held-out set contains only 14 URLs.

Real-world performance may differ significantly on a larger and more diverse dataset.

### 4. SUSPICIOUS Class Ambiguity

The SUSPICIOUS class represents URLs that contain warning signs but are not necessarily malicious.

Examples include:

- URL shorteners
- HTTP URLs
- uncommon TLDs
- unknown domains with weak signals

This makes the boundary between Safe and Suspicious inherently less precise than the phishing detection boundary.

### 5. URL-Only Analysis

SecureAI analyzes the URL itself.

It does not fetch or render the destination webpage.

Therefore, a malicious webpage hosted at a URL with no obvious suspicious structural indicators may not be detected.

### 6. No Visual Similarity Analysis

The current version does not analyze webpage screenshots or compare login-page layouts.

Advanced attacks using visually cloned websites require content or visual analysis.

### 7. Punycode / IDN Limitations

Full Punycode and internationalized-domain-name homograph detection is not yet implemented.

Some Unicode-based impersonation techniques may therefore bypass the current hostname normalization logic.

---

## 15. Local Setup

### Prerequisites

- Node.js >= 20
- npm >= 9
- Supabase project
- Google AI Studio API key for Gemini (optional)

The scanner works without Gemini because the deterministic security engine is independent of the AI service.

### 1. Clone the Repository

```bash
git clone https://github.com/Nikshitha-02/secureai-phishing-detection.git
cd secureai-phishing-detection
```

### 2. Set Up the Database

Open the Supabase SQL Editor and run:

```text
supabase_migration.sql
```

This creates the required scan-results table and Row Level Security policies.

### 3. Set Up the Backend

```bash
cd backend
npm install
```

Create:

```text
backend/.env
```

using:

```text
backend/.env.example
```

Then configure the required environment variables.

Start the backend:

```bash
npm run dev
```

The backend runs on:

```text
http://localhost:5000
```

### 4. Set Up the Frontend

Open another terminal:

```bash
cd frontend
npm install --legacy-peer-deps
```

Create:

```text
frontend/.env
```

using:

```text
frontend/.env.example
```

Start the frontend:

```bash
npm run dev
```

The frontend runs on:

```text
http://localhost:5173
```

### 5. Run the Evaluation

```bash
cd backend
npm run evaluate
```

### 6. Run Adversarial Tests

```bash
cd backend
npm run adversarial
```

### 7. Health Check

```text
GET http://localhost:5000/health
```

Expected response:

```json
{
  "status": "ok"
}
```

---

## 16. Environment Variables

### Backend

Create:

```text
backend/.env
```

Example:

```env
NODE_ENV=development
PORT=5000
CORS_ORIGIN=http://localhost:5173

SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key

GEMINI_API_KEY=your-gemini-api-key
GEMINI_MODEL=gemini-3.6-flash
GEMINI_TIMEOUT_MS=5000
```

### Backend Variables

| Variable | Required | Description |
|---|---|---|
| `NODE_ENV` | No | `development` or `production` |
| `PORT` | No | Backend server port |
| `CORS_ORIGIN` | No | Allowed frontend origin |
| `SUPABASE_URL` | Required for persistence | Supabase project URL |
| `SUPABASE_SERVICE_ROLE_KEY` | Required for persistence | Backend-only service-role key |
| `GEMINI_API_KEY` | No | Gemini API key |
| `GEMINI_MODEL` | No | Gemini model name |
| `GEMINI_TIMEOUT_MS` | No | Maximum Gemini request time in milliseconds |

Current Gemini configuration:

```env
GEMINI_MODEL=gemini-3.6-flash
GEMINI_TIMEOUT_MS=5000
```

### Frontend

Create:

```text
frontend/.env
```

Example:

```env
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your-anon-key
VITE_API_BASE_URL=http://localhost:5000/api
```

### Important Security Rule

Never commit:

```text
backend/.env
frontend/.env
```

Never expose:

```text
SUPABASE_SERVICE_ROLE_KEY
GEMINI_API_KEY
```

The frontend should only receive the public Supabase anon key.

---

## 17. API Documentation

### POST `/api/scan`

Analyze a URL for phishing indicators.

#### Authentication

```text
Authorization: Bearer <supabase-jwt>
```

#### Request

```json
{
  "url": "https://example.com"
}
```

#### Constraints

- URL must use HTTP or HTTPS
- URL must contain a valid hostname
- URL cannot exceed 2048 characters

#### Response

```json
{
  "url": "https://secure-paypal-login.com/verify-account",
  "riskScore": 90,
  "riskLevel": "Dangerous",
  "checks": {
    "https": true,
    "ipAddress": false,
    "urlShortener": false,
    "longUrl": false,
    "suspiciousKeywords": [
      "verify",
      "account"
    ],
    "suspiciousTld": false,
    "manySubdomains": false,
    "hyphenCount": 2,
    "hasEncodedChars": false,
    "brandImpersonation": {
      "brand": "paypal",
      "hostname": "secure-paypal-login.com"
    }
  },
  "scoreBreakdown": [
    {
      "signal": "brandImpersonation",
      "description": "Hostname appears to impersonate the \"paypal\" brand",
      "points": 35,
      "severity": "critical"
    }
  ],
  "aiExplanation": "The URL contains indicators commonly associated with phishing..."
}
```

### Error Responses

| Status | Condition |
|---|---|
| `400 Bad Request` | Missing or invalid URL |
| `401 Unauthorized` | Missing or invalid authentication token |
| `429 Too Many Requests` | Rate limit exceeded |
| `500 Internal Server Error` | Unexpected server error |

---

### GET `/health`

Checks whether the backend is running.

Example:

```json
{
  "status": "ok"
}
```

---

## 18. Deployment

SecureAI can be deployed using any hosting environment that supports:

- Node.js
- static frontend hosting
- environment variables
- PostgreSQL/Supabase connectivity

### Backend Deployment

Configure:

```env
NODE_ENV=production
PORT=<provider-port>
CORS_ORIGIN=https://your-frontend-domain.com

SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=<server-only-key>

GEMINI_API_KEY=<optional-key>
GEMINI_MODEL=gemini-3.6-flash
GEMINI_TIMEOUT_MS=5000
```

Build:

```bash
npm run build
```

Start:

```bash
npm start
```

### Frontend Deployment

Configure:

```env
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=<public-anon-key>
VITE_API_BASE_URL=https://your-backend-domain.com/api
```

Build:

```bash
npm run build
```

The generated frontend output is located in:

```text
dist/
```

### Production Security Checklist

Before deployment:

- [ ] `.env` files are not committed
- [ ] service-role key exists only on the backend
- [ ] Gemini API key exists only on the backend
- [ ] CORS is restricted to the frontend origin
- [ ] Supabase RLS policies are enabled
- [ ] production error responses do not expose stack traces
- [ ] rate limiting is enabled
- [ ] Helmet is enabled
- [ ] frontend uses HTTPS
- [ ] authentication redirects use the production domain

---

## 19. Future Work

Planned improvements include:

1. **External URL reputation integration**
   - Integrate a malicious-URL reputation provider
   - Improve detection of URLs with no obvious structural indicators

2. **Domain age analysis**
   - Add WHOIS/RDAP integration
   - Identify newly registered suspicious domains

3. **Larger evaluation dataset**
   - Expand from 80 URLs to hundreds or thousands
   - Include more legitimate, suspicious, and phishing examples

4. **Punycode / IDN detection**
   - Decode internationalized domains
   - Improve Unicode homoglyph detection

5. **User feedback loop**
   - Allow users to report incorrect classifications
   - Use feedback to improve the evaluation dataset

6. **Email phishing analysis**
   - Analyze email content
   - Extract and scan embedded URLs

7. **Visual webpage analysis**
   - Detect cloned login pages
   - Compare webpage structure and visual similarity

8. **Statistical evaluation**
   - Add confidence intervals
   - Evaluate against larger benchmark datasets
   - Measure performance across different phishing families

---

## 20. Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 19 |
| Language | TypeScript |
| Build Tool | Vite |
| Styling | Tailwind CSS v4 |
| Animations | Framer Motion |
| Routing | React Router |
| State Management | Zustand |
| Backend | Node.js |
| API Framework | Express 5 |
| Database | PostgreSQL via Supabase |
| Authentication | Supabase Auth |
| Authorization | JWT + Row Level Security |
| AI | Google Gemini |
| Security Middleware | Helmet |
| Rate Limiting | express-rate-limit |
| HTTP Client | Axios |
| Testing/Evaluation | Custom TypeScript evaluation framework |

---

## 21. Project Structure

```text
SecureAI/
│
├── backend/
│   ├── src/
│   │   ├── config/
│   │   │   ├── env.ts
│   │   │   └── supabaseAdmin.ts
│   │   │
│   │   ├── controllers/
│   │   │
│   │   ├── evaluation/
│   │   │   ├── evaluate.ts
│   │   │   ├── adversarialTests.ts
│   │   │   └── runAdversarial.ts
│   │   │
│   │   ├── middlewares/
│   │   │   ├── requireAuth.ts
│   │   │   └── errorHandler.ts
│   │   │
│   │   ├── models/
│   │   │   └── scan.model.ts
│   │   │
│   │   ├── routes/
│   │   │
│   │   ├── services/
│   │   │   ├── scan.service.ts
│   │   │   └── gemini.service.ts
│   │   │
│   │   └── utils/
│   │       ├── brandImpersonation.ts
│   │       ├── urlStructureAnalyzer.ts
│   │       ├── riskScoring.ts
│   │       ├── domainReputation.ts
│   │       └── recommendationEngine.ts
│   │
│   ├── evaluation/
│   │   ├── results.json
│   │   └── ADVERSARIAL_REPORT.md
│   │
│   ├── .env.example
│   ├── package.json
│   └── tsconfig.json
│
├── frontend/
│   ├── src/
│   │   ├── features/
│   │   │   ├── auth/
│   │   │   ├── dashboard/
│   │   │   ├── history/
│   │   │   ├── reports/
│   │   │   └── scanner/
│   │   │
│   │   ├── hooks/
│   │   ├── layouts/
│   │   ├── pages/
│   │   ├── services/
│   │   ├── components/
│   │   └── lib/
│   │
│   ├── .env.example
│   ├── package.json
│   └── vite.config.ts
│
├── supabase_migration.sql
├── README.md
└── .gitignore
```

---

## 22. Available Scripts

### Backend

```bash
npm run dev
```

Starts the backend development server with hot reload.

```bash
npm run build
```

Compiles the TypeScript backend.

```bash
npm start
```

Starts the compiled production server.

```bash
npm run lint
```

Runs ESLint.

```bash
npm run evaluate
```

Runs the deterministic evaluation framework.

```bash
npm run adversarial
```

Runs the adversarial robustness suite.

---

### Frontend

```bash
npm run dev
```

Starts the Vite development server.

```bash
npm run build
```

Runs the production build.

```bash
npm run preview
```

Previews the production build locally.

```bash
npm run lint
```

Runs ESLint.

---

## 23. License

ISC
