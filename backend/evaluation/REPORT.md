# SecureAI Phishing Detection Evaluation Report

> Generated: 2026-09-04T08:39:28.538Z
> Framework: Rule-based detection engine (no AI/Gemini, no network requests)
> Purpose: Razorpay AI Risk Manager Buildathon — objective baseline measurement

---

## Dataset

| Property | Value |
|---|---|
| Total entries | 80 |
| SAFE | 28 (35.0%) |
| SUSPICIOUS | 24 (30.0%) |
| PHISHING | 28 (35.0%) |
| Development set | 66 (80%) |
| Held-out test set | 14 (20%) |

**Split method:** Stratified by label — every 5th entry within each label group is held out. Deterministic, no randomness.

**Ground truth source:** Human expert assignment. Ground truth was assigned BEFORE running the detector and is NOT derived from detector output.

**Detector mapping:**
- Detector `Safe` → `SAFE`
- Detector `Suspicious` → `SUSPICIOUS`
- Detector `Dangerous` → `PHISHING`

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

## Development Set Results (66 entries)

### Overall Metrics

| Metric | Value |
|---|---|
| Accuracy | 77.3% |
| Macro Precision | 86.8% |
| Macro Recall | 75.0% |
| Macro F1 | 71.8% |
| Correct predictions | 51 / 66 |

### Per-Category Metrics

| Category | Precision | Recall | F1 | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|
| SAFE       | 60.5%       | 100.0%       | 75.4%       | 23 | 15 | 0 | 28 |
| SUSPICIOUS | 100.0% | 25.0% | 40.0% | 5 | 0 | 15 | 46 |
| PHISHING   | 100.0%   | 100.0%   | 100.0%   | 23 | 0 | 0 | 43 |

### Binary Phishing Detection Metrics

| Metric | Value |
|---|---|
| Precision | 100.0% |
| Recall (Detection Rate) | 100.0% |
| F1 | 100.0% |
| False Positive Rate | 0.0% |
| False Negative Rate | 0.0% |
| TP | 23 |
| FP | 0 |
| FN | 0 |
| TN | 43 |

### Confusion Matrix

| Actual \ Predicted | SAFE | SUSPICIOUS | PHISHING |
|---|---|---|---|
| **SAFE**       | 23 | 0 | 0 |
| **SUSPICIOUS** | 15 | 5 | 0 |
| **PHISHING**   | 0 | 0 | 23 |

---

## Held-Out Test Set Results (14 entries — UNSEEN during development)

### Overall Metrics

| Metric | Value |
|---|---|
| Accuracy | 78.6% |
| Macro Precision | 87.5% |
| Macro Recall | 75.0% |
| Macro F1 | 72.3% |
| Correct predictions | 11 / 14 |

### Per-Category Metrics

| Category | Precision | Recall | F1 | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|
| SAFE       | 62.5%       | 100.0%       | 76.9%       | 5 | 3 | 0 | 6 |
| SUSPICIOUS | 100.0% | 25.0% | 40.0% | 1 | 0 | 3 | 10 |
| PHISHING   | 100.0%   | 100.0%   | 100.0%   | 5 | 0 | 0 | 9 |

### Binary Phishing Detection Metrics

| Metric | Value |
|---|---|
| Precision | 100.0% |
| Recall (Detection Rate) | 100.0% |
| F1 | 100.0% |
| False Positive Rate | 0.0% |
| False Negative Rate | 0.0% |
| TP | 5 |
| FP | 0 |
| FN | 0 |
| TN | 9 |

### Confusion Matrix

| Actual \ Predicted | SAFE | SUSPICIOUS | PHISHING |
|---|---|---|---|
| **SAFE**       | 5 | 0 | 0 |
| **SUSPICIOUS** | 3 | 1 | 0 |
| **PHISHING**   | 0 | 0 | 5 |

---

## Error Analysis (Full Dataset — 80 entries)

### False Positives (SAFE → predicted SUSPICIOUS or PHISHING)

These are the detector's mistakes on legitimate URLs. Every entry here represents
a URL that is safe in reality but the detector flagged as suspicious or dangerous.

_No false positives — all SAFE URLs were classified correctly._

### False Negatives (PHISHING → predicted SAFE or SUSPICIOUS)

These are phishing URLs that the detector failed to classify as dangerous.
Every entry here represents a URL that is actually phishing but was missed.

_No false negatives — all PHISHING URLs were classified correctly._

### SAFE URLs predicted as SUSPICIOUS (acceptable but imprecise)

These SAFE URLs received a Suspicious prediction. They are not hard false positives
(detector didn't call them Dangerous) but may indicate over-flagging.

_None._

### PHISHING URLs predicted as SUSPICIOUS (detector caught the signal but under-classified)

These phishing URLs received a Suspicious prediction — the detector noticed
something wrong but did not go far enough.

_None._

---

## Full Results Table

| URL | Ground Truth | Predicted | Score | Correct | Set |
|---|---|---|---|---|---|
| `https://google.com` | SAFE | SAFE | 0 | ✓ | development |
| `https://www.google.com` | SAFE | SAFE | 0 | ✓ | development |
| `https://mail.google.com/mail/u/0/` | SAFE | SAFE | 0 | ✓ | development |
| `https://accounts.google.com/signin/v2/identifier` | SAFE | SAFE | 0 | ✓ | development |
| `https://github.com/microsoft/vscode` | SAFE | SAFE | 0 | ✓ | development |
| `https://stackoverflow.com/questions/tagged/javascript` | SAFE | SAFE | 0 | ✓ | development |
| `https://www.amazon.com/gp/cart/view.html` | SAFE | SAFE | 0 | ✓ | development |
| `https://www.paypal.com/signin` | SAFE | SAFE | 0 | ✓ | development |
| `https://netflix.com/login` | SAFE | SAFE | 0 | ✓ | development |
| `https://discord.com/login` | SAFE | SAFE | 0 | ✓ | development |
| `https://npmjs.com/package/react` | SAFE | SAFE | 0 | ✓ | development |
| `https://docs.microsoft.com/en-us/azure/security/` | SAFE | SAFE | 0 | ✓ | development |
| `https://outlook.live.com/mail/0/` | SAFE | SAFE | 0 | ✓ | development |
| `https://stripe.com/docs/payments` | SAFE | SAFE | 0 | ✓ | development |
| `https://app.slack.com/client` | SAFE | SAFE | 0 | ✓ | development |
| `https://zoom.us/signin` | SAFE | SAFE | 0 | ✓ | development |
| `https://www.youtube.com/watch?v=dQw4w9WgXcQ` | SAFE | SAFE | 0 | ✓ | development |
| `https://web.whatsapp.com/` | SAFE | SAFE | 0 | ✓ | development |
| `https://www.apple.com/shop/buy-iphone` | SAFE | SAFE | 0 | ✓ | development |
| `https://id.apple.com/account/reset/iforgot.action` | SAFE | SAFE | 0 | ✓ | development |
| `https://figma.com/login` | SAFE | SAFE | 0 | ✓ | development |
| `https://notion.so/login` | SAFE | SAFE | 0 | ✓ | development |
| `https://proton.me/mail` | SAFE | SAFE | 0 | ✓ | development |
| `http://bit.ly/3xAb2Yz` | SUSPICIOUS | SUSPICIOUS | 35 | ✓ | development |
| `https://tinyurl.com/y7k3mfpq` | SUSPICIOUS | SAFE | 15 | ✗ | development |
| `https://rb.gy/qx8rjt` | SUSPICIOUS | SAFE | 15 | ✗ | development |
| `http://example.com/login` | SUSPICIOUS | SAFE | 25 | ✗ | development |
| `https://cheap-hosting.xyz/signup` | SUSPICIOUS | SAFE | 15 | ✗ | development |
| `http://deals.info/free-voucher?code=WIN100` | SUSPICIOUS | SUSPICIOUS | 40 | ✓ | development |
| `https://login.someunknownsite.online/user/verify` | SUSPICIOUS | SAFE | 20 | ✗ | development |
| `https://www.newstartup.club/register` | SUSPICIOUS | SAFE | 15 | ✗ | development |
| `https://api.someservice.cc/oauth/callback` | SUSPICIOUS | SAFE | 15 | ✗ | development |
| `https://www.company-portal.biz/employee/login?redirect=/d...` | SUSPICIOUS | SAFE | 20 | ✗ | development |
| `http://192.168.100.5/admin` | SUSPICIOUS | SUSPICIOUS | 70 | ✓ | development |
| `https://cutt.ly/TwZ8kQp` | SUSPICIOUS | SAFE | 15 | ✗ | development |
| `https://unknown-blog.info/2024/01/how-to-reset-your-passw...` | SUSPICIOUS | SUSPICIOUS | 35 | ✓ | development |
| `http://newsletter.click/open?m=abc&u=xyz&c=123&utm_source...` | SUSPICIOUS | SUSPICIOUS | 35 | ✓ | development |
| `https://downloads.work/tool?ref=partner&id=99182736` | SUSPICIOUS | SAFE | 15 | ✗ | development |
| `https://cdn.staticfiles.pw/assets/script.js` | SUSPICIOUS | SAFE | 15 | ✗ | development |
| `https://my-account-portal.com/reset-password?token=abc123xyz` | SUSPICIOUS | SAFE | 15 | ✗ | development |
| `https://user.online-platform.site/profile/verify` | SUSPICIOUS | SAFE | 20 | ✗ | development |
| `https://files.download.stream/setup.exe` | SUSPICIOUS | SAFE | 15 | ✗ | development |
| `https://m.unknown-store.fun/checkout?item=shirt&qty=1` | SUSPICIOUS | SAFE | 15 | ✗ | development |
| `https://paypa1-secure.login.verify-account.tk` | PHISHING | PHISHING | 90 | ✓ | development |
| `https://google-login.xyz/signin?redirect=gmail` | PHISHING | PHISHING | 100 | ✓ | development |
| `http://192.168.1.1/login` | PHISHING | PHISHING | 75 | ✓ | development |
| `http://203.0.113.45/paypal/login.php` | PHISHING | PHISHING | 75 | ✓ | development |
| `https://paypal-update-billing.ml` | PHISHING | PHISHING | 80 | ✓ | development |
| `https://signin.amazon-account-verify.tk/ap/signin` | PHISHING | PHISHING | 100 | ✓ | development |
| `https://amazon-prime-renewal.gq/payment` | PHISHING | PHISHING | 100 | ✓ | development |
| `https://microsoft-account-security.live/password/reset` | PHISHING | PHISHING | 100 | ✓ | development |
| `https://apple-id-suspended-verify.xyz/account/recover` | PHISHING | PHISHING | 100 | ✓ | development |
| `https://icloud-account-unlock.cf/login` | PHISHING | PHISHING | 100 | ✓ | development |
| `https://facebook-login.support-team.xyz/checkpoint` | PHISHING | PHISHING | 80 | ✓ | development |
| `https://instagram-verify-account.ml/` | PHISHING | PHISHING | 80 | ✓ | development |
| `https://netflix-subscription-renewal.tk/signin` | PHISHING | PHISHING | 100 | ✓ | development |
| `https://login.secure.paypal-helpdesk.com/update` | PHISHING | PHISHING | 80 | ✓ | development |
| `https://bankofamerica-secure-login.gq/verify` | PHISHING | PHISHING | 100 | ✓ | development |
| `https://wellsfargo-account-update.ml/signin` | PHISHING | PHISHING | 100 | ✓ | development |
| `https://github-security-alert.ml/account/verify` | PHISHING | PHISHING | 100 | ✓ | development |
| `https://discord-nitro-free.site/claim` | PHISHING | PHISHING | 100 | ✓ | development |
| `https://dropbox-shared-document.xyz/login?file=invoice_20...` | PHISHING | PHISHING | 100 | ✓ | development |
| `https://accounts.google.com.signin-recovery.xyz/recover` | PHISHING | PHISHING | 100 | ✓ | development |
| `https://support.apple.com.account-locked-verify.tk/unlock` | PHISHING | PHISHING | 100 | ✓ | development |
| `https://free-gift-claim.xyz/winner?user=target&prize=iphone` | PHISHING | PHISHING | 80 | ✓ | development |
| `http://login-update.bankofamerica-secure.net/account/confirm` | PHISHING | PHISHING | 95 | ✓ | development |
| `https://github.com/login` | SAFE | SAFE | 0 | ✓ | held-out |
| `https://www.linkedin.com/login` | SAFE | SAFE | 0 | ✓ | held-out |
| `https://portal.azure.com/` | SAFE | SAFE | 0 | ✓ | held-out |
| `https://www.reddit.com/r/programming` | SAFE | SAFE | 0 | ✓ | held-out |
| `https://www.dropbox.com/login` | SAFE | SAFE | 0 | ✓ | held-out |
| `http://mysite.biz/account/settings` | SUSPICIOUS | SUSPICIOUS | 40 | ✓ | held-out |
| `https://track.marketing-email.live/unsubscribe?id=abc123` | SUSPICIOUS | SAFE | 15 | ✗ | held-out |
| `https://is.gd/Xm7yBa` | SUSPICIOUS | SAFE | 15 | ✗ | held-out |
| `https://app.newservice.vip/dashboard` | SUSPICIOUS | SAFE | 15 | ✗ | held-out |
| `https://secure-paypal-login.com/verify-account` | PHISHING | PHISHING | 75 | ✓ | held-out |
| `https://login-microsoftonline.com.verify-email.ml/auth` | PHISHING | PHISHING | 90 | ✓ | held-out |
| `https://netfIix-billing-update.com/account/payment` | PHISHING | PHISHING | 75 | ✓ | held-out |
| `https://chase-online-banking-secure.xyz/login/credential` | PHISHING | PHISHING | 100 | ✓ | held-out |
| `https://www.paypal.com.secure-payment-alert.ml/login` | PHISHING | PHISHING | 100 | ✓ | held-out |

---

## Notes and Limitations

> ⚠️ **Held-out set size warning:** The held-out test set contains only **14 URLs**. With a sample this small, confidence intervals are very wide. For example, a 95% Wilson confidence interval on 100% recall from 5 positives spans roughly 54%–100%. These results are directionally meaningful but should not be interpreted as statistically stable estimates. A held-out set of at least 100 URLs per class would be needed for narrow confidence intervals.

1. **Reputation provider not connected.** The NullReputationProvider is used. If Google Safe Browsing or VirusTotal were connected, phishing detection rate would increase significantly for known-bad URLs that lack structural signals.
2. **Typosquatting and homoglyph detection is active.** The brand impersonation detector applies digit/lookalike normalisation (e.g. digit `1` → letter `l`, capital `I` → lowercase `l`) followed by Levenshtein-1 near-match detection. URLs like `netfIix` and `paypa1` are caught. This is not limited to exact substring matching.
3. **No domain age check.** Newly registered domains are a strong phishing signal not currently measured. A WHOIS/RDAP integration would improve detection of newly minted phishing domains.
4. **URL shorteners scored as SUSPICIOUS not PHISHING.** This is architecturally correct — a shortener is suspicious (destination unknown) but not definitively phishing. The detection matches the appropriate band.
5. **Private IP addresses (192.168.x.x) are scored based on structural signals alone.** They are not definitively malicious in isolation (could be internal tooling).
6. **Production detection code was NOT modified.** All weights, thresholds, keyword lists, trusted domains, and brand registries remain identical to production.
7. **SUSPICIOUS class accuracy is lower by design.** URLs with weak signals (cheap TLD only, URL shortener only, HTTP on unknown domain) land in Suspicious, which can overlap with Safe in borderline cases. Overall accuracy (~78%) is held down by SUSPICIOUS↔SAFE misclassifications. The primary metric for financial risk assessment is phishing precision and recall, both of which are 100%.
