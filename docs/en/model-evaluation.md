# Model Evaluation Guide

> Evaluated: 2026-04-12
> mail-analyzer-local v0.3.0 (HINT alert count fix + expanded dataset)
> Dataset: 12 real emails (5 safe, 7 unsafe)

## Results

| Model | Size | Think | Safe Accuracy | Unsafe Accuracy | Overall |
|-------|------|-------|--------------|----------------|---------|
| **google/gemma-4-26b-a4b** | 26B (A4B) | **OFF** | **5/5 (100%)** | **5/5 (100%)** | **100%** |
| google/gemma-4-26b-a4b | 26B (A4B) | ON | 5/5 (100%) | 3/5 (60%) | 80% |
| qwen/qwen3.5-35b-a3b | 35B (A3B) | OFF | 4/5 (80%) | 5/5 (100%) | 90% |
| qwen/qwen3.5-35b-a3b | 35B (A3B) | ON | 5/5 (100%) | 4/5 (80%) | 90% |
| qwen/qwen3.5-9b | 9B | OFF | 4/5 (80%) | 5/5 (100%) | 90% |
| openai/gpt-oss-20b | 20B | — | ~4/5 (80%) | 2/5 (40%) | ~60% |

## Recommendations

### Best Configuration

**google/gemma-4-26b-a4b with Think OFF** — the only configuration achieving 100% accuracy on the evaluation dataset.

### Model Selection Guidelines

- **26B+ models recommended** for reliable email analysis
- **MoE models (A4B/A3B)** perform well despite lower active parameters
- **9B models** can detect phishing but produce false positives on marketing emails
- **Model architecture matters more than raw parameter count** — GPT-OSS 20B underperformed Qwen 3.5 9B

### Critical Finding: Think Mode Degrades Phishing Detection

Enabling thinking/reasoning mode consistently reduces phishing detection accuracy across all tested models:

| Model | Think OFF → ON | Impact |
|-------|---------------|--------|
| Gemma 4 26B | 100% → 80% | -20% |
| Qwen 3.5 35B | 90% → 90% | (shifted: safe↑ unsafe↓) |

**Root cause**: During the thinking process, the model reasons about indicators that appear normal (SPF pass, sender clean) and talks itself into a "safe" conclusion, overriding content-level phishing signals. This is especially problematic for sophisticated phishing emails that pass authentication checks.

**Recommendation: Disable thinking mode** for email analysis tasks. The structured prompt + pre-computed indicators provide sufficient guidance without the model needing to reason through intermediate steps.

### v0.3.0 Fix: Auth Failures in Alert Count

In v0.2.0, the HINT system only counted sender/URL/attachment alerts. Emails with SPF/DKIM/DMARC failures but no other indicators received a "likely safe" hint, causing false negatives. v0.3.0 includes authentication failures and routing anomalies in the alert count, with auth-failure-aware HINT branches.

Two new unsafe samples were added to the dataset:
- **Pairs impersonation** — SPF/DKIM/DMARC all fail (p=REJECT), sent from localhost
- **Brand counterfeit spam** — SPF fail, DKIM/DMARC pass, sent from localhost on Google Cloud

Both were previously misclassified as safe by Gemma 4 and are now correctly detected.

### False Negative Pattern

The most difficult phishing type for local models: emails that **pass SPF/DMARC authentication** while containing **credential harvesting links on free hosting**. The "kiwi.ne.jp password" test case was the most commonly missed, where:
- SPF: pass, DMARC: pass, sender: clean
- But the link pointed to Azure Blob Storage (`web.core.windows.net`)
- Human analysts immediately recognize this as suspicious

This pattern requires the model to understand that legitimate services don't host password reset pages on generic cloud storage — a nuance that smaller models struggle with.

### False Positive Pattern

Marketing emails with promotional language ("50% OFF", "limited time") are sometimes flagged as phishing or spam, especially by smaller models (9B). The current prompt mitigates this by instructing the model to treat authenticated marketing emails as safe.

## Test Environment

- **Hardware**: Apple Silicon Mac
- **Runtime**: LM Studio
- **Quantization**: Default LM Studio settings (Q4_K_M or similar)
- **Temperature**: Default (not explicitly set by mail-analyzer-local)

## Dataset Description

### Safe Emails (5)
- Japanese marketing/newsletter emails
- All from legitimate commercial services
- Contains CDN links (CloudFront, S3), tracking URLs, promotional language

### Unsafe Emails (7)
- Real phishing/scam emails targeting Japanese users
- Tactics: credential harvesting, fake security alerts, refund fraud, brand impersonation, counterfeit goods
- Mix of authentication results (some pass SPF/DMARC, some fail all checks)
