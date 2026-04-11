# Changelog

## v0.2.0 (2026-04-11)

### Improvements

- Prompt rewritten for local LLM optimization (shorter, affirmative, indicator-aware)
- Pre-computed indicator summary now explicitly states clean/alert status
- HINT system provides safety guidance based on authentication + indicator state
- Credential harvesting detection rule added (suspicious link + password request)

### Documentation

- Model Evaluation Guide (en/ja) with 6 model configurations tested
- Recommended model: google/gemma-4-26b-a4b (Think OFF) — 100% accuracy
- Critical finding: Think mode degrades phishing detection across all models

### Evaluation Results (10 real emails)

| Model | Think | Accuracy |
|-------|-------|----------|
| google/gemma-4-26b-a4b | OFF | 100% |
| google/gemma-4-26b-a4b | ON | 80% |
| qwen/qwen3.5-35b-a3b | OFF | 90% |
| qwen/qwen3.5-35b-a3b | ON | 90% |
| qwen/qwen3.5-9b | OFF | 90% |
| openai/gpt-oss-20b | — | ~60% |

## v0.1.0 (2026-04-11)

Initial release.

### Features

- Email parsing (.eml/.msg) — ported from mail-analyzer
- Rule-based indicator analysis (authentication, sender, URLs, attachments, routing) — ported from mail-analyzer
- LLM judgment via OpenAI-compatible API (LM Studio, Ollama, etc.)
- `--offline` mode (indicators only, no LLM)
- nlk library integration (guard, jsonfix, strip, backoff, validate)

### Tested Models

- google/gemma-4-26b-a4b (think ON/OFF)
- qwen/qwen3.5-9b (think ON/OFF)
