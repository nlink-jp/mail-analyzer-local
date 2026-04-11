# Changelog

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
