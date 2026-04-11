# mail-analyzer-local

Local LLM version of [mail-analyzer](https://github.com/nlink-jp/mail-analyzer) — suspicious email analysis using OpenAI-compatible API (LM Studio, Ollama, etc.).

Same rule-based indicators + LLM judgment, but runs entirely offline with a local model. No GCP/Vertex AI required.

## Requirements

- Local LLM server running OpenAI-compatible API (e.g. [LM Studio](https://lmstudio.ai/))
- A loaded model (tested with google/gemma-4-26b-a4b and qwen/qwen3.5-9b)

## Install

Download from [Releases](https://github.com/nlink-jp/mail-analyzer-local/releases), or build from source:

```bash
make build    # → dist/mail-analyzer-local
```

## Setup

```bash
export MAIL_ANALYZER_LOCAL_ENDPOINT="http://localhost:1234/v1"
export MAIL_ANALYZER_LOCAL_MODEL="google/gemma-4-26b-a4b"
# export MAIL_ANALYZER_LOCAL_API_KEY="your-key"   # optional
# export MAIL_ANALYZER_LOCAL_LANG="Japanese"       # optional
```

## Usage

```bash
mail-analyzer-local suspicious.eml
mail-analyzer-local --offline suspicious.eml    # rule-based only, no LLM
mail-analyzer-local --version
```

Output is JSON to stdout (same schema as mail-analyzer).

## Tested Models

| Model | Think OFF | Think ON |
|-------|-----------|----------|
| google/gemma-4-26b-a4b | OK | OK |
| qwen/qwen3.5-9b | OK | OK |

## Built with nlk

Uses [nlk](https://github.com/nlink-jp/nlk) library for LLM peripheral utilities:

- `guard` — prompt injection defense (128-bit nonce-tagged XML)
- `strip` — thinking/reasoning tag removal (Gemma 4, Qwen, DeepSeek)
- `jsonfix` — JSON extraction and repair from LLM output
- `backoff` — exponential backoff for API retries
- `validate` — rule-based output validation

## License

MIT
