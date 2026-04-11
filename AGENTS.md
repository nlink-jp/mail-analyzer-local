# AGENTS.md — mail-analyzer-local

## Summary

Local LLM version of mail-analyzer. Uses OpenAI-compatible API instead of Vertex AI.
Integrates nlk library for prompt injection defense, JSON repair, thinking tag removal,
backoff, and validation.

## Build & Test

```bash
make build        # → dist/mail-analyzer-local
make test         # go test ./...
go test ./...     # same without Makefile
```

## Project Structure

```
mail-analyzer-local/
├── main.go
├── internal/
│   ├── parser/      # EML/MSG parsing (ported from mail-analyzer)
│   ├── indicator/   # Rule-based analysis (ported from mail-analyzer)
│   ├── llm/         # OpenAI-compatible LLM client + nlk integration
│   │   ├── client.go    # HTTP client, strip, jsonfix, validate
│   │   └── prompt.go    # System/user prompt with nlk/guard
│   ├── analyzer/    # Composite analysis (indicators + LLM → result)
│   └── config/      # Environment variable config
├── testdata/        # Test .eml files
├── docs/
│   └── en/          # RFP document
├── Makefile
└── README.md
```

## Environment Variables

```
MAIL_ANALYZER_LOCAL_ENDPOINT  (required) OpenAI-compatible API endpoint
MAIL_ANALYZER_LOCAL_MODEL     (required) Model name
MAIL_ANALYZER_LOCAL_API_KEY   (optional) API key
MAIL_ANALYZER_LOCAL_LANG      (optional) Output language
```

## Gotchas

- Parser and indicator packages are copied from mail-analyzer (not shared via library)
- LLM client uses net/http directly — no OpenAI SDK dependency
- Local models may produce thinking tags — nlk/strip handles removal
- Local models may produce malformed JSON — nlk/jsonfix handles repair
- The `--offline` mode uses the same heuristic logic as mail-analyzer
