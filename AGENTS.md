# AGENTS.md — mail-analyzer-local

## Summary

Local LLM version of mail-analyzer. Uses OpenAI-compatible API instead of Vertex AI.
Integrates nlk library for prompt injection defense, JSON repair, thinking tag removal,
backoff, and validation.

## Build & Test

```bash
make build        # → dist/mail-analyzer-local
make test         # go test ./...
make verify-release  # gate: notarized, fresh, runs at this version, clean linux archives (run before upload)
go test ./...     # same without Makefile
```

## Project Structure

```
mail-analyzer-local/
├── main.go
├── internal/
│   ├── parser/      # mailparse.Message → Email (same code as mail-analyzer)
│   ├── indicator/   # Rule-based analysis (same code as mail-analyzer)
│   ├── llm/         # OpenAI-compatible LLM client + nlk integration
│   │   ├── client.go    # HTTP client, strip, jsonfix, validate
│   │   ├── prompt.go    # System/user prompt with nlk/guard
│   │   └── prompt_test.go # HINT logic unit tests
│   ├── analyzer/    # Composite analysis (indicators + LLM → result)
│   └── config/      # Environment variable config
├── testdata/        # Test .eml files + eval dataset (5 safe, 7 unsafe)
├── docs/
│   ├── en/          # RFP, model evaluation guide
│   └── ja/          # Model evaluation guide (ja)
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

- **Twin of mail-analyzer**: `internal/parser`, `internal/indicator` and `internal/analyzer` are the
  same code in both, differing only in import paths (and, in analyzer.go, the LLM call). Change them in
  both repositories together and compare with the import paths normalized.
- **All parsing is mailparse** (`github.com/nlink-jp/mailparse`). A parsing defect is fixed and
  released in mailparse first, never worked around here. Addresses become text only through
  `Mailbox.String()`.
- **Authentication-Results: the top field decides**; a disagreeing lower field is a NOTE line in the
  prompt, not an alert (honest forwarding produces it in most real mail).
- LLM client uses net/http directly — no OpenAI SDK dependency
- Local models may produce thinking tags — nlk/strip handles removal
- Local models may produce malformed JSON — nlk/jsonfix handles repair
- The `--offline` mode uses the same heuristic logic as mail-analyzer
