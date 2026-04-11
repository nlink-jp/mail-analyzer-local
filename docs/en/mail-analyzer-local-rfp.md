# RFP: mail-analyzer-local

> Generated: 2026-04-11
> Status: Draft

## 1. Problem Statement

mail-analyzer is Vertex AI exclusive and cannot operate in environments without GCP. mail-analyzer-local is a separate project that replaces the LLM backend with a local LLM via OpenAI-compatible API (LM Studio), enabling fully offline email analysis. The rule-based analysis (parser, indicators) is ported directly from mail-analyzer. This project also serves as a real-world validation of the nlk library.

## 2. Functional Specification

### Commands / API Surface

CLI-compatible with mail-analyzer:

```
mail-analyzer-local [--offline] <file.eml|file.msg>
mail-analyzer-local --version
```

### Input / Output

- **Input**: `.eml` or `.msg` file path
- **Output**: Structured JSON to stdout (same schema as mail-analyzer)

### Configuration

| Environment Variable | Description | Required |
|---------------------|-------------|----------|
| `MAIL_ANALYZER_LOCAL_ENDPOINT` | OpenAI-compatible API endpoint (e.g. `http://localhost:1234/v1`) | Yes |
| `MAIL_ANALYZER_LOCAL_MODEL` | Model name | Yes |
| `MAIL_ANALYZER_LOCAL_API_KEY` | API key (optional, skipped if unset) | No |
| `MAIL_ANALYZER_LOCAL_LANG` | Output language (optional) | No |

### External Dependencies

- Local LLM server running OpenAI-compatible API (LM Studio, Ollama, etc.)
- nlk library (`github.com/nlink-jp/nlk`)

## 3. Design Decisions

### Tech Stack

- **Go** — same as mail-analyzer for maximum code reuse
- **net/http + encoding/json** — direct OpenAI-compatible API calls, no SDK dependency
- **nlk** — guard, jsonfix, strip, backoff, validate

### Code Reuse from mail-analyzer

| Package | Action |
|---------|--------|
| `internal/parser/` | Port as-is (eml/msg parsing) |
| `internal/indicator/` | Port as-is (rule-based analysis) |
| `internal/llm/` | **Replace** with OpenAI-compatible client |
| `internal/analyzer/` | Port with LLM client swap |
| `internal/config/` | Rewrite for local env vars |

### nlk Integration

| nlk Package | Usage |
|------------|-------|
| `guard` | Prompt injection defense (nonce-tagged XML) |
| `strip` | Remove thinking/reasoning tags from local LLM output |
| `jsonfix` | Extract and repair JSON from LLM response |
| `backoff` | Retry wait calculation for API errors |
| `validate` | Validate LLM judgment output |

### Out of Scope

- Vertex AI support (mail-analyzer's domain)
- Streaming responses
- Multi-backend support
- Structured output / JSON mode (model-dependent, unreliable)

## 4. Development Plan

### Phase 1: Core

- Port `parser/` and `indicator/` from mail-analyzer
- Implement OpenAI-compatible LLM client (net/http)
- Integrate nlk packages (guard, jsonfix, strip, backoff, validate)
- Unit tests

### Phase 2: Features

- `--offline` mode (rule-based only, no LLM)
- Error handling (connection refused, timeout, model not loaded)
- E2E testing with LM Studio

### Phase 3: Release

- Documentation (README.md, README.ja.md, CHANGELOG.md, AGENTS.md)
- Release

## 5. Required API Scopes / Permissions

None (cloud API). Requires a local LLM server to be running.

## 6. Series Placement

Series: **util-series**
Reason: Same series as mail-analyzer. Related tool with different backend.

## 7. External Platform Constraints

- `response_format: {"type": "json_object"}` support varies by model — jsonfix handles malformed output
- Thinking/reasoning tags in output vary by model — strip handles removal
- Context length varies by model — mail-analyzer's 3000-char body limit mitigates this
- LM Studio API is a subset of OpenAI API — only `/v1/chat/completions` is used

---

## Discussion Log

1. **Motivation**: mail-analyzer is Vertex AI exclusive. Need a local LLM version for GCP-free environments
2. **Approach**: New project rather than multi-backend modification of mail-analyzer. Keep things simple
3. **LLM backend**: OpenAI-compatible API via LM Studio. Direct net/http implementation to avoid SDK issues with API subsets
4. **nlk validation**: This project serves as real-world validation of all 5 nlk packages
5. **API key**: Optional `MAIL_ANALYZER_LOCAL_API_KEY` for LM Studio's API key support
