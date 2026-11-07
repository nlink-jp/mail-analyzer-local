# Changelog

## v0.5.0 (2026-11-07)

The move to mailparse is done together with mail-analyzer, eml-to-jsonl and msg-to-jsonl, so the
four read mail the same way. Changes against v0.4.0:

### Changed

- **The message is read by [mailparse](https://github.com/nlink-jp/mailparse) v0.2.0** instead of
  the in-tool parsers (`net/mail` and an `.msg` reader on the community package
  `richardlehane/mscfb`, which is no longer a dependency). mail-analyzer-local and mail-analyzer
  share the parser and indicator code, and eml-to-jsonl and msg-to-jsonl read mail the same way.
  - The format is recognized by content (`.eml`, `.msg`, `winmail.dat`), not by the file extension.
  - `from` lists every From mailbox; display names that are not plain atoms are quoted
    (`Mailbox.String()`), so a name that decodes to an address stays a name.
  - A `.msg` gets its `date`, its Authentication-Results and its Bcc recipients (which were missing
    or listed under To); files larger than 64 MiB are refused.
- **Authentication: the top Authentication-Results decides** (the recipient's own server adds it;
  a forged field sits below). Every field is kept in `authentication.raw` and given to the LLM
  inside the untrusted-data tags; `authentication.conflicting` flags a lower field that disagrees.
  It is information only: in 12 real messages, 10 carried several fields and all 10 disagreed
  through honest forwarding.
- **Sender checks run over every From, Return-Path and Reply-To mailbox**: a check fires when any
  combination fires, so a second From or Reply-To cannot hide the first. Domains and display names
  come from the parsed mailboxes, not from re-parsing a display string.
- **Attached (forwarded) messages are searched**: their URLs and attachments are checked and carry
  `layer` (a mailparse `Message.Walk` path). Sender and authentication checks stay on the outer
  message, and the LLM sees the outer body only.
- **URLs in text/* attachments** (a calendar invitation, say) are checked and carry `attachment`.
- An attachment without a name has an empty `filename` (it was `"attachment"`), and a text part
  other than text/plain and text/html (an inline text/calendar, say) is an attachment, no longer a
  body: it appears in `indicators.attachments`, and its URLs carry `attachment`.

### Added

- `warnings` in the result: mailparse's warnings for the message and every attached message,
  always an array. The LLM is given the warning codes (no message text).
- The prompt notes a disagreeing lower Authentication-Results as a NOTE line, not counted as an
  alert, and says where a suspicious URL or attachment was found.

## v0.4.0 (2026-07-12)

### Removed

- **darwin/amd64 (Intel) pre-built binary.** macOS releases now ship
  **arm64 only**, per the org-wide policy (darwin is Apple-Silicon only; no
  universal binaries). Intel Mac users can build from source.

### Changed

- **Linux release archives are now `.tar.gz`** (darwin/windows remain `.zip`),
  per `nlink-jp/.github` CONVENTIONS.md §Release Archive Standard. Archives
  still bundle `LICENSE` + `README.md` alongside the canonical binary.
- **darwin code-signature identifier** is now the canonical
  `mail-analyzer-local` (was `mail-analyzer-local-darwin-arm64`), set via
  `codesign -i` so it stays stable after the archived binary is renamed to
  its canonical name.

No change to the binary's behaviour — a packaging / build-config release.

## v0.3.4 (2026-05-23)

### Added

- **`package` Makefile target.** Build-all now produces the
  cross-compiled binaries (and codesigns the darwin ones); the new
  `package` target zips each with LICENSE + README.md using
  versioned naming
  (`mail-analyzer-local-vX.Y.Z-<os>-<arch>.zip`) and notarizes the
  darwin zips. Previously zip was inlined into `build-all`,
  producing version-less filenames.

### Changed

- **Darwin releases are now Developer ID signed and Apple-notarized.**
  `mail-analyzer-local-v0.3.4-darwin-{amd64,arm64}.zip` carry
  full Apple Developer ID Application signatures and notarization
  tickets from Apple. End users on macOS no longer need to bypass
  Gatekeeper with right-click → Open or
  `xattr -d com.apple.quarantine` on first launch; local users
  who place `mail-analyzer-local` under Dropbox-synced (or any
  other FileProvider-managed) paths are no longer killed by
  macOS's ad-hoc + provenance distrust policy. Pipeline:
  `scripts/codesign-darwin.sh` + `scripts/notarize-darwin.sh`,
  driven by `make package`. Adopts the org-wide convention in
  `nlink-jp/.github` CONVENTIONS.md §Code Signing.
- **Release zip filenames now embed the version**
  (`mail-analyzer-local-vX.Y.Z-<os>-<arch>.zip`), aligning with
  sibling util-series tools. Previous v0.3.3 was source-only
  (no asset zips on GitHub Releases).

No behaviour change to the binary itself — feature-wise this is
identical to v0.3.3.

## v0.3.3 (2026-05-03)

### Fixes

- Bump nlk to v0.5.2 — strip: ignore `<tag>` matches inside markdown inline-code spans so LLM responses that explain the literal `<think>` tag don't get truncated mid-explanation under the unclosed-tag rule.
- Makefile: auto-detect version from git tag (no more hardcoded VERSION).

## v0.3.2 (2026-04-12)

### Fixes

- Update nlk to v0.5.1 — jsonfix: handle zero-width Unicode spaces and parenthesized prose

## v0.3.1 (2026-04-12)

### Security

- Update nlk to v0.5.0 — handle `guard.Wrap()` error return (tag collision defense-in-depth)

## v0.3.0 (2026-04-12)

### Improvements

- HINT system now counts auth failures (SPF/DKIM/DMARC fail) and routing anomalies in alertCount
- Auth-failure-aware HINT branches prevent "likely safe" hint on spoofed emails
- 2 new unsafe eval samples added (Pairs impersonation, brand counterfeit spam)
- Prompt builder unit tests added

### Evaluation Results (12 real emails: 5 safe, 7 unsafe)

| Model | Think | Accuracy |
|-------|-------|----------|
| google/gemma-4-26b-a4b | OFF | 100% (12/12) |

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
## [Unreleased]

### Fixed

- **`make verify-release` now fails closed.** Its last block chained unzip, the
  packaged binary's `--version` and `spctl` with `&&` and ended the whole chain
  in `|| true`, so a zip that did not unpack or a binary that did not run exited
  0 and the upload proceeded. Each step is now judged on its own, the packaged
  binary's `--version` must contain the tag being released, and only the
  informational `spctl` line may be ignored. Matches the org template
  (CONVENTIONS.md §Code Signing → Verifying a release).
- **The Linux archives no longer carry macOS file metadata.** macOS `tar` wrote
  each bundled file's extended attributes (`com.apple.provenance`, and a Dropbox
  attribute where the tree is synced) into the `.tar.gz` twice: as AppleDouble
  `._` members, which GNU tar extracts as stray `._<name>` files beside the real
  ones, and as `LIBARCHIVE.xattr.*` / `SCHILY.xattr.*` pax headers, which it
  reports as unknown keywords. `make package` now archives with
  `COPYFILE_DISABLE=1 tar --no-xattrs`; each setting stops one of the two.
  Archives already published still carry them; the files themselves are
  unaffected.

### Internal

- `make verify-release` also judges each Linux archive: no AppleDouble or other
  macOS metadata members — listed with `--options 'tar:!mac-ext'`, because a
  plain macOS listing folds `._` members away — no extended attributes as pax
  headers, and exactly the canonical binary, `README.md` and `LICENSE`, compared
  in the C locale.
- The Linux-archive check in `make verify-release` reads each archive's pax
  headers with Python's `tarfile` instead of grepping the decompressed stream,
  which also matched file text that names the keywords (a bundled CHANGELOG,
  for one).

