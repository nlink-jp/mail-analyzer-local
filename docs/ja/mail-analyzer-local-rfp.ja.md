# RFP: mail-analyzer-local

> Generated: 2026-04-11
> Status: Draft

## 1. Problem Statement

mail-analyzer は Vertex AI 専用であり、GCP の無い環境では動かせない。mail-analyzer-local は、LLM バックエンドを OpenAI 互換 API（LM Studio）経由のローカル LLM に置き換えた別プロジェクトであり、完全オフラインでのメール分析を可能にする。ルールベースの分析（parser、indicators）は mail-analyzer からそのまま移植する。本プロジェクトは、nlk ライブラリの実環境での検証も兼ねる。

## 2. Functional Specification

### Commands / API Surface

mail-analyzer と CLI 互換:

```
mail-analyzer-local [--offline] <file.eml|file.msg>
mail-analyzer-local --version
```

### Input / Output

- **Input**: `.eml` または `.msg` ファイルのパス
- **Output**: 構造化された JSON を stdout へ（mail-analyzer と同一スキーマ）

### Configuration

| 環境変数 | 説明 | 必須 |
|---------------------|-------------|----------|
| `MAIL_ANALYZER_LOCAL_ENDPOINT` | OpenAI 互換 API のエンドポイント（例: `http://localhost:1234/v1`） | Yes |
| `MAIL_ANALYZER_LOCAL_MODEL` | モデル名 | Yes |
| `MAIL_ANALYZER_LOCAL_API_KEY` | API キー（任意。未設定なら省略する） | No |
| `MAIL_ANALYZER_LOCAL_LANG` | 出力言語（任意） | No |

### External Dependencies

- OpenAI 互換 API を提供するローカル LLM サーバー（LM Studio、Ollama など）
- nlk ライブラリ（`github.com/nlink-jp/nlk`）

## 3. Design Decisions

### Tech Stack

- **Go** — コードの再利用を最大化するため、mail-analyzer と同じにする
- **net/http + encoding/json** — OpenAI 互換 API を直接呼び、SDK に依存しない
- **nlk** — guard、jsonfix、strip、backoff、validate

### Code Reuse from mail-analyzer

| パッケージ | 対応 |
|---------|--------|
| `internal/parser/` | そのまま移植（eml/msg の解析） |
| `internal/indicator/` | そのまま移植（ルールベースの分析） |
| `internal/llm/` | OpenAI 互換クライアントに**置き換え** |
| `internal/analyzer/` | LLM クライアントを差し替えて移植 |
| `internal/config/` | ローカル向けの環境変数に合わせて書き直し |

### nlk Integration

| nlk パッケージ | 用途 |
|------------|-------|
| `guard` | プロンプトインジェクション防御（nonce タグ付き XML） |
| `strip` | ローカル LLM の出力から thinking/reasoning タグを除去 |
| `jsonfix` | LLM 応答から JSON を抽出・修復 |
| `backoff` | API エラー時のリトライ待ち時間の計算 |
| `validate` | LLM の判定出力を検証 |

### Out of Scope

- Vertex AI 対応（mail-analyzer の領分）
- ストリーミング応答
- 複数バックエンド対応
- 構造化出力 / JSON モード（モデル依存で信頼できない）

## 4. Development Plan

### Phase 1: Core

- mail-analyzer から `parser/` と `indicator/` を移植
- OpenAI 互換の LLM クライアントを実装（net/http）
- nlk のパッケージを統合（guard、jsonfix、strip、backoff、validate）
- ユニットテスト

### Phase 2: Features

- `--offline` モード（ルールベースのみ。LLM を使わない）
- エラー処理（接続拒否、タイムアウト、モデル未ロード）
- LM Studio での E2E テスト

### Phase 3: Release

- ドキュメント（README.md、README.ja.md、CHANGELOG.md、AGENTS.md）
- リリース

## 5. Required API Scopes / Permissions

なし（クラウド API）。ローカル LLM サーバーが起動していることが必要。

## 6. Series Placement

Series: **util-series**
理由: mail-analyzer と同じシリーズ。バックエンドの異なる関連ツールである。

## 7. External Platform Constraints

- `response_format: {"type": "json_object"}` の対応はモデルによって異なる — 壊れた出力は jsonfix が扱う
- 出力に現れる thinking/reasoning タグはモデルによって異なる — 除去は strip が扱う
- 文脈長はモデルによって異なる — mail-analyzer の本文 3000 文字上限がこれを緩和する
- LM Studio の API は OpenAI API のサブセット — 使うのは `/v1/chat/completions` のみ

---

## Discussion Log

1. **Motivation**: mail-analyzer は Vertex AI 専用。GCP の無い環境向けにローカル LLM 版が必要
2. **Approach**: mail-analyzer を複数バックエンド対応に改造するのではなく、新規プロジェクトとする。単純さを保つ
3. **LLM backend**: LM Studio 経由の OpenAI 互換 API。API のサブセットで SDK が問題を起こすのを避けるため、net/http で直接実装する
4. **nlk validation**: 本プロジェクトは nlk の 5 パッケージすべての実環境での検証を兼ねる
5. **API key**: LM Studio の API キー対応のため、`MAIL_ANALYZER_LOCAL_API_KEY` を任意で用意する
