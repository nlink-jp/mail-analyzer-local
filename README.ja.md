# mail-analyzer-local

[mail-analyzer](https://github.com/nlink-jp/mail-analyzer) のローカルLLM版 — OpenAI互換API（LM Studio, Ollama等）を使った不審メール分析。

ルールベース指標 + LLM判定の同一機能を、完全オフラインで実行。GCP/Vertex AI不要。

## 動作要件

- OpenAI互換APIを提供するローカルLLMサーバー（例: [LM Studio](https://lmstudio.ai/)）
- ロード済みモデル（google/gemma-4-26b-a4b, qwen/qwen3.5-9b で動作確認済み）

## インストール

[Releases](https://github.com/nlink-jp/mail-analyzer-local/releases) からダウンロード、またはソースからビルド：

```bash
make build    # → dist/mail-analyzer-local
```

## セットアップ

```bash
export MAIL_ANALYZER_LOCAL_ENDPOINT="http://localhost:1234/v1"
export MAIL_ANALYZER_LOCAL_MODEL="google/gemma-4-26b-a4b"
# export MAIL_ANALYZER_LOCAL_API_KEY="your-key"   # オプション
# export MAIL_ANALYZER_LOCAL_LANG="Japanese"       # オプション
```

## 使い方

```bash
mail-analyzer-local suspicious.eml
mail-analyzer-local --offline suspicious.eml    # ルールベースのみ（LLMなし）
mail-analyzer-local --version
```

出力はstdoutへのJSON（mail-analyzerと同一スキーマ）。

## テスト済みモデル

| モデル | Think OFF | Think ON |
|--------|-----------|----------|
| google/gemma-4-26b-a4b | OK | OK |
| qwen/qwen3.5-9b | OK | OK |

## nlk統合

[nlk](https://github.com/nlink-jp/nlk) ライブラリをLLM周辺ユーティリティとして使用：

- `guard` — プロンプトインジェクション防御（128ビットノンスタグXML）
- `strip` — 思考/推論タグ除去（Gemma 4, Qwen, DeepSeek対応）
- `jsonfix` — LLM出力からのJSON抽出・修復
- `backoff` — APIリトライ用指数バックオフ
- `validate` — ルールベース出力検証

## ライセンス

MIT
