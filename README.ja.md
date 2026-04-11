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

## 推奨モデル

**google/gemma-4-26b-a4b（Think OFF）** — 10通の評価データセット（safe 5通、フィッシング 5通）で100%精度を達成。

| モデル | サイズ | Think | 精度 |
|--------|--------|-------|------|
| **google/gemma-4-26b-a4b** | 26B | **OFF** | **100%** |
| qwen/qwen3.5-35b-a3b | 35B | OFF | 90% |
| qwen/qwen3.5-9b | 9B | OFF | 90% |

**重要：メール分析ではthinkingモードを無効にすること。** Thinkモードはindicatorsの正常性を過度に推論し、フィッシング検出精度を低下させる。

詳細は[モデル評価ガイド](docs/ja/model-evaluation.ja.md)を参照。

## nlk統合

[nlk](https://github.com/nlink-jp/nlk) ライブラリをLLM周辺ユーティリティとして使用：

- `guard` — プロンプトインジェクション防御（128ビットノンスタグXML）
- `strip` — 思考/推論タグ除去（Gemma 4, Qwen, DeepSeek対応）
- `jsonfix` — LLM出力からのJSON抽出・修復
- `backoff` — APIリトライ用指数バックオフ
- `validate` — ルールベース出力検証

## ライセンス

MIT
