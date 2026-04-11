// Package llm provides OpenAI-compatible LLM integration for content analysis.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/nlink-jp/mail-analyzer-local/internal/config"
	"github.com/nlink-jp/nlk/backoff"
	"github.com/nlink-jp/nlk/jsonfix"
	"github.com/nlink-jp/nlk/strip"
	"github.com/nlink-jp/nlk/validate"
)

const maxRetries = 5

// Judgment is the structured LLM analysis result.
type Judgment struct {
	IsSuspicious bool     `json:"is_suspicious"`
	Category     string   `json:"category"`
	Confidence   float64  `json:"confidence"`
	Summary      string   `json:"summary"`
	Reasons      []string `json:"reasons"`
	Tags         []string `json:"tags"`
}

// chatRequest is the OpenAI-compatible chat completion request.
type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatResponse is the OpenAI-compatible chat completion response.
type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Analyze sends the email data to a local LLM and returns a structured judgment.
func Analyze(ctx context.Context, cfg *config.Config, systemPrompt, userPrompt string) (*Judgment, error) {
	reqBody := chatRequest{
		Model: cfg.Model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
	}

	bo := backoff.New(
		backoff.WithBase(2*time.Second),
		backoff.WithMax(30*time.Second),
	)

	var lastErr error
	for attempt := range maxRetries + 1 {
		text, err := callAPI(ctx, cfg, reqBody)
		if err == nil {
			judgment, parseErr := parseJudgment(text)
			if parseErr != nil {
				return nil, fmt.Errorf("parsing LLM response: %w", parseErr)
			}
			return judgment, nil
		}

		lastErr = err
		errStr := strings.ToLower(err.Error())
		retryable := false
		for _, k := range []string{"429", "503", "500", "timeout", "connection refused", "eof"} {
			if strings.Contains(errStr, k) {
				retryable = true
				break
			}
		}

		if !retryable || attempt == maxRetries {
			return nil, fmt.Errorf("LLM analysis failed: %w", err)
		}

		wait := bo.Duration(attempt)
		log.Printf("LLM call failed (attempt %d/%d), retrying in %v: %v",
			attempt+1, maxRetries+1, wait.Round(time.Second), err)
		time.Sleep(wait)
	}

	return nil, fmt.Errorf("LLM analysis failed after %d retries: %w", maxRetries, lastErr)
}

// callAPI performs a single HTTP call to the OpenAI-compatible endpoint.
func callAPI(ctx context.Context, cfg *config.Config, reqBody chatRequest) (string, error) {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshaling request: %w", err)
	}

	url := strings.TrimRight(cfg.Endpoint, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return "", fmt.Errorf("parsing API response: %w", err)
	}

	if chatResp.Error != nil {
		return "", fmt.Errorf("API error: %s", chatResp.Error.Message)
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("empty response from LLM")
	}

	return chatResp.Choices[0].Message.Content, nil
}

// parseJudgment extracts and validates a Judgment from raw LLM text.
// Uses nlk/strip, nlk/jsonfix, and nlk/validate.
func parseJudgment(text string) (*Judgment, error) {
	// 1. Strip thinking/reasoning tags (local models often emit these).
	cleaned := strip.ThinkTags(text)

	// 2. Extract and repair JSON.
	var j Judgment
	if err := jsonfix.ExtractTo(cleaned, &j); err != nil {
		return nil, fmt.Errorf("JSON extraction: %w (raw: %.200s)", err, text)
	}

	// 3. Validate and fix.
	validCategories := []string{"phishing", "spam", "malware-delivery", "bec", "scam", "safe"}
	if err := validate.Run(
		validate.OneOf("category", j.Category, validCategories...),
	); err != nil {
		j.Category = "safe" // fallback
	}

	if j.Confidence < 0 {
		j.Confidence = 0
	}
	if j.Confidence > 1 {
		j.Confidence = 1
	}
	if len(j.Tags) > 5 {
		j.Tags = j.Tags[:5]
	}
	if len(j.Reasons) > 5 {
		j.Reasons = j.Reasons[:5]
	}

	return &j, nil
}
