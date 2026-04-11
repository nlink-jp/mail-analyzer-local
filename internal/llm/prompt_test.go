package llm

import (
	"strings"
	"testing"

	"github.com/nlink-jp/mail-analyzer-local/internal/indicator"
	"github.com/nlink-jp/mail-analyzer-local/internal/parser"
)

func TestBuildUserPromptHintAuthAllPass(t *testing.T) {
	_, tag := BuildSystemPrompt("")
	email := &parser.Email{
		Subject: "Newsletter",
		From:    "info@example.com",
		To:      []string{"user@example.com"},
	}
	ind := &indicator.Indicators{
		Authentication: indicator.AuthResult{SPF: "pass", DKIM: "pass", DMARC: "pass"},
		Sender:         indicator.SenderResult{},
	}

	prompt, err := BuildUserPrompt(tag, email, ind)
	if err != nil {
		t.Fatalf("BuildUserPrompt: %v", err)
	}

	if !strings.Contains(prompt, "very likely a legitimate email") {
		t.Error("all-pass + clean sender should produce 'very likely legitimate' hint")
	}
}

func TestBuildUserPromptHintAuthFail(t *testing.T) {
	_, tag := BuildSystemPrompt("")
	email := &parser.Email{
		Subject: "Test",
		From:    "mail@spoofed.com",
		To:      []string{"user@example.com"},
	}
	ind := &indicator.Indicators{
		Authentication: indicator.AuthResult{SPF: "fail", DKIM: "fail", DMARC: "fail"},
		Sender:         indicator.SenderResult{},
	}

	prompt, err := BuildUserPrompt(tag, email, ind)
	if err != nil {
		t.Fatalf("BuildUserPrompt: %v", err)
	}

	if strings.Contains(prompt, "likely safe") {
		t.Error("auth all-fail must NOT produce 'likely safe' hint")
	}
	if !strings.Contains(prompt, "authentication checks FAILED") {
		t.Error("auth all-fail should produce strong spoofing warning hint")
	}
}

func TestBuildUserPromptHintAuthPartialFail(t *testing.T) {
	_, tag := BuildSystemPrompt("")
	email := &parser.Email{
		Subject: "Test",
		From:    "mail@example.com",
		To:      []string{"user@example.com"},
	}
	ind := &indicator.Indicators{
		Authentication: indicator.AuthResult{SPF: "fail", DKIM: "pass", DMARC: "pass"},
		Sender:         indicator.SenderResult{},
		Routing: indicator.RoutingResult{
			SuspiciousHops: []string{"localhost/unknown origin: from localhost"},
		},
	}

	prompt, err := BuildUserPrompt(tag, email, ind)
	if err != nil {
		t.Fatalf("BuildUserPrompt: %v", err)
	}

	if strings.Contains(prompt, "likely safe") {
		t.Error("partial auth fail with routing anomaly must NOT produce 'likely safe' hint")
	}
	if !strings.Contains(prompt, "warrants careful scrutiny") {
		t.Errorf("partial auth fail + routing should warrant scrutiny, got:\n%s", prompt)
	}
}

func TestBuildUserPromptHintRoutingOnly(t *testing.T) {
	_, tag := BuildSystemPrompt("")
	email := &parser.Email{
		Subject: "Test",
		From:    "mail@example.com",
		To:      []string{"user@example.com"},
	}
	ind := &indicator.Indicators{
		Authentication: indicator.AuthResult{SPF: "pass", DKIM: "pass", DMARC: "pass"},
		Sender:         indicator.SenderResult{},
		Routing: indicator.RoutingResult{
			SuspiciousHops: []string{"localhost/unknown origin: from localhost"},
		},
	}

	prompt, err := BuildUserPrompt(tag, email, ind)
	if err != nil {
		t.Fatalf("BuildUserPrompt: %v", err)
	}

	if strings.Contains(prompt, "very likely a legitimate email") {
		t.Error("routing anomaly should prevent 'very likely legitimate' hint even with auth all pass")
	}
}

func TestBuildUserPromptHintSoftfailCounted(t *testing.T) {
	_, tag := BuildSystemPrompt("")
	email := &parser.Email{
		Subject: "Test",
		From:    "mail@example.com",
		To:      []string{"user@example.com"},
	}
	ind := &indicator.Indicators{
		Authentication: indicator.AuthResult{SPF: "softfail", DKIM: "pass", DMARC: "fail"},
		Sender:         indicator.SenderResult{},
	}

	prompt, err := BuildUserPrompt(tag, email, ind)
	if err != nil {
		t.Fatalf("BuildUserPrompt: %v", err)
	}

	if strings.Contains(prompt, "likely safe") {
		t.Error("softfail + dmarc fail must NOT produce 'likely safe' hint")
	}
	if !strings.Contains(prompt, "authentication checks FAILED") {
		t.Error("SPF softfail + DMARC fail should count as 2 auth failures")
	}
}

func TestBuildUserPromptAlertCountIncludesXMailer(t *testing.T) {
	_, tag := BuildSystemPrompt("")
	email := &parser.Email{
		Subject: "Test",
		From:    "mail@example.com",
		To:      []string{"user@example.com"},
	}
	ind := &indicator.Indicators{
		Authentication: indicator.AuthResult{SPF: "pass", DKIM: "pass", DMARC: "pass"},
		Sender:         indicator.SenderResult{},
		Routing: indicator.RoutingResult{
			XMailer:           "PHPMailer 6.0",
			XMailerSuspicious: true,
		},
	}

	prompt, err := BuildUserPrompt(tag, email, ind)
	if err != nil {
		t.Fatalf("BuildUserPrompt: %v", err)
	}

	if strings.Contains(prompt, "very likely a legitimate email") {
		t.Error("suspicious X-Mailer should prevent 'very likely legitimate' hint")
	}
}
