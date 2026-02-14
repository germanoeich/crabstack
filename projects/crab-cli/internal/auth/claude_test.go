package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildClaudeAuthorizeURLModes(t *testing.T) {
	tests := []struct {
		name          string
		mode          ClaudeMode
		wantBaseURL   string
		wantScope     string
		wantAuthorize string
	}{
		{
			name:          "max mode",
			mode:          ClaudeModeMax,
			wantBaseURL:   "https://claude.ai/oauth/authorize",
			wantScope:     claudeMaxScope,
			wantAuthorize: claudeMaxAuthorizeURL,
		},
		{
			name:          "console mode",
			mode:          ClaudeModeConsole,
			wantBaseURL:   "https://console.anthropic.com/oauth/authorize",
			wantScope:     claudeConsoleScope,
			wantAuthorize: claudeConsoleAuthorizeURL,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultClaudeConfig()
			cfg.Mode = tc.mode
			cfg.AuthorizeURL = ""
			cfg.Scope = ""
			cfg = cfg.withDefaults()

			got, err := buildClaudeAuthorizeURL(cfg, "challenge_test", "state_test")
			if err != nil {
				t.Fatalf("buildClaudeAuthorizeURL failed: %v", err)
			}

			parsed, err := url.Parse(got)
			if err != nil {
				t.Fatalf("parse authorize url: %v", err)
			}
			assertEqual(t, parsed.Scheme+"://"+parsed.Host+parsed.Path, tc.wantBaseURL, "authorize_url")

			query := parsed.Query()
			assertEqual(t, query.Get("response_type"), "code", "response_type")
			assertEqual(t, query.Get("scope"), tc.wantScope, "scope")
			assertEqual(t, query.Get("code_challenge"), "challenge_test", "code_challenge")
			assertEqual(t, query.Get("code_challenge_method"), "S256", "code_challenge_method")
			assertEqual(t, query.Get("state"), "state_test", "state")
			assertEqual(t, cfg.AuthorizeURL, tc.wantAuthorize, "config authorize_url default")
		})
	}
}

func TestClaudeManualCodeHashFormat(t *testing.T) {
	parsed, err := parseManualCodeInput("manual_code#state_123")
	if err != nil {
		t.Fatalf("parseManualCodeInput failed: %v", err)
	}
	assertEqual(t, parsed.Code, "manual_code", "code")
	assertEqual(t, parsed.State, "state_123", "state")
}

func TestLoginClaudeSetupTokenManual(t *testing.T) {
	cfg := DefaultClaudeConfig()
	fixedNow := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	cfg.Now = func() time.Time { return fixedNow }

	token := claudeSetupTokenForTest()
	input := bytes.NewBufferString(token + "\n")
	var output bytes.Buffer
	creds, err := LoginClaude(context.Background(), cfg, input, &output)
	if err != nil {
		t.Fatalf("LoginClaude failed: %v", err)
	}

	assertEqual(t, creds.Provider, "claude", "provider")
	assertEqual(t, creds.AccountID, "unknown", "account_id")
	assertEqual(t, creds.AccessToken, token, "access_token")
	assertEqual(t, creds.RefreshToken, token, "refresh_token")
	assertEqual(t, creds.ProviderMeta["mode"], string(ClaudeModeMax), "provider_meta.mode")
	assertEqual(t, creds.ProviderMeta["flow"], "setup-token", "provider_meta.flow")
	assertEqual(t, creds.Scope, "setup-token", "scope")
	if !strings.Contains(output.String(), "Paste Anthropic setup-token") {
		t.Fatalf("expected setup-token prompt in output")
	}
}

func TestLoginClaudeRejectsInvalidSetupToken(t *testing.T) {
	cfg := DefaultClaudeConfig()

	input := bytes.NewBufferString("bad-token\n")
	var output bytes.Buffer
	_, err := LoginClaude(context.Background(), cfg, input, &output)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "expected setup-token starting with") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClaudeConfigValidate(t *testing.T) {
	cfg := DefaultClaudeConfig()
	cfg.Mode = ClaudeMode("invalid")
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected invalid mode error")
	}

	cfg = DefaultClaudeConfig()
	cfg.CallbackPath = "callback"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected callback path error")
	}
}

func TestExchangeClaudeAuthorizationCodeRequiresRefreshToken(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access_test",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	cfg := DefaultClaudeConfig()
	cfg.TokenURL = tokenServer.URL

	_, _, err := exchangeClaudeAuthorizationCode(context.Background(), cfg, "code", "verifier")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "refresh_token") {
		t.Fatalf("expected refresh_token error, got %v", err)
	}
}

func TestSaveClaudeCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth", "claude.json")
	creds := Credentials{
		ClientID:     "claude_client",
		AccountID:    "acct_1",
		AccessToken:  "access",
		RefreshToken: "refresh",
		ExpiresAt:    time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC),
		ObtainedAt:   time.Date(2026, 2, 14, 11, 0, 0, 0, time.UTC),
	}

	gotPath, err := SaveClaudeCredentials(path, creds)
	if err != nil {
		t.Fatalf("SaveClaudeCredentials failed: %v", err)
	}
	assertEqual(t, gotPath, path, "saved path")

	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read credentials file: %v", err)
	}
	var decoded Credentials
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decode saved credentials: %v", err)
	}
	assertEqual(t, decoded.Provider, "claude", "saved provider")
	assertEqual(t, decoded.AccountID, "acct_1", "saved account_id")
}

func claudeSetupTokenForTest() string {
	return claudeSetupTokenPrefix + strings.Repeat("x", claudeSetupTokenMinLength-len(claudeSetupTokenPrefix))
}
