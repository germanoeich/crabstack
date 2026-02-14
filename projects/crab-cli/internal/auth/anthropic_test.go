package auth

import (
	"bytes"
	"context"
	"encoding/base64"
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

func TestBuildAnthropicAuthorizeURL(t *testing.T) {
	cfg := DefaultAnthropicConfig()
	got, err := buildAnthropicAuthorizeURL(cfg, "challenge_test", "state_test")
	if err != nil {
		t.Fatalf("buildAnthropicAuthorizeURL failed: %v", err)
	}

	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	query := parsed.Query()
	assertEqual(t, query.Get("response_type"), "code", "response_type")
	assertEqual(t, query.Get("scope"), anthropicDefaultScope, "scope")
	assertEqual(t, query.Get("code_challenge"), "challenge_test", "code_challenge")
	assertEqual(t, query.Get("code_challenge_method"), "S256", "code_challenge_method")
	assertEqual(t, query.Get("state"), "state_test", "state")
	assertEqual(t, query.Get("code"), "true", "code")
}

func TestLoginAnthropicManualFlow(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") != "authorization_code" {
			http.Error(w, "bad grant_type", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(r.Form.Get("code")) != "manual_code_value" {
			http.Error(w, "bad code", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(r.Form.Get("client_id")) == "" {
			http.Error(w, "missing client_id", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(r.Form.Get("code_verifier")) == "" {
			http.Error(w, "missing code_verifier", http.StatusBadRequest)
			return
		}

		token := anthropicJWTWithClaims(map[string]any{
			"sub":   "acct_token",
			"email": "token@example.com",
			"name":  "Token User",
		})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  token,
			"refresh_token": "refresh_test",
			"token_type":    "bearer",
			"scope":         anthropicDefaultScope,
			"expires_in":    3600,
			"account": map[string]any{
				"id":            "acct_response",
				"email_address": "response@example.com",
				"display_name":  "Response User",
				"workspace_id":  "ws_123",
			},
		})
	}))
	defer tokenServer.Close()

	cfg := DefaultAnthropicConfig()
	cfg.TokenURL = tokenServer.URL
	cfg.Timeout = 2 * time.Second
	fixedNow := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	cfg.Now = func() time.Time { return fixedNow }

	input := bytes.NewBufferString("manual_code_value\n")
	var output bytes.Buffer
	creds, err := LoginAnthropic(context.Background(), cfg, input, &output)
	if err != nil {
		t.Fatalf("LoginAnthropic failed: %v", err)
	}

	assertEqual(t, creds.Provider, "anthropic", "provider")
	assertEqual(t, creds.AccountID, "acct_response", "account_id")
	assertEqual(t, creds.AccountEmail, "response@example.com", "account_email")
	assertEqual(t, creds.AccountName, "Response User", "account_name")
	assertEqual(t, creds.ProviderMeta["token_url"], tokenServer.URL, "provider_meta.token_url")
	assertEqual(t, creds.RefreshToken, "refresh_test", "refresh_token")
	assertEqual(t, creds.ExpiresAt.UTC().Format(time.RFC3339), fixedNow.Add(time.Hour).UTC().Format(time.RFC3339), "expires_at")
	assertEqual(t, creds.AccountMeta["workspace_id"], "ws_123", "account_meta.workspace_id")

	if !strings.Contains(output.String(), "Open this URL in your browser") {
		t.Fatalf("expected browser URL prompt in output")
	}
	if !strings.Contains(output.String(), "Paste redirect URL or code") {
		t.Fatalf("expected manual prompt in output")
	}
}

func TestExtractAnthropicAccountMetadataJWTFallback(t *testing.T) {
	token := anthropicJWTWithClaims(map[string]any{
		"sub":             "acct_jwt",
		"email":           "jwt@example.com",
		"name":            "JWT User",
		"organization_id": "org_test",
	})

	account := extractAnthropicAccountMetadata(token, nil)
	assertEqual(t, account.AccountID, "acct_jwt", "account_id")
	assertEqual(t, account.Email, "jwt@example.com", "account_email")
	assertEqual(t, account.Name, "JWT User", "account_name")
	assertEqual(t, account.Meta["organization_id"], "org_test", "account_meta.organization_id")
}

func TestExtractAnthropicAccountMetadataResponsePreferred(t *testing.T) {
	token := anthropicJWTWithClaims(map[string]any{
		"sub":   "acct_jwt",
		"email": "jwt@example.com",
		"name":  "JWT User",
	})
	account := extractAnthropicAccountMetadata(token, map[string]any{
		"account": map[string]any{
			"id":            "acct_response",
			"email_address": "response@example.com",
			"display_name":  "Response User",
		},
	})
	assertEqual(t, account.AccountID, "acct_response", "account_id")
	assertEqual(t, account.Email, "response@example.com", "account_email")
	assertEqual(t, account.Name, "Response User", "account_name")
}

func TestSaveAnthropicCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth", "anthropic.json")
	creds := Credentials{
		ClientID:     "anthropic_client",
		AccountID:    "acct_1",
		AccountEmail: "operator@example.com",
		AccountMeta: map[string]string{
			"workspace_id": "ws_1",
		},
		AccessToken:  "access",
		RefreshToken: "refresh",
		ExpiresAt:    time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC),
		ObtainedAt:   time.Date(2026, 2, 14, 11, 0, 0, 0, time.UTC),
	}

	gotPath, err := SaveAnthropicCredentials(path, creds)
	if err != nil {
		t.Fatalf("SaveAnthropicCredentials failed: %v", err)
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
	assertEqual(t, decoded.Provider, "anthropic", "saved provider")
	assertEqual(t, decoded.AccountMeta["workspace_id"], "ws_1", "saved account_meta.workspace_id")
}

func anthropicJWTWithClaims(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return header + "." + payload + ".sig"
}
