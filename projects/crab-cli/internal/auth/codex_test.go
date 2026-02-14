package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildAuthorizeURL(t *testing.T) {
	cfg := DefaultConfig()
	got, err := buildAuthorizeURL(cfg, "challenge_test", "state_test")
	if err != nil {
		t.Fatalf("buildAuthorizeURL failed: %v", err)
	}

	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	query := parsed.Query()
	assertEqual(t, query.Get("response_type"), "code", "response_type")
	assertEqual(t, query.Get("scope"), defaultScope, "scope")
	assertEqual(t, query.Get("code_challenge"), "challenge_test", "code_challenge")
	assertEqual(t, query.Get("code_challenge_method"), "S256", "code_challenge_method")
	assertEqual(t, query.Get("state"), "state_test", "state")
	assertEqual(t, query.Get("codex_cli_simplified_flow"), "true", "codex_cli_simplified_flow")
	assertEqual(t, query.Get("id_token_add_organizations"), "true", "id_token_add_organizations")
	assertEqual(t, query.Get("originator"), cfg.Originator, "originator")
}

func TestParseManualCodeInput(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantCode  string
		wantState string
	}{
		{
			name:      "full redirect url",
			input:     "http://localhost:1455/auth/callback?code=abc123&state=state1",
			wantCode:  "abc123",
			wantState: "state1",
		},
		{
			name:      "query format",
			input:     "code=abc123&state=state2",
			wantCode:  "abc123",
			wantState: "state2",
		},
		{
			name:      "hash format",
			input:     "abc123#state3",
			wantCode:  "abc123",
			wantState: "state3",
		},
		{
			name:      "code only",
			input:     "abc123",
			wantCode:  "abc123",
			wantState: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseManualCodeInput(tc.input)
			if err != nil {
				t.Fatalf("parseManualCodeInput failed: %v", err)
			}
			assertEqual(t, got.Code, tc.wantCode, "code")
			assertEqual(t, got.State, tc.wantState, "state")
		})
	}
}

func TestWaitForCallbackCode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Timeout = 2 * time.Second
	cfg.CallbackAddr = reserveTCPAddr(t)
	expectedState := "state123"
	expectedCode := "code123"

	type result struct {
		code string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		code, err := waitForCallbackCode(context.Background(), cfg, expectedState, io.Discard)
		done <- result{code: code, err: err}
	}()

	callbackURL := fmt.Sprintf("http://%s%s?code=%s&state=%s", cfg.CallbackAddr, cfg.CallbackPath, expectedCode, expectedState)
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := http.Get(callbackURL)
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("callback never became available: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("waitForCallbackCode failed: %v", got.err)
		}
		assertEqual(t, got.code, expectedCode, "callback code")
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for callback result")
	}
}

func TestLoginManualFallback(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") != "authorization_code" {
			http.Error(w, "bad grant_type", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(r.Form.Get("code")) == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}

		token := jwtWithAccountID("acct_codex_test")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  token,
			"refresh_token": "refresh_test",
			"token_type":    "bearer",
			"scope":         defaultScope,
			"expires_in":    3600,
		})
	}))
	defer tokenServer.Close()

	blockedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen blocked callback addr: %v", err)
	}
	defer blockedListener.Close()

	cfg := DefaultConfig()
	cfg.TokenURL = tokenServer.URL
	cfg.CallbackAddr = blockedListener.Addr().String()
	cfg.Timeout = 1 * time.Second
	fixedNow := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	cfg.Now = func() time.Time { return fixedNow }

	input := bytes.NewBufferString("manual_code_value\n")
	var output bytes.Buffer
	creds, err := Login(context.Background(), cfg, input, &output)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	assertEqual(t, creds.Provider, "codex", "provider")
	assertEqual(t, creds.AccountID, "acct_codex_test", "account_id")
	assertEqual(t, creds.RefreshToken, "refresh_test", "refresh_token")
	assertEqual(t, creds.ProviderMeta["token_url"], tokenServer.URL, "provider_meta.token_url")
	assertEqual(t, creds.AccountMeta["chatgpt_account_id"], "acct_codex_test", "account_meta.chatgpt_account_id")
	assertEqual(t, creds.ExpiresAt.UTC().Format(time.RFC3339), fixedNow.Add(time.Hour).UTC().Format(time.RFC3339), "expires_at")
	if !strings.Contains(output.String(), "Open this URL in your browser") {
		t.Fatalf("expected browser URL prompt in output")
	}
	if !strings.Contains(output.String(), "Paste redirect URL or code") {
		t.Fatalf("expected manual fallback prompt in output")
	}
}

func TestSaveCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth", "codex.json")
	creds := Credentials{
		Provider:     "codex",
		ClientID:     "client",
		AccountID:    "acct",
		ProviderMeta: map[string]string{"authorize_url": "https://auth.example"},
		AccountMeta:  map[string]string{"chatgpt_account_id": "acct"},
		AccessToken:  "access",
		RefreshToken: "refresh",
		ExpiresAt:    time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC),
		ObtainedAt:   time.Date(2026, 2, 14, 11, 0, 0, 0, time.UTC),
	}

	gotPath, err := SaveCredentials(path, creds)
	if err != nil {
		t.Fatalf("SaveCredentials failed: %v", err)
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
	assertEqual(t, decoded.AccountID, "acct", "saved account_id")
	assertEqual(t, decoded.Provider, "codex", "saved provider")
	assertEqual(t, decoded.ProviderMeta["authorize_url"], "https://auth.example", "saved provider_meta.authorize_url")
	assertEqual(t, decoded.AccountMeta["chatgpt_account_id"], "acct", "saved account_meta.chatgpt_account_id")
}

func TestExtractChatGPTAccountID(t *testing.T) {
	tests := []struct {
		name    string
		token   tokenResponse
		want    string
		wantErr bool
	}{
		{
			name: "nested auth claim",
			token: tokenResponse{
				AccessToken: jwtWithPayload(`{"https://api.openai.com/auth":{"chatgpt_account_id":"acct_nested"}}`),
			},
			want: "acct_nested",
		},
		{
			name: "legacy access token claim",
			token: tokenResponse{
				AccessToken: jwtWithAccountIDClaim("https://api.openai.com/auth.chatgpt_account_id", "acct_legacy"),
			},
			want: "acct_legacy",
		},
		{
			name: "slash access token claim",
			token: tokenResponse{
				AccessToken: jwtWithAccountID("acct_slash"),
			},
			want: "acct_slash",
		},
		{
			name: "organizations fallback",
			token: tokenResponse{
				AccessToken: jwtWithPayload(`{"organizations":[{"id":"acct_org"}]}`),
			},
			want: "acct_org",
		},
		{
			name: "id token fallback",
			token: tokenResponse{
				AccessToken: jwtWithoutAccountID(),
				IDToken:     jwtWithAccountID("acct_id_token"),
			},
			want: "acct_id_token",
		},
		{
			name: "account object fallback",
			token: tokenResponse{
				AccessToken: jwtWithoutAccountID(),
				Account: map[string]any{
					"id": "acct_account",
				},
			},
			want: "acct_account",
		},
		{
			name: "missing claim",
			token: tokenResponse{
				AccessToken: jwtWithoutAccountID(),
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			accountID, err := extractChatGPTAccountID(tc.token)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected missing-claim error")
				}
				return
			}
			if err != nil {
				t.Fatalf("extractChatGPTAccountID failed: %v", err)
			}
			assertEqual(t, accountID, tc.want, "account_id")
		})
	}
}

func TestDefaultCredentialsPath_PrefersHomeWithoutLocalCrabstack(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	setAuthWorkingDir(t, t.TempDir())

	got := defaultCredentialsPath("codex.json")
	want := filepath.Join(homeDir, ".crabstack", "auth", "codex.json")
	if got != want {
		t.Fatalf("unexpected default credentials path: got=%q want=%q", got, want)
	}
}

func TestDefaultCredentialsPath_UsesLocalWhenCrabstackDirExists(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	workDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workDir, ".crabstack"), 0o700); err != nil {
		t.Fatalf("mkdir local .crabstack: %v", err)
	}
	setAuthWorkingDir(t, workDir)

	got := defaultCredentialsPath("codex.json")
	want := filepath.Join(".crabstack", "auth", "codex.json")
	if got != want {
		t.Fatalf("unexpected default credentials path: got=%q want=%q", got, want)
	}
}

func jwtWithAccountID(accountID string) string {
	return jwtWithAccountIDClaim("https://api.openai.com/auth/chatgpt_account_id", accountID)
}

func jwtWithAccountIDClaim(claimKey, accountID string) string {
	return jwtWithPayload(fmt.Sprintf(`{"%s":"%s"}`, claimKey, accountID))
}

func jwtWithPayload(payloadJSON string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	return header + "." + payload + ".sig"
}

func jwtWithoutAccountID() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user"}`))
	return header + "." + payload + ".sig"
}

func reserveTCPAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp addr: %v", err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	return addr
}

func setAuthWorkingDir(t *testing.T, dir string) {
	t.Helper()
	original, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
}

func assertEqual(t *testing.T, got, want, field string) {
	t.Helper()
	if got != want {
		t.Fatalf("unexpected %s: got=%q want=%q", field, got, want)
	}
}
