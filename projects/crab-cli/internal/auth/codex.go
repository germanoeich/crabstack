package auth

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultAuthorizeURL = "https://auth.openai.com/oauth/authorize"
	defaultTokenURL     = "https://auth.openai.com/oauth/token"
	defaultClientID     = "app_EMoamEEZ73f0CkXaXp7hrann"
	defaultRedirectURL  = "http://localhost:1455/auth/callback"
	defaultCallbackAddr = "127.0.0.1:1455"
	defaultCallbackPath = "/auth/callback"
	defaultScope        = "openid profile email offline_access"
	defaultOriginator   = "pi"
	defaultTimeout      = 60 * time.Second
)

type Config struct {
	AuthorizeURL string
	TokenURL     string
	ClientID     string
	RedirectURL  string
	CallbackAddr string
	CallbackPath string
	Scope        string
	Originator   string
	Timeout      time.Duration
	HTTPClient   *http.Client
	Now          func() time.Time
}

type Credentials struct {
	Provider     string            `json:"provider"`
	ClientID     string            `json:"client_id"`
	AccountID    string            `json:"account_id"`
	AccountEmail string            `json:"account_email,omitempty"`
	AccountName  string            `json:"account_name,omitempty"`
	ProviderMeta map[string]string `json:"provider_meta,omitempty"`
	AccountMeta  map[string]string `json:"account_meta,omitempty"`
	AccessToken  string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token"`
	TokenType    string            `json:"token_type,omitempty"`
	Scope        string            `json:"scope,omitempty"`
	ExpiresAt    time.Time         `json:"expires_at"`
	ObtainedAt   time.Time         `json:"obtained_at"`
}

type tokenResponse struct {
	AccessToken  string         `json:"access_token"`
	RefreshToken string         `json:"refresh_token"`
	TokenType    string         `json:"token_type"`
	Scope        string         `json:"scope"`
	ExpiresIn    int64          `json:"expires_in"`
	Account      map[string]any `json:"account,omitempty"`
}

type manualCode struct {
	Code  string
	State string
}

func DefaultConfig() Config {
	return Config{
		AuthorizeURL: defaultAuthorizeURL,
		TokenURL:     defaultTokenURL,
		ClientID:     defaultClientID,
		RedirectURL:  defaultRedirectURL,
		CallbackAddr: defaultCallbackAddr,
		CallbackPath: defaultCallbackPath,
		Scope:        defaultScope,
		Originator:   defaultOriginator,
		Timeout:      defaultTimeout,
		Now:          time.Now,
	}
}

func DefaultCredentialsPath() string {
	return defaultCredentialsPath("codex.json")
}

func Login(ctx context.Context, cfg Config, input io.Reader, output io.Writer) (Credentials, error) {
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return Credentials{}, err
	}

	codeVerifier, codeChallenge, err := generatePKCE()
	if err != nil {
		return Credentials{}, fmt.Errorf("generate pkce: %w", err)
	}
	state, err := randomBase64URL(32)
	if err != nil {
		return Credentials{}, fmt.Errorf("generate oauth state: %w", err)
	}
	authURL, err := buildAuthorizeURL(cfg, codeChallenge, state)
	if err != nil {
		return Credentials{}, err
	}

	_, _ = fmt.Fprintf(output, "Open this URL in your browser:\n%s\n", authURL)

	code, err := waitForCallbackCode(ctx, cfg, state, output)
	if err != nil {
		_, _ = fmt.Fprintf(output, "Local callback unavailable: %v\n", err)
		code, err = promptForManualCode(input, output, state)
		if err != nil {
			return Credentials{}, fmt.Errorf("obtain authorization code: %w", err)
		}
	}

	token, err := exchangeAuthorizationCode(ctx, cfg, code, codeVerifier)
	if err != nil {
		return Credentials{}, err
	}

	accountID, err := extractChatGPTAccountID(token.AccessToken)
	if err != nil {
		return Credentials{}, err
	}

	now := cfg.Now().UTC()
	creds := Credentials{
		Provider:  "codex",
		ClientID:  cfg.ClientID,
		AccountID: accountID,
		ProviderMeta: map[string]string{
			"authorize_url": cfg.AuthorizeURL,
			"token_url":     cfg.TokenURL,
			"redirect_url":  cfg.RedirectURL,
		},
		AccountMeta: map[string]string{
			"chatgpt_account_id": accountID,
		},
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		Scope:        token.Scope,
		ObtainedAt:   now,
		ExpiresAt:    now.Add(time.Duration(token.ExpiresIn) * time.Second),
	}
	return creds, nil
}

func SaveCredentials(path string, creds Credentials) (string, error) {
	return saveProviderCredentials(path, "codex", creds)
}

func saveProviderCredentials(path, defaultProvider string, creds Credentials) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("auth file path is required")
	}
	if strings.TrimSpace(creds.Provider) == "" {
		creds.Provider = defaultProvider
	}
	return saveCredentials(path, creds)
}

func saveCredentials(path string, creds Credentials) (string, error) {
	resolvedPath, err := expandPath(path)
	if err != nil {
		return "", err
	}
	encoded, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal credentials: %w", err)
	}

	dir := filepath.Dir(resolvedPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create credentials dir: %w", err)
	}

	tmpPath := resolvedPath + ".tmp"
	if err := os.WriteFile(tmpPath, encoded, 0o600); err != nil {
		return "", fmt.Errorf("write temporary credentials: %w", err)
	}
	if err := os.Rename(tmpPath, resolvedPath); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("persist credentials: %w", err)
	}
	return resolvedPath, nil
}

func defaultCredentialsPath(filename string) string {
	home, err := os.UserHomeDir()
	if err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".crabstack", "auth", filename)
	}
	return filepath.Join(".crabstack", "auth", filename)
}

func (c Config) withDefaults() Config {
	if strings.TrimSpace(c.AuthorizeURL) == "" {
		c.AuthorizeURL = defaultAuthorizeURL
	}
	if strings.TrimSpace(c.TokenURL) == "" {
		c.TokenURL = defaultTokenURL
	}
	if strings.TrimSpace(c.ClientID) == "" {
		c.ClientID = defaultClientID
	}
	if strings.TrimSpace(c.RedirectURL) == "" {
		c.RedirectURL = defaultRedirectURL
	}
	if strings.TrimSpace(c.CallbackAddr) == "" {
		c.CallbackAddr = defaultCallbackAddr
	}
	if strings.TrimSpace(c.CallbackPath) == "" {
		c.CallbackPath = defaultCallbackPath
	}
	if strings.TrimSpace(c.Scope) == "" {
		c.Scope = defaultScope
	}
	if strings.TrimSpace(c.Originator) == "" {
		c.Originator = defaultOriginator
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultTimeout
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.AuthorizeURL) == "" {
		return fmt.Errorf("authorize url is required")
	}
	if strings.TrimSpace(c.TokenURL) == "" {
		return fmt.Errorf("token url is required")
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return fmt.Errorf("client id is required")
	}
	if strings.TrimSpace(c.RedirectURL) == "" {
		return fmt.Errorf("redirect url is required")
	}
	if strings.TrimSpace(c.CallbackAddr) == "" {
		return fmt.Errorf("callback addr is required")
	}
	if strings.TrimSpace(c.CallbackPath) == "" {
		return fmt.Errorf("callback path is required")
	}
	if !strings.HasPrefix(c.CallbackPath, "/") {
		return fmt.Errorf("callback path must start with /")
	}
	if strings.TrimSpace(c.Scope) == "" {
		return fmt.Errorf("scope is required")
	}
	if strings.TrimSpace(c.Originator) == "" {
		return fmt.Errorf("originator is required")
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be > 0")
	}
	return nil
}

func buildAuthorizeURL(cfg Config, codeChallenge, state string) (string, error) {
	parsed, err := url.Parse(cfg.AuthorizeURL)
	if err != nil {
		return "", fmt.Errorf("parse authorize url: %w", err)
	}
	q := parsed.Query()
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", cfg.RedirectURL)
	q.Set("scope", cfg.Scope)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	q.Set("codex_cli_simplified_flow", "true")
	q.Set("id_token_add_organizations", "true")
	q.Set("originator", cfg.Originator)
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

func waitForCallbackCode(ctx context.Context, cfg Config, expectedState string, output io.Writer) (string, error) {
	listener, err := net.Listen("tcp", cfg.CallbackAddr)
	if err != nil {
		return "", fmt.Errorf("listen callback: %w", err)
	}
	defer listener.Close()

	type result struct {
		code string
		err  error
	}
	resultCh := make(chan result, 1)
	var once sync.Once
	sendResult := func(r result) {
		once.Do(func() {
			resultCh <- r
		})
	}

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.CallbackPath, func(w http.ResponseWriter, r *http.Request) {
		code := strings.TrimSpace(r.URL.Query().Get("code"))
		state := strings.TrimSpace(r.URL.Query().Get("state"))
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			sendResult(result{err: fmt.Errorf("callback missing code")})
			return
		}
		if state == "" || state != expectedState {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			sendResult(result{err: fmt.Errorf("callback state mismatch")})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<html><body><h1>Login complete</h1><p>You can close this window.</p></body></html>")
		sendResult(result{code: code})
	})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			sendResult(result{err: fmt.Errorf("callback server error: %w", err)})
		}
	}()

	_, _ = fmt.Fprintf(output, "Waiting for callback on http://%s%s ...\n", cfg.CallbackAddr, cfg.CallbackPath)

	timer := time.NewTimer(cfg.Timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-timer.C:
		return "", fmt.Errorf("timed out waiting for oauth callback")
	case r := <-resultCh:
		return r.code, r.err
	}
}

func promptForManualCode(input io.Reader, output io.Writer, expectedState string) (string, error) {
	if input == nil {
		return "", fmt.Errorf("manual input reader is required")
	}
	reader := bufio.NewReader(input)
	_, _ = fmt.Fprint(output, "Paste redirect URL or code: ")
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read manual input: %w", err)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", fmt.Errorf("manual input is empty")
	}

	parsed, err := parseManualCodeInput(line)
	if err != nil {
		return "", err
	}
	if parsed.State != "" && parsed.State != expectedState {
		return "", fmt.Errorf("manual state mismatch")
	}
	return parsed.Code, nil
}

func parseManualCodeInput(raw string) (manualCode, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return manualCode{}, fmt.Errorf("manual input is empty")
	}

	if strings.Contains(raw, "://") {
		parsedURL, err := url.Parse(raw)
		if err == nil {
			code := strings.TrimSpace(parsedURL.Query().Get("code"))
			state := strings.TrimSpace(parsedURL.Query().Get("state"))
			if code == "" && strings.TrimSpace(parsedURL.Fragment) != "" {
				fragment, _ := url.ParseQuery(parsedURL.Fragment)
				code = strings.TrimSpace(fragment.Get("code"))
				if state == "" {
					state = strings.TrimSpace(fragment.Get("state"))
				}
			}
			if code != "" {
				return manualCode{Code: code, State: state}, nil
			}
		}
	}

	if strings.Contains(raw, "code=") {
		values, err := url.ParseQuery(strings.TrimPrefix(raw, "?"))
		if err == nil {
			code := strings.TrimSpace(values.Get("code"))
			if code != "" {
				return manualCode{
					Code:  code,
					State: strings.TrimSpace(values.Get("state")),
				}, nil
			}
		}
	}

	if idx := strings.Index(raw, "#"); idx > 0 {
		code := strings.TrimSpace(raw[:idx])
		state := strings.TrimSpace(raw[idx+1:])
		if code != "" {
			return manualCode{Code: code, State: state}, nil
		}
	}

	return manualCode{Code: raw}, nil
}

func exchangeAuthorizationCode(ctx context.Context, cfg Config, code, codeVerifier string) (tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", cfg.ClientID)
	form.Set("code", strings.TrimSpace(code))
	form.Set("code_verifier", codeVerifier)
	form.Set("redirect_uri", cfg.RedirectURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("exchange authorization code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return tokenResponse{}, fmt.Errorf("token exchange failed: %s", msg)
	}

	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return tokenResponse{}, fmt.Errorf("decode token response: %w", err)
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		return tokenResponse{}, fmt.Errorf("token response missing access_token")
	}
	if strings.TrimSpace(token.RefreshToken) == "" {
		return tokenResponse{}, fmt.Errorf("token response missing refresh_token")
	}
	if token.ExpiresIn <= 0 {
		return tokenResponse{}, fmt.Errorf("token response missing expires_in")
	}
	return token, nil
}

func extractChatGPTAccountID(accessToken string) (string, error) {
	parts := strings.Split(accessToken, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid access token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode access token payload: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("decode access token claims: %w", err)
	}
	accountID, _ := claims["https://api.openai.com/auth.chatgpt_account_id"].(string)
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return "", fmt.Errorf("access token missing chatgpt account id claim")
	}
	return accountID, nil
}

func generatePKCE() (string, string, error) {
	verifier, err := randomBase64URL(64)
	if err != nil {
		return "", "", err
	}
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	return verifier, challenge, nil
}

func randomBase64URL(size int) (string, error) {
	if size <= 0 {
		return "", fmt.Errorf("size must be > 0")
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func expandPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home dir: %w", err)
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~/")), nil
	}
	return path, nil
}
