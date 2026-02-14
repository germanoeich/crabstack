package auth

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	claudeMaxAuthorizeURL     = "https://claude.ai/oauth/authorize"
	claudeConsoleAuthorizeURL = "https://console.anthropic.com/oauth/authorize"
	claudeDefaultTokenURL     = "https://console.anthropic.com/v1/oauth/token"
	claudeDefaultClientID     = "52e4e498-8c4b-4023-8dbb-9048068b91de"
	claudeDefaultRedirectURL  = "http://localhost:54545/callback"
	claudeDefaultCallbackAddr = "127.0.0.1:54545"
	claudeDefaultCallbackPath = "/callback"
	claudeMaxScope            = "user:inference"
	claudeConsoleScope        = "org:create_api_key"
	claudeDefaultTimeout      = 60 * time.Second
	claudeSetupTokenPrefix    = "sk-ant-oat01-"
	claudeSetupTokenMinLength = 80
)

type ClaudeMode string

const (
	ClaudeModeMax     ClaudeMode = "max"
	ClaudeModeConsole ClaudeMode = "console"
)

type ClaudeConfig struct {
	Mode         ClaudeMode
	AuthorizeURL string
	TokenURL     string
	ClientID     string
	RedirectURL  string
	CallbackAddr string
	CallbackPath string
	Scope        string
	Timeout      time.Duration
	HTTPClient   *http.Client
	Now          func() time.Time
	SetupToken   string
}

func DefaultClaudeConfig() ClaudeConfig {
	return ClaudeConfig{
		Mode:         ClaudeModeMax,
		AuthorizeURL: claudeMaxAuthorizeURL,
		TokenURL:     claudeDefaultTokenURL,
		ClientID:     claudeDefaultClientID,
		RedirectURL:  claudeDefaultRedirectURL,
		CallbackAddr: claudeDefaultCallbackAddr,
		CallbackPath: claudeDefaultCallbackPath,
		Scope:        claudeMaxScope,
		Timeout:      claudeDefaultTimeout,
		Now:          time.Now,
	}
}

func ClaudeDefaultConfig() ClaudeConfig {
	return DefaultClaudeConfig()
}

func DefaultClaudeCredentialsPath() string {
	return defaultCredentialsPath("claude.json")
}

func ClaudeDefaultCredentialsPath() string {
	return DefaultClaudeCredentialsPath()
}

func LoginClaude(ctx context.Context, cfg ClaudeConfig, input io.Reader, output io.Writer) (Credentials, error) {
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return Credentials{}, err
	}

	setupToken := strings.TrimSpace(cfg.SetupToken)
	tokenSource := "manual"
	if setupToken != "" {
		tokenSource = "configured"
	}

	if setupToken == "" {
		token, err := promptForClaudeSetupToken(input, output)
		if err != nil {
			return Credentials{}, fmt.Errorf("obtain claude setup-token: %w", err)
		}
		setupToken = token
	}
	if err := validateClaudeSetupToken(setupToken); err != nil {
		return Credentials{}, err
	}

	now := cfg.Now().UTC()
	creds := Credentials{
		Provider:  "claude",
		ClientID:  cfg.ClientID,
		AccountID: "unknown",
		ProviderMeta: map[string]string{
			"mode":         string(cfg.Mode),
			"flow":         "setup-token",
			"token_source": tokenSource,
		},
		AccountMeta: map[string]string{
			"token_prefix": claudeSetupTokenPrefix,
		},
		AccessToken:  setupToken,
		RefreshToken: setupToken,
		TokenType:    "bearer",
		Scope:        "setup-token",
		ObtainedAt:   now,
		ExpiresAt:    now.Add(365 * 24 * time.Hour),
	}
	return creds, nil
}

func ClaudeLogin(ctx context.Context, cfg ClaudeConfig, input io.Reader, output io.Writer) (Credentials, error) {
	return LoginClaude(ctx, cfg, input, output)
}

func SaveClaudeCredentials(path string, creds Credentials) (string, error) {
	return saveProviderCredentials(path, "claude", creds)
}

func (c ClaudeConfig) withDefaults() ClaudeConfig {
	c.Mode = normalizeClaudeMode(c.Mode)
	if strings.TrimSpace(string(c.Mode)) == "" {
		c.Mode = ClaudeModeMax
	}
	if strings.TrimSpace(c.AuthorizeURL) == "" {
		c.AuthorizeURL = defaultClaudeAuthorizeURL(c.Mode)
	}
	if strings.TrimSpace(c.TokenURL) == "" {
		c.TokenURL = claudeDefaultTokenURL
	}
	if strings.TrimSpace(c.ClientID) == "" {
		c.ClientID = claudeDefaultClientID
	}
	if strings.TrimSpace(c.RedirectURL) == "" {
		c.RedirectURL = claudeDefaultRedirectURL
	}
	if strings.TrimSpace(c.CallbackAddr) == "" {
		c.CallbackAddr = claudeDefaultCallbackAddr
	}
	if strings.TrimSpace(c.CallbackPath) == "" {
		c.CallbackPath = claudeDefaultCallbackPath
	}
	if strings.TrimSpace(c.Scope) == "" {
		c.Scope = defaultClaudeScope(c.Mode)
	}
	if c.Timeout <= 0 {
		c.Timeout = claudeDefaultTimeout
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

func (c ClaudeConfig) Validate() error {
	switch normalizeClaudeMode(c.Mode) {
	case ClaudeModeMax, ClaudeModeConsole:
	default:
		return fmt.Errorf("mode must be one of: max, console")
	}
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
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be > 0")
	}
	return nil
}

func buildClaudeAuthorizeURL(cfg ClaudeConfig, codeChallenge, state string) (string, error) {
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
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

func exchangeClaudeAuthorizationCode(ctx context.Context, cfg ClaudeConfig, code, codeVerifier string) (tokenResponse, map[string]any, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", cfg.ClientID)
	form.Set("code", strings.TrimSpace(code))
	form.Set("code_verifier", codeVerifier)
	form.Set("redirect_uri", cfg.RedirectURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return tokenResponse{}, nil, fmt.Errorf("exchange authorization code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return tokenResponse{}, nil, fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return tokenResponse{}, nil, fmt.Errorf("token exchange failed: %s", msg)
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return tokenResponse{}, nil, fmt.Errorf("decode token response: %w", err)
	}

	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return tokenResponse{}, nil, fmt.Errorf("decode token response: %w", err)
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		return tokenResponse{}, nil, fmt.Errorf("token response missing access_token")
	}
	if strings.TrimSpace(token.RefreshToken) == "" {
		return tokenResponse{}, nil, fmt.Errorf("token response missing refresh_token")
	}
	if token.ExpiresIn <= 0 {
		return tokenResponse{}, nil, fmt.Errorf("token response missing expires_in")
	}
	return token, raw, nil
}

func normalizeClaudeMode(mode ClaudeMode) ClaudeMode {
	switch strings.ToLower(strings.TrimSpace(string(mode))) {
	case "":
		return ""
	case string(ClaudeModeMax):
		return ClaudeModeMax
	case string(ClaudeModeConsole):
		return ClaudeModeConsole
	default:
		return ClaudeMode(strings.ToLower(strings.TrimSpace(string(mode))))
	}
}

func defaultClaudeAuthorizeURL(mode ClaudeMode) string {
	switch normalizeClaudeMode(mode) {
	case ClaudeModeConsole:
		return claudeConsoleAuthorizeURL
	default:
		return claudeMaxAuthorizeURL
	}
}

func defaultClaudeScope(mode ClaudeMode) string {
	switch normalizeClaudeMode(mode) {
	case ClaudeModeConsole:
		return claudeConsoleScope
	default:
		return claudeMaxScope
	}
}

func validateClaudeSetupToken(raw string) error {
	token := strings.TrimSpace(raw)
	if token == "" {
		return fmt.Errorf("setup-token is required")
	}
	if !strings.HasPrefix(token, claudeSetupTokenPrefix) {
		return fmt.Errorf("expected setup-token starting with %s", claudeSetupTokenPrefix)
	}
	if len(token) < claudeSetupTokenMinLength {
		return fmt.Errorf("setup-token looks too short; paste the full token")
	}
	return nil
}

func promptForClaudeSetupToken(input io.Reader, output io.Writer) (string, error) {
	if input == nil {
		return "", fmt.Errorf("manual input reader is required")
	}
	reader := bufio.NewReader(input)
	_, _ = fmt.Fprint(output, "Paste Anthropic setup-token: ")
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read setup-token: %w", err)
	}
	token := strings.TrimSpace(line)
	if token == "" {
		return "", fmt.Errorf("setup-token is required")
	}
	return token, nil
}
