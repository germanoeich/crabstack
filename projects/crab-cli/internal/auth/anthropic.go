package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	anthropicDefaultAuthorizeURL = "https://platform.claude.com/oauth/authorize"
	anthropicDefaultTokenURL     = "https://platform.claude.com/v1/oauth/token"
	anthropicDefaultClientID     = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	anthropicDefaultRedirectURL  = "https://platform.claude.com/oauth/code/callback"
	anthropicDefaultScope        = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers"
	anthropicDefaultTimeout      = 60 * time.Second
)

type AnthropicConfig struct {
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
}

type anthropicAccountMetadata struct {
	AccountID string
	Email     string
	Name      string
	Meta      map[string]string
}

func DefaultAnthropicConfig() AnthropicConfig {
	return AnthropicConfig{
		AuthorizeURL: anthropicDefaultAuthorizeURL,
		TokenURL:     anthropicDefaultTokenURL,
		ClientID:     anthropicDefaultClientID,
		RedirectURL:  anthropicDefaultRedirectURL,
		CallbackAddr: defaultCallbackAddr,
		CallbackPath: defaultCallbackPath,
		Scope:        anthropicDefaultScope,
		Timeout:      anthropicDefaultTimeout,
		Now:          time.Now,
	}
}

func AnthropicDefaultConfig() AnthropicConfig {
	return DefaultAnthropicConfig()
}

func DefaultAnthropicCredentialsPath() string {
	return defaultCredentialsPath("anthropic.json")
}

func AnthropicDefaultCredentialsPath() string {
	return DefaultAnthropicCredentialsPath()
}

func LoginAnthropic(ctx context.Context, cfg AnthropicConfig, input io.Reader, output io.Writer) (Credentials, error) {
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
	authURL, err := buildAnthropicAuthorizeURL(cfg, codeChallenge, state)
	if err != nil {
		return Credentials{}, err
	}

	_, _ = fmt.Fprintf(output, "Open this URL in your browser:\n%s\n", authURL)

	var code string
	if shouldUseLocalAnthropicCallback(cfg.RedirectURL) {
		code, err = waitForCallbackCode(ctx, Config{
			CallbackAddr: cfg.CallbackAddr,
			CallbackPath: cfg.CallbackPath,
			Timeout:      cfg.Timeout,
		}, state, output)
		if err != nil {
			_, _ = fmt.Fprintf(output, "Local callback unavailable: %v\n", err)
		}
	}

	if strings.TrimSpace(code) == "" {
		_, _ = fmt.Fprintln(output, "After login, copy the shown code and paste it below.")
		code, err = promptForManualCode(input, output, state)
		if err != nil {
			return Credentials{}, fmt.Errorf("obtain authorization code: %w", err)
		}
	}

	exchangeCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && cfg.Timeout > 0 {
		var cancel context.CancelFunc
		exchangeCtx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}

	token, rawToken, err := exchangeAnthropicAuthorizationCode(exchangeCtx, cfg, code, codeVerifier)
	if err != nil {
		return Credentials{}, err
	}
	account := extractAnthropicAccountMetadata(token.AccessToken, rawToken)

	now := cfg.Now().UTC()
	creds := Credentials{
		Provider:     "anthropic",
		ClientID:     cfg.ClientID,
		AccountID:    account.AccountID,
		AccountEmail: account.Email,
		AccountName:  account.Name,
		ProviderMeta: map[string]string{
			"authorize_url": cfg.AuthorizeURL,
			"token_url":     cfg.TokenURL,
			"redirect_url":  cfg.RedirectURL,
		},
		AccountMeta:  account.Meta,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		Scope:        token.Scope,
		ObtainedAt:   now,
		ExpiresAt:    now.Add(time.Duration(token.ExpiresIn) * time.Second),
	}
	if strings.TrimSpace(creds.Scope) == "" {
		creds.Scope = cfg.Scope
	}
	return creds, nil
}

func AnthropicLogin(ctx context.Context, cfg AnthropicConfig, input io.Reader, output io.Writer) (Credentials, error) {
	return LoginAnthropic(ctx, cfg, input, output)
}

func SaveAnthropicCredentials(path string, creds Credentials) (string, error) {
	return saveProviderCredentials(path, "anthropic", creds)
}

func (c AnthropicConfig) withDefaults() AnthropicConfig {
	if strings.TrimSpace(c.AuthorizeURL) == "" {
		c.AuthorizeURL = anthropicDefaultAuthorizeURL
	}
	if strings.TrimSpace(c.TokenURL) == "" {
		c.TokenURL = anthropicDefaultTokenURL
	}
	if strings.TrimSpace(c.ClientID) == "" {
		c.ClientID = anthropicDefaultClientID
	}
	if strings.TrimSpace(c.RedirectURL) == "" {
		c.RedirectURL = anthropicDefaultRedirectURL
	}
	if strings.TrimSpace(c.CallbackAddr) == "" {
		c.CallbackAddr = defaultCallbackAddr
	}
	if strings.TrimSpace(c.CallbackPath) == "" {
		c.CallbackPath = defaultCallbackPath
	}
	if strings.TrimSpace(c.Scope) == "" {
		c.Scope = anthropicDefaultScope
	}
	if c.Timeout <= 0 {
		c.Timeout = anthropicDefaultTimeout
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

func (c AnthropicConfig) Validate() error {
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
	if strings.TrimSpace(c.Scope) == "" {
		return fmt.Errorf("scope is required")
	}
	if strings.TrimSpace(c.CallbackPath) == "" {
		return fmt.Errorf("callback path is required")
	}
	if !strings.HasPrefix(c.CallbackPath, "/") {
		return fmt.Errorf("callback path must start with /")
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be > 0")
	}
	return nil
}

func buildAnthropicAuthorizeURL(cfg AnthropicConfig, codeChallenge, state string) (string, error) {
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
	q.Set("code", "true")
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

func shouldUseLocalAnthropicCallback(redirectURL string) bool {
	parsedURL, err := url.Parse(strings.TrimSpace(redirectURL))
	if err != nil {
		return false
	}

	switch strings.ToLower(strings.TrimSpace(parsedURL.Hostname())) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

func exchangeAnthropicAuthorizationCode(ctx context.Context, cfg AnthropicConfig, code, codeVerifier string) (tokenResponse, map[string]any, error) {
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

func extractAnthropicAccountMetadata(accessToken string, rawToken map[string]any) anthropicAccountMetadata {
	meta := map[string]string{}

	account := map[string]any{}
	if rawToken != nil {
		if v, ok := rawToken["account"]; ok {
			if accountValue, ok := v.(map[string]any); ok {
				account = accountValue
			}
		}
	}

	accountID := firstString(account, "id", "account_id", "user_id", "uuid", "sub")
	if accountID == "" {
		accountID = firstString(rawToken, "account_id", "user_id", "sub", "id")
	}
	email := firstString(account, "email", "email_address", "user_email")
	if email == "" {
		email = firstString(rawToken, "email", "email_address", "user_email")
	}
	name := firstString(account, "name", "display_name")
	if name == "" {
		name = firstString(rawToken, "name", "display_name")
	}

	addMetadata(meta, rawToken,
		"account_id",
		"organization_id",
		"org_id",
		"workspace_id",
		"team_id",
	)
	addMetadata(meta, account,
		"id",
		"uuid",
		"account_id",
		"organization_id",
		"org_id",
		"workspace_id",
		"team_id",
		"email",
		"email_address",
		"name",
		"display_name",
	)

	if claims, err := decodeJWTClaims(accessToken); err == nil {
		if accountID == "" {
			accountID = firstString(claims, "sub", "account_id", "user_id", "id")
		}
		if email == "" {
			email = firstString(claims, "email", "email_address")
		}
		if name == "" {
			name = firstString(claims, "name", "preferred_username")
		}
		addMetadata(meta, claims,
			"sub",
			"email",
			"organization_id",
			"org_id",
			"workspace_id",
		)
	}

	if accountID != "" {
		meta["resolved_account_id"] = accountID
	}
	if email != "" {
		meta["resolved_email"] = email
	}
	if name != "" {
		meta["resolved_name"] = name
	}
	if len(meta) == 0 {
		meta = nil
	}
	return anthropicAccountMetadata{
		AccountID: accountID,
		Email:     email,
		Name:      name,
		Meta:      meta,
	}
}

func firstString(values map[string]any, keys ...string) string {
	if len(values) == 0 {
		return ""
	}
	for _, key := range keys {
		value, ok := values[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case string:
			trimmed := strings.TrimSpace(typed)
			if trimmed != "" {
				return trimmed
			}
		case json.Number:
			trimmed := strings.TrimSpace(typed.String())
			if trimmed != "" {
				return trimmed
			}
		case float64:
			trimmed := strings.TrimSpace(strconv.FormatFloat(typed, 'f', -1, 64))
			if trimmed != "" {
				return trimmed
			}
		case int:
			trimmed := strings.TrimSpace(strconv.Itoa(typed))
			if trimmed != "" {
				return trimmed
			}
		case int64:
			trimmed := strings.TrimSpace(strconv.FormatInt(typed, 10))
			if trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

func addMetadata(meta map[string]string, values map[string]any, keys ...string) {
	if len(values) == 0 {
		return
	}
	for _, key := range keys {
		if _, exists := meta[key]; exists {
			continue
		}
		value := firstString(values, key)
		if value == "" {
			continue
		}
		meta[key] = value
	}
}

func decodeJWTClaims(accessToken string) (map[string]any, error) {
	parts := strings.Split(strings.TrimSpace(accessToken), ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid access token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode access token payload: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("decode access token claims: %w", err)
	}
	return claims, nil
}
