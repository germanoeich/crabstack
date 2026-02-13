package integration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestGatewayCLIPairing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	repoRoot, err := locateRepoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}

	tempDir := t.TempDir()
	adminSocket := filepath.Join(tempDir, "run", "gateway-admin.sock")
	dbPath := filepath.Join(tempDir, "data", "gateway.db")
	keyDir := filepath.Join(tempDir, "keys")
	binDir := filepath.Join(tempDir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}

	buildCtx, cancelBuild := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelBuild()

	gatewayBin := filepath.Join(binDir, "crab-gateway")
	if err := buildBinary(buildCtx, repoRoot, gatewayBin, "./projects/crab-gateway/cmd/crab-gateway"); err != nil {
		t.Fatalf("build crab-gateway binary: %v", err)
	}
	cliBin := filepath.Join(binDir, "crab-cli")
	if err := buildBinary(buildCtx, repoRoot, cliBin, "./projects/crab-cli/cmd/crab-cli"); err != nil {
		t.Fatalf("build crab-cli binary: %v", err)
	}

	httpAddr, err := reserveTCPAddr()
	if err != nil {
		t.Fatalf("reserve http addr: %v", err)
	}

	gatewayCtx, gatewayCancel := context.WithCancel(context.Background())
	defer gatewayCancel()

	gatewayCmd := exec.CommandContext(gatewayCtx, gatewayBin)
	gatewayCmd.Dir = repoRoot
	gatewayCmd.Env = append(os.Environ(),
		"CRAB_GATEWAY_HTTP_ADDR="+httpAddr,
		"CRAB_GATEWAY_DB_DRIVER=sqlite",
		"CRAB_GATEWAY_DB_DSN="+dbPath,
		"CRAB_GATEWAY_KEY_DIR="+keyDir,
		"CRAB_GATEWAY_ID=gateway-integration-test",
		"CRAB_GATEWAY_ADMIN_SOCKET_PATH="+adminSocket,
		"CRAB_GATEWAY_PAIR_TIMEOUT=20s",
		"CRAB_GATEWAY_ALLOW_INSECURE_LOOPBACK_PAIRING=true",
	)

	var gatewayLogs bytes.Buffer
	gatewayCmd.Stdout = &gatewayLogs
	gatewayCmd.Stderr = &gatewayLogs

	if err := gatewayCmd.Start(); err != nil {
		t.Fatalf("start gateway: %v", err)
	}

	gatewayDone := make(chan error, 1)
	go func() {
		gatewayDone <- gatewayCmd.Wait()
	}()
	t.Cleanup(func() {
		gatewayCancel()
		select {
		case <-gatewayDone:
		case <-time.After(5 * time.Second):
			if gatewayCmd.Process != nil {
				_ = gatewayCmd.Process.Kill()
			}
			select {
			case <-gatewayDone:
			case <-time.After(2 * time.Second):
			}
		}
	})

	readyCtx, cancelReady := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelReady()
	if err := waitForGatewayAdmin(readyCtx, adminSocket, gatewayDone); err != nil {
		t.Fatalf("wait for gateway admin: %v\nGateway logs:\n%s", err, gatewayLogs.String())
	}

	gatewayPubB64, err := waitForGatewayPublicKey(readyCtx, keyDir)
	if err != nil {
		t.Fatalf("wait for gateway public key: %v\nGateway logs:\n%s", err, gatewayLogs.String())
	}

	cliCtx, cancelCLI := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancelCLI()
	cliCmd := exec.CommandContext(
		cliCtx,
		cliBin, "pair",
		"-admin-socket", adminSocket,
		"-gateway-public-key", gatewayPubB64,
		"-component-type", "tool_host",
		"-component-id", "integration-cli",
		"-listen-addr", "127.0.0.1:0",
		"-listen-path", "/v1/pair",
		"-timeout", "20s",
	)
	cliCmd.Dir = repoRoot
	cliOut, err := cliCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run crab pair: %v\nCLI output:\n%s\nGateway logs:\n%s", err, string(cliOut), gatewayLogs.String())
	}
	cliText := string(cliOut)
	if !strings.Contains(cliText, "pairing complete") {
		t.Fatalf("cli output missing completion marker\nCLI output:\n%s\nGateway logs:\n%s", cliText, gatewayLogs.String())
	}

	ctx, cancelQuery := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelQuery()
	status, endpoint, fingerprint, err := queryPeerByComponentID(ctx, dbPath, "integration-cli")
	if err != nil {
		t.Fatalf("query paired peer row: %v\nCLI output:\n%s\nGateway logs:\n%s", err, cliText, gatewayLogs.String())
	}
	if status != "active" {
		t.Fatalf("unexpected peer status %q, want active\nCLI output:\n%s\nGateway logs:\n%s", status, cliText, gatewayLogs.String())
	}
	if !strings.HasPrefix(endpoint, "ws://127.0.0.1:") {
		t.Fatalf("unexpected endpoint %q", endpoint)
	}
	if !strings.HasPrefix(strings.ToLower(fingerprint), "sha256:") {
		t.Fatalf("unexpected mTLS fingerprint %q", fingerprint)
	}
}

func locateRepoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	candidates := []string{cwd, filepath.Dir(cwd)}
	for _, candidate := range candidates {
		if fileExists(filepath.Join(candidate, "go.work")) && fileExists(filepath.Join(candidate, "projects", "crab-gateway", "cmd", "crab-gateway", "main.go")) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("could not find repo root from cwd=%s", cwd)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func reserveTCPAddr() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer listener.Close()
	return listener.Addr().String(), nil
}

func buildBinary(ctx context.Context, repoRoot, outputPath, packagePath string) error {
	cmd := exec.CommandContext(ctx, "go", "build", "-o", outputPath, packagePath)
	cmd.Dir = repoRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func waitForGatewayAdmin(ctx context.Context, adminSocket string, gatewayDone <-chan error) error {
	for {
		if err := gatewayAdminHealthcheck(adminSocket); err == nil {
			return nil
		}

		select {
		case err := <-gatewayDone:
			if err == nil {
				return fmt.Errorf("gateway exited before admin socket became ready")
			}
			return fmt.Errorf("gateway exited before admin socket became ready: %w", err)
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for admin socket: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func gatewayAdminHealthcheck(adminSocket string) error {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", adminSocket)
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: 500 * time.Millisecond}
	resp, err := client.Get("http://unix/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("unexpected status %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func waitForGatewayPublicKey(ctx context.Context, keyDir string) (string, error) {
	identityPath := filepath.Join(keyDir, "gateway_identity.json")
	for {
		data, err := os.ReadFile(identityPath)
		if err == nil {
			var record struct {
				PrivateKeyEd25519 string `json:"private_key_ed25519"`
			}
			if err := json.Unmarshal(data, &record); err != nil {
				return "", fmt.Errorf("decode identity file: %w", err)
			}
			privateBytes, err := base64.StdEncoding.DecodeString(record.PrivateKeyEd25519)
			if err != nil {
				return "", fmt.Errorf("decode private key: %w", err)
			}
			if len(privateBytes) != ed25519.PrivateKeySize {
				return "", fmt.Errorf("invalid private key size %d", len(privateBytes))
			}
			pub := ed25519.PrivateKey(privateBytes).Public().(ed25519.PublicKey)
			return base64.StdEncoding.EncodeToString(pub), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}

		select {
		case <-ctx.Done():
			return "", fmt.Errorf("timeout waiting for identity file: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func queryPeerByComponentID(ctx context.Context, dbPath, componentID string) (status, endpoint, fingerprint string, err error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return "", "", "", fmt.Errorf("open sqlite db: %w", err)
	}
	defer db.Close()

	err = db.QueryRowContext(
		ctx,
		`select status, endpoint, mtls_cert_fingerprint from paired_peers where component_id = ? limit 1`,
		componentID,
	).Scan(&status, &endpoint, &fingerprint)
	if err != nil {
		return "", "", "", err
	}
	return status, endpoint, fingerprint, nil
}
