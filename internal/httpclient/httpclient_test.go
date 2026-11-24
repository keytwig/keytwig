package httpclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keytwig/keytwig/internal/config"
	"github.com/keytwig/keytwig/internal/vault"
)

func testVault(t *testing.T) *vault.Vault {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KEYTWIG_RUNTIME_DIR", filepath.Join(dir, "run"))
	p := vault.Paths{
		Identity: filepath.Join(dir, "id.txt"),
		Vault:    filepath.Join(dir, "v.age"),
		Config:   filepath.Join(dir, "config.toml"),
	}
	if _, err := vault.Init(p, vault.ModeFile, nil); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	v.Set("API_KEY", "sk_http_secret_12345", "test")
	v.Set("DENIED_KEY", "sk_denied_secret_67890", "test")
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDoAllowedHostAndRedactsResponse(t *testing.T) {
	v := testVault(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		w.Header().Set("X-Echo", auth)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"got_auth": auth,
			"query":    r.URL.Query().Get("token"),
		})
	}))
	defer srv.Close()

	cfg := config.Config{
		Secrets: map[string]config.SecretPolicy{
			"API_KEY": {AllowedHosts: []string{"127.0.0.1"}},
		},
	}
	resp, err := Do(context.Background(), v, cfg, Request{
		Method:    "POST",
		URL:       srv.URL + "/charge?token={{API_KEY}}",
		Headers:   map[string]string{"Authorization": "Bearer {{API_KEY}}"},
		Body:      `{"key":"{{API_KEY}}"}`,
		Transport: srv.Client().Transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if len(resp.Injected) != 1 || resp.Injected[0] != "API_KEY" {
		t.Fatalf("injected = %v", resp.Injected)
	}
	if resp.Redactions < 2 {
		t.Fatalf("expected >=2 redactions (header+body), got %d", resp.Redactions)
	}
	if strings.Contains(resp.Body, "sk_http_secret_12345") || strings.Contains(resp.Headers["X-Echo"], "sk_http_secret_12345") {
		t.Fatalf("secret leaked in response: headers=%v body=%s", resp.Headers, resp.Body)
	}
	if !strings.Contains(resp.Body, "‹keytwig:API_KEY›") {
		t.Fatalf("expected redaction placeholder in body: %s", resp.Body)
	}
}

func TestDoRejectsDisallowedHostAndAgentDeny(t *testing.T) {
	v := testVault(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// Empty allowed_hosts -> refused
	_, err := Do(context.Background(), v, config.Config{}, Request{
		Method:  "GET",
		URL:     srv.URL + "/test",
		Headers: map[string]string{"Authorization": "Bearer {{API_KEY}}"},
	})
	if err == nil || !strings.Contains(err.Error(), "allowed_hosts") {
		t.Fatalf("expected allowed_hosts error, got %v", err)
	}

	// Agent deny -> refused even if host is allowed
	cfg := config.Config{
		Agents: map[string]config.AgentPolicy{
			"bot": {Deny: []string{"DENIED_*"}},
		},
		Secrets: map[string]config.SecretPolicy{
			"DENIED_KEY": {AllowedHosts: []string{"127.0.0.1"}},
		},
	}
	_, err = Do(context.Background(), v, cfg, Request{
		Method:  "GET",
		URL:     srv.URL + "/test",
		Headers: map[string]string{"X-Key": "{{DENIED_KEY}}"},
		Agent:   "bot",
	})
	if err == nil || !strings.Contains(err.Error(), "not allowed for agent") {
		t.Fatalf("expected agent deny error, got %v", err)
	}
}

func TestDoBlocksCrossHostRedirectWithSecrets(t *testing.T) {
	v := testVault(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer target.Close()

	// Redirect from 127.0.0.1 to localhost (different hostname)
	localURL := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, localURL, http.StatusFound)
	}))
	defer redirector.Close()

	cfg := config.Config{
		Secrets: map[string]config.SecretPolicy{
			"API_KEY": {AllowedHosts: []string{"127.0.0.1", "localhost"}},
		},
	}
	_, err := Do(context.Background(), v, cfg, Request{
		Method:  "GET",
		URL:     redirector.URL,
		Headers: map[string]string{"Authorization": "Bearer {{API_KEY}}"},
	})
	if err == nil || !strings.Contains(err.Error(), "cross-host redirect") {
		t.Fatalf("expected cross-host redirect error, got %v", err)
	}
}

func TestDoRejectsPlainHTTPNonLocalhost(t *testing.T) {
	v := testVault(t)
	_, err := Do(context.Background(), v, config.Config{}, Request{
		Method: "GET",
		URL:    "http://api.example.com/v1/test",
	})
	if err == nil || !strings.Contains(err.Error(), "plain http is only allowed") {
		t.Fatalf("expected http rejection, got %v", err)
	}
}

type failingRoundTripper struct{}

func (failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial failed")
}

func TestDoRedactsSecretsInErrorsAndBasicAuthResponse(t *testing.T) {
	v := testVault(t)
	v.Set("SVC_USER", "alice_svc", "test")
	v.Set("SVC_PASS", "s3cr3t_pass_999", "test")
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{
		Secrets: map[string]config.SecretPolicy{
			"API_KEY":  {AllowedHosts: []string{"127.0.0.1"}},
			"SVC_USER": {AllowedHosts: []string{"127.0.0.1"}},
			"SVC_PASS": {AllowedHosts: []string{"127.0.0.1"}},
		},
	}

	// Transport error must redact secret placed in query string (*url.Error).
	_, err := Do(context.Background(), v, cfg, Request{
		Method:    "GET",
		URL:       "http://127.0.0.1:1/v1?api_key={{API_KEY}}",
		Transport: failingRoundTripper{},
	})
	if err == nil {
		t.Fatal("expected error from failing transport")
	}
	if strings.Contains(err.Error(), "sk_http_secret_12345") {
		t.Fatalf("secret leaked in transport error: %v", err)
	}
	if !strings.Contains(err.Error(), "‹keytwig:API_KEY›") {
		t.Fatalf("expected redacted placeholder in error: %v", err)
	}

	// Cross-host / insecure redirect with secret in query must not leak secret.
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/leak?api_key="+r.URL.Query().Get("api_key"), http.StatusFound)
	}))
	defer redirector.Close()
	_, err = Do(context.Background(), v, cfg, Request{
		Method: "GET",
		URL:    redirector.URL + "/start?api_key={{API_KEY}}",
	})
	if err == nil {
		t.Fatal("expected redirect error")
	}
	if strings.Contains(err.Error(), "sk_http_secret_12345") {
		t.Fatalf("secret leaked in redirect error: %v", err)
	}

	// Basic auth pair derived from SVC_USER + SVC_PASS must be redacted in response.
	b64 := base64.StdEncoding.EncodeToString([]byte("alice_svc:s3cr3t_pass_999"))
	echoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("echo Basic " + b64))
	}))
	defer echoSrv.Close()
	resp, err := Do(context.Background(), v, cfg, Request{
		Method: "POST",
		URL:    echoSrv.URL,
		Body:   `{"u":"{{SVC_USER}}","p":"{{SVC_PASS}}"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(resp.Body, b64) {
		t.Fatalf("basic auth token leaked in response: %s", resp.Body)
	}
	if resp.Redactions < 1 {
		t.Fatalf("expected basic auth redaction, got %d", resp.Redactions)
	}
}
