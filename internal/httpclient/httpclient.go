// Package httpclient executes HTTP requests with vault secret placeholders
// ({{NAME}}) without invoking a shell, enforcing per-secret allowed_hosts and
// cross-host redirect protection, and masking any reflected secrets in output.
package httpclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/keytwig/keytwig/internal/config"
	"github.com/keytwig/keytwig/internal/redact"
	"github.com/keytwig/keytwig/internal/vault"
)

const (
	DefaultTimeout = 30 * time.Second
	MaxTimeout     = 120 * time.Second
	MaxBodyBytes   = 64 * 1024
)

var AllowedMethods = map[string]bool{
	"GET":    true,
	"POST":   true,
	"PUT":    true,
	"PATCH":  true,
	"DELETE": true,
	"HEAD":   true,
}

var placeholderRe = regexp.MustCompile(`\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}`)

// Request describes an HTTP call with optional {{NAME}} secret placeholders.
type Request struct {
	Method    string
	URL       string
	Headers   map[string]string
	Body      string
	Timeout   time.Duration
	Agent     string
	Transport http.RoundTripper // optional, primarily for tests
}

// Response is the masked HTTP response returned to callers.
type Response struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body"`
	Injected   []string          `json:"injected,omitempty"`
	Redactions int               `json:"redactions"`
}

func isLocalhost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func collectPlaceholders(s string, dst map[string]bool) {
	for _, m := range placeholderRe.FindAllStringSubmatch(s, -1) {
		dst[m[1]] = true
	}
}

func replacePlaceholders(s string, vals map[string]string) string {
	if len(vals) == 0 || !strings.Contains(s, "{{") {
		return s
	}
	return placeholderRe.ReplaceAllStringFunc(s, func(tok string) string {
		name := tok[2 : len(tok)-2]
		if v, ok := vals[name]; ok {
			return v
		}
		return tok
	})
}

func redactString(s string, secrets map[string]string) (string, int) {
	if s == "" || len(secrets) == 0 {
		return s, 0
	}
	var buf bytes.Buffer
	w := redact.New(&buf, secrets)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return buf.String(), w.Count()
}

// Do validates the request and secret policies, executes the HTTP request,
// and returns a masked Response.
func Do(ctx context.Context, v *vault.Vault, cfg config.Config, req Request) (*Response, error) {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = "GET"
	}
	if !AllowedMethods[method] {
		return nil, fmt.Errorf("unsupported HTTP method %q (allowed: GET, POST, PUT, PATCH, DELETE, HEAD)", method)
	}

	rawURL := strings.TrimSpace(req.URL)
	if rawURL == "" {
		return nil, errors.New("url is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	targetHost := u.Hostname()
	if targetHost == "" {
		return nil, errors.New("url must include a host")
	}
	if strings.Contains(targetHost, "{{") || strings.Contains(u.Host, "{{") {
		return nil, errors.New("secret placeholders are not allowed in the URL host")
	}
	switch scheme {
	case "https":
	case "http":
		if !isLocalhost(targetHost) {
			return nil, fmt.Errorf("plain http is only allowed for localhost/127.0.0.1/::1 (got %q); use https", targetHost)
		}
	default:
		return nil, fmt.Errorf("unsupported URL scheme %q (use https)", u.Scheme)
	}

	refs := map[string]bool{}
	collectPlaceholders(rawURL, refs)
	for _, hv := range req.Headers {
		collectPlaceholders(hv, refs)
	}
	collectPlaceholders(req.Body, refs)

	injected := make([]string, 0, len(refs))
	for name := range refs {
		injected = append(injected, name)
	}
	sort.Strings(injected)

	resolved := make(map[string]string, len(injected))
	for _, name := range injected {
		sec, ok := v.Get(name)
		if !ok {
			return nil, fmt.Errorf("secret %s not found (see `keytwig ls`)", name)
		}
		canon := v.Canonical(name)
		allNames := append([]string{canon}, sec.Aliases...)
		if !cfg.Allowed(req.Agent, allNames...) {
			return nil, fmt.Errorf("secret %s is not allowed for agent %q (config.toml [agents])", name, req.Agent)
		}
		if !cfg.HostAllowed(targetHost, allNames...) {
			return nil, fmt.Errorf("secret %s is not allowed for host %q: add [secrets.%s] allowed_hosts = [%q] in config.toml", name, targetHost, canon, strings.ToLower(targetHost))
		}
		resolved[name] = sec.Value
	}

	allSecrets := v.Values()
	redact.AddBasicAuthPairs(allSecrets, resolved)
	redactErr := func(err error) error {
		if err == nil {
			return nil
		}
		msg, _ := redactString(err.Error(), allSecrets)
		return errors.New(msg)
	}

	finalURL := replacePlaceholders(rawURL, resolved)
	parsedFinal, err := url.Parse(finalURL)
	if err != nil {
		return nil, redactErr(fmt.Errorf("invalid url after substitution: %w", err))
	}
	if !strings.EqualFold(parsedFinal.Hostname(), targetHost) || strings.ToLower(parsedFinal.Scheme) != scheme {
		return nil, errors.New("url scheme or host changed after secret substitution")
	}

	finalBody := replacePlaceholders(req.Body, resolved)
	var bodyReader io.Reader
	if finalBody != "" {
		bodyReader = strings.NewReader(finalBody)
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if timeout > MaxTimeout {
		timeout = MaxTimeout
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, finalURL, bodyReader)
	if err != nil {
		return nil, redactErr(err)
	}
	for k, hv := range req.Headers {
		httpReq.Header.Set(k, replacePlaceholders(hv, resolved))
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: req.Transport,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(injected) > 0 {
				if !strings.EqualFold(r.URL.Hostname(), targetHost) {
					return fmt.Errorf("refusing cross-host redirect from %s to %s when secrets are injected", targetHost, r.URL.Hostname())
				}
				if strings.ToLower(r.URL.Scheme) == "http" && !isLocalhost(r.URL.Hostname()) {
					return fmt.Errorf("refusing insecure redirect to %s://%s when secrets are injected", r.URL.Scheme, r.URL.Host)
				}
			}
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, redactErr(err)
	}
	defer resp.Body.Close()

	rawResp, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if err != nil {
		return nil, redactErr(err)
	}
	truncated := false
	if len(rawResp) > MaxBodyBytes {
		rawResp = rawResp[:MaxBodyBytes]
		truncated = true
	}

	redactions := 0

	redactedBody, n := redactString(string(rawResp), allSecrets)
	redactions += n
	if truncated {
		redactedBody += "\n[output truncated]"
	}

	outHeaders := map[string]string{}
	for k, vals := range resp.Header {
		joined := strings.Join(vals, ", ")
		rv, rn := redactString(joined, allSecrets)
		redactions += rn
		outHeaders[k] = rv
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    outHeaders,
		Body:       redactedBody,
		Injected:   injected,
		Redactions: redactions,
	}, nil
}
