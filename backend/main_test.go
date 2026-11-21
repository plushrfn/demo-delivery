package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestFrontendTemplateMatchesEmbeddedPage(t *testing.T) {
	frontend, err := os.ReadFile("../frontend/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if string(frontend) != pageHTML {
		t.Fatal("frontend/index.html differs from embedded page.html")
	}
	styles, err := os.ReadFile("../frontend/styles.css")
	if err != nil {
		t.Fatal(err)
	}
	if string(styles) != pageStyles {
		t.Fatal("frontend/styles.css differs from embedded styles.css")
	}
	script, err := os.ReadFile("../frontend/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if string(script) != pageScript {
		t.Fatal("frontend/app.js differs from embedded app.js")
	}
}

func TestLoginRequestsSelectedAllowedFields(t *testing.T) {
	a := &app{cfg: config{PublicVaultURL: "http://localhost:3000/api", ClientID: "delivery", RedirectURI: "http://localhost:8090/callback", Scopes: []string{"full_name", "email", "phone", "address"}}}
	for _, tc := range []struct {
		path       string
		wantStatus int
		wantScope  string
	}{
		{"/login?selection=1&scope=email&scope=address", http.StatusSeeOther, "email address"},
		{"/login", http.StatusSeeOther, "full_name email phone address"},
		{"/login?selection=1", http.StatusBadRequest, ""},
		{"/login?selection=1&scope=email&scope=passport", http.StatusBadRequest, ""},
		{"/login?selection=1&scope=email&scope=email", http.StatusBadRequest, ""},
	} {
		t.Run(tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			a.login(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusSeeOther {
				u, err := url.Parse(rec.Header().Get("Location"))
				if err != nil {
					t.Fatal(err)
				}
				if got := u.Query().Get("scope"); got != tc.wantScope {
					t.Fatalf("scope = %q", got)
				}
				if u.Query().Get("code_challenge_method") != "S256" {
					t.Fatal("missing PKCE")
				}
			}
		})
	}
}

func TestHomeUsesBackendAndKeepsTokenOutOfHTML(t *testing.T) {
	const token = "secret-test-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("missing token on %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/services/consent":
			_, _ = w.Write([]byte(`{"status":"active","access_type":"sync","scopes":["email"]}`))
		case "/services/data":
			_, _ = w.Write([]byte(`{"fields":[{"key":"email","label":"Email","value":"<script>alert(1)</script>","version":2}]}`))
		case "/services/sync":
			_, _ = w.Write([]byte(`{"since":"2026-11-21T00:00:00Z","changes":[],"deleted":["email"]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	a := &app{cfg: config{VaultURL: server.URL, Scopes: []string{"email"}}, client: server.Client()}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: cookieToken, Value: token})
	rec := httptest.NewRecorder()
	a.home(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Удалённые поля") || !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("unexpected response status=%d", rec.Code)
	}
	if strings.Contains(body, token) || strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("token or unescaped data in page")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("sensitive page must not be cached")
	}
}

func TestExpiredTokenShowsReconnect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer server.Close()
	a := &app{cfg: config{VaultURL: server.URL, Scopes: []string{"email"}}, client: server.Client()}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: cookieToken, Value: "expired-token"})
	rec := httptest.NewRecorder()
	a.home(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Сессия истекла") || !strings.Contains(rec.Body.String(), "Подключить Personal Data Vault") {
		t.Fatal("expired session must offer reconnection")
	}
}

// Вектор из RFC 7636, Appendix B: challenge для известного verifier.
func TestPKCEChallengeMatchesRFC7636(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := pkceChallenge(verifier); got != expected {
		t.Fatalf("challenge = %q, want %q", got, expected)
	}
}

func TestNewVerifierIsURLSafeAndLongEnough(t *testing.T) {
	verifier, err := newVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if len(verifier) < 43 || len(verifier) > 128 {
		t.Fatalf("verifier length = %d, want 43..128", len(verifier))
	}
	if strings.ContainsAny(verifier, "+/=") {
		t.Fatalf("verifier %q contains non-url-safe characters", verifier)
	}
}

func TestAuthorizeURLContainsPKCEParams(t *testing.T) {
	cfg := config{
		VaultURL:       "http://localhost:8080",
		PublicVaultURL: "http://localhost:8080",
		ClientID:       "delivery",
		RedirectURI:    "http://localhost:8090/callback",
		Scopes:         []string{"full_name", "email"},
	}
	u, err := url.Parse(authorizeURL(cfg, "challenge-xyz", "state-abc"))
	if err != nil {
		t.Fatal(err)
	}
	if base := u.Scheme + "://" + u.Host + u.Path; base != "http://localhost:8080/oauth/authorize" {
		t.Fatalf("base = %q", base)
	}
	q := u.Query()
	for key, want := range map[string]string{
		"client_id":             "delivery",
		"redirect_uri":          "http://localhost:8090/callback",
		"response_type":         "code",
		"scope":                 "full_name email",
		"code_challenge":        "challenge-xyz",
		"code_challenge_method": "S256",
		"state":                 "state-abc",
	} {
		if got := q.Get(key); got != want {
			t.Errorf("param %s = %q, want %q", key, got, want)
		}
	}
}

func TestLoadConfigDefaultsAndScopes(t *testing.T) {
	for _, name := range []string{"PORT", "VAULT_URL", "PUBLIC_VAULT_URL", "CLIENT_ID", "REDIRECT_URI", "SCOPES"} {
		t.Setenv(name, "")
	}
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != "8090" || cfg.VaultURL != "http://localhost:8080" ||
		cfg.PublicVaultURL != "http://localhost:3000/api" || cfg.ClientID != "delivery" || cfg.RedirectURI != "http://localhost:8090/callback" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if len(cfg.Scopes) != 4 || cfg.Scopes[0] != "full_name" {
		t.Fatalf("scopes = %v", cfg.Scopes)
	}

	t.Setenv("SCOPES", "full_name,  email ")
	t.Setenv("VAULT_URL", "http://example.com/")
	cfg, err = loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VaultURL != "http://example.com" {
		t.Fatalf("VaultURL trailing slash not trimmed: %q", cfg.VaultURL)
	}
	if len(cfg.Scopes) != 2 || cfg.Scopes[1] != "email" {
		t.Fatalf("scopes parsing = %v", cfg.Scopes)
	}
}
