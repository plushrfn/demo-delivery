package main

import (
	"net/url"
	"strings"
	"testing"
)

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
		VaultURL:    "http://localhost:8080",
		ClientID:    "delivery",
		RedirectURI: "http://localhost:8090/callback",
		Scopes:      []string{"full_name", "email"},
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
	for _, name := range []string{"PORT", "VAULT_URL", "CLIENT_ID", "REDIRECT_URI", "SCOPES"} {
		t.Setenv(name, "")
	}
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != "8090" || cfg.VaultURL != "http://localhost:8080" ||
		cfg.ClientID != "delivery" || cfg.RedirectURI != "http://localhost:8090/callback" {
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
