// Command delivery — backend demo-сервиса «Доставка» (BE-016): вход через
// Vault по OAuth 2.0 (Authorization Code + PKCE, BE-005), получение
// разрешённых полей (BE-014) и pull-синхронизация изменений (BE-013).
package main

import (
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// config — настройки demo-сервиса из переменных окружения.
type config struct {
	Port           string
	VaultURL       string
	PublicVaultURL string
	ClientID       string
	RedirectURI    string
	Scopes         []string
}

func loadConfig() (config, error) {
	cfg := config{
		Port:           envOr("PORT", "8090"),
		VaultURL:       strings.TrimRight(envOr("VAULT_URL", "http://localhost:8080"), "/"),
		PublicVaultURL: strings.TrimRight(envOr("PUBLIC_VAULT_URL", "http://localhost:3000/api"), "/"),
		ClientID:       envOr("CLIENT_ID", "delivery"),
		RedirectURI:    envOr("REDIRECT_URI", "http://localhost:8090/callback"),
	}
	for _, scope := range strings.Split(envOr("SCOPES", "full_name,email,phone,address"), ",") {
		if scope = strings.TrimSpace(scope); scope != "" {
			cfg.Scopes = append(cfg.Scopes, scope)
		}
	}
	if len(cfg.Scopes) == 0 {
		return config{}, fmt.Errorf("SCOPES must contain at least one scope")
	}
	return cfg, nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// Имена cookie demo-сервиса.
const (
	cookieToken    = "delivery_token"
	cookieCursor   = "delivery_sync_cursor"
	cookieState    = "delivery_state"
	cookieVerifier = "delivery_verifier"
)

// PKCE: verifier — 32 случайных байта в base64url, challenge — его SHA-256.
func newVerifier() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// newState — случайный CSRF-параметр авторизации.
func newState() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// authorizeURL собирает адрес /oauth/authorize Vault с параметрами PKCE.
func authorizeURL(cfg config, challenge, state string) string {
	q := url.Values{}
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", cfg.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(cfg.Scopes, " "))
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	return cfg.PublicVaultURL + "/oauth/authorize?" + q.Encode()
}

// JSON-формы ответов Vault (BE-013 / BE-014).
type pdvField struct {
	Key       string    `json:"key"`
	Label     string    `json:"label"`
	Value     string    `json:"value"`
	Custom    bool      `json:"custom"`
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

type dataResponse struct {
	Fields []pdvField `json:"fields"`
}

type consentResponse struct {
	ClientID   string   `json:"client_id"`
	ClientName string   `json:"client_name"`
	Status     string   `json:"status"`
	AccessType string   `json:"access_type"`
	Scopes     []string `json:"scopes"`
}

type syncResponse struct {
	Since   string     `json:"since"`
	Changes []pdvField `json:"changes"`
	Deleted []string   `json:"deleted"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type app struct {
	cfg    config
	client *http.Client
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	a := &app{cfg: cfg, client: &http.Client{Timeout: 5 * time.Second}}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.home)
	mux.HandleFunc("GET /login", a.login)
	mux.HandleFunc("GET /callback", a.callback)
	mux.HandleFunc("POST /logout", a.logout)
	mux.HandleFunc("GET /styles.css", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write([]byte(pageStyles))
	})
	mux.HandleFunc("GET /app.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write([]byte(pageScript))
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("delivery demo listening on :%s (vault: %s, client: %s)", cfg.Port, cfg.VaultURL, cfg.ClientID)
	server := &http.Server{Addr: ":" + cfg.Port, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}

// apiGet выполняет GET к Vault с Bearer-токеном и разбирает JSON в dst.
func (a *app) apiGet(path, token string, dst any) (int, error) {
	req, err := http.NewRequest(http.MethodGet, a.cfg.VaultURL+path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := a.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if dst != nil && resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

// pageData — всё, что рендерит главная страница.
type pageData struct {
	LoggedIn          bool
	ConsentStatus     string
	ConsentAccessType string
	Scopes            []string
	Fields            []pdvField
	Changes           []pdvField
	Deleted           []string
	SyncSince         string
	Message           string
	NeedSync          bool
	Options           []scopeOption
}

type scopeOption struct{ Key, Label string }

func fieldLabel(key string) string {
	labels := map[string]string{"full_name": "ФИО", "email": "Email", "phone": "Телефон", "address": "Адрес доставки", "birth_date": "Дата рождения"}
	if label, ok := labels[key]; ok {
		return label
	}
	return key
}

func (a *app) home(w http.ResponseWriter, r *http.Request) {
	data := pageData{}
	for _, scope := range a.cfg.Scopes {
		data.Options = append(data.Options, scopeOption{Key: scope, Label: fieldLabel(scope)})
	}
	token := cookieValue(r, cookieToken)
	if token == "" {
		data.Message = "Войдите через Vault, чтобы сервис получил ваши данные."
		renderPage(w, data)
		return
	}
	data.LoggedIn = true

	var consent consentResponse
	if status, err := a.apiGet("/services/consent", token, &consent); err != nil {
		data.Message = "Не удалось проверить статус согласия."
	} else if status == http.StatusOK {
		data.ConsentStatus = consent.Status
		data.ConsentAccessType = consent.AccessType
		data.Scopes = consent.Scopes
		if consent.Status == "revoked" {
			data.Message = "Согласие отозвано: сервис больше не получает ваши данные."
		} else if consent.AccessType != "sync" {
			data.Message = "Согласие активно (только чтение). Для синхронизации изменений включите тип «Синхронизация» для сервиса Delivery в Vault."
			data.NeedSync = true
		}
	} else if status == http.StatusUnauthorized {
		clearCookie(w, cookieToken)
		clearCookie(w, cookieCursor)
		data.LoggedIn = false
		data.Message = "Сессия истекла. Подключите Vault снова."
		renderPage(w, data)
		return
	} else {
		data.Message = fmt.Sprintf("Статус согласия недоступен (HTTP %d).", status)
	}

	var fields dataResponse
	if status, err := a.apiGet("/services/data", token, &fields); err != nil {
		data.Message += " Не удалось получить данные."
	} else if status == http.StatusForbidden {
		data.Message += " Получение данных запрещено (согласие отозвано или поле не разрешено)."
	} else if status == http.StatusOK {
		data.Fields = fields.Fields
	}

	if data.ConsentAccessType == "sync" && data.ConsentStatus == "active" {
		a.sync(w, r, token, &data)
	}

	renderPage(w, data)
}

// sync вызывает pull-синхронизацию и обновляет курсор в cookie.
func (a *app) sync(w http.ResponseWriter, r *http.Request, token string, data *pageData) {
	path := "/services/sync"
	if cursor := cookieValue(r, cookieCursor); cursor != "" {
		path += "?since=" + url.QueryEscape(cursor)
	}
	var result syncResponse
	status, err := a.apiGet(path, token, &result)
	if err != nil {
		data.Message += " Синхронизация не выполнена."
		return
	}
	switch status {
	case http.StatusOK:
		data.Changes = result.Changes
		data.Deleted = result.Deleted
		data.SyncSince = result.Since
		if result.Since != "" {
			http.SetCookie(w, &http.Cookie{Name: cookieCursor, Value: result.Since, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 86400})
		}
	case http.StatusForbidden:
		data.Message += " Синхронизация запрещена: согласие должно иметь тип sync."
	default:
		data.Message += fmt.Sprintf(" Синхронизация недоступна (HTTP %d).", status)
	}
}

// login начинает OAuth: PKCE + state в cookie и редирект на экран согласия.
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	cfg := a.cfg
	if r.URL.Query().Has("selection") {
		requested := r.URL.Query()["scope"]
		if len(requested) == 0 || len(requested) > len(a.cfg.Scopes) {
			http.Error(w, "Выберите хотя бы одно разрешённое поле", http.StatusBadRequest)
			return
		}
		allowed := make(map[string]bool, len(a.cfg.Scopes))
		for _, scope := range a.cfg.Scopes {
			allowed[scope] = true
		}
		seen := make(map[string]bool, len(requested))
		for _, scope := range requested {
			if !allowed[scope] || seen[scope] {
				http.Error(w, "Недопустимый список полей", http.StatusBadRequest)
				return
			}
			seen[scope] = true
		}
		cfg.Scopes = requested
	}
	verifier, err := newVerifier()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	state, err := newState()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieVerifier, Value: verifier, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.SetCookie(w, &http.Cookie{Name: cookieState, Value: state, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, authorizeURL(cfg, pkceChallenge(verifier), state), http.StatusSeeOther)
}

// callback завершает OAuth: проверка state, обмен кода на токен.
func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie(cookieState)
	if err != nil || stateCookie.Value == "" || stateCookie.Value != r.URL.Query().Get("state") {
		http.Error(w, "invalid state", http.StatusForbidden)
		return
	}
	verifierCookie, err := r.Cookie(cookieVerifier)
	if err != nil || verifierCookie.Value == "" {
		http.Error(w, "missing PKCE verifier", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "authorization failed: "+r.URL.Query().Get("error"), http.StatusBadRequest)
		return
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", a.cfg.RedirectURI)
	form.Set("client_id", a.cfg.ClientID)
	form.Set("code_verifier", verifierCookie.Value)

	resp, err := a.client.PostForm(a.cfg.VaultURL+"/oauth/token", form)
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("token exchange failed: HTTP %d", resp.StatusCode), http.StatusBadGateway)
		return
	}
	var tokens tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		http.Error(w, "invalid token response", http.StatusBadGateway)
		return
	}
	if tokens.AccessToken == "" {
		http.Error(w, "token response has no access_token", http.StatusBadGateway)
		return
	}

	// Токен живёт в HttpOnly cookie, в HTML он не попадает.
	maxAge := 15 * 60
	if tokens.ExpiresIn > 0 && tokens.ExpiresIn < maxAge {
		maxAge = tokens.ExpiresIn
	}
	http.SetCookie(w, &http.Cookie{Name: cookieToken, Value: tokens.AccessToken, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
	clearCookie(w, cookieState)
	clearCookie(w, cookieVerifier)
	clearCookie(w, cookieCursor) // новая авторизация — синхронизация с нуля
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// logout удаляет токен и курсор.
func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	clearCookie(w, cookieToken)
	clearCookie(w, cookieCursor)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func cookieValue(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

//go:embed page.html
var pageHTML string

//go:embed styles.css
var pageStyles string

//go:embed app.js
var pageScript string

var pageTemplate = template.Must(template.New("page").Funcs(template.FuncMap{"fieldLabel": fieldLabel}).Parse(pageHTML))

func renderPage(w http.ResponseWriter, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := pageTemplate.Execute(w, data); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
	}
}
