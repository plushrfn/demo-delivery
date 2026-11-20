// Command delivery — backend demo-сервиса «Доставка» (BE-016): вход через
// Vault по OAuth 2.0 (Authorization Code + PKCE, BE-005), получение
// разрешённых полей (BE-014) и pull-синхронизация изменений (BE-013).
package main

import (
	"crypto/rand"
	"crypto/sha256"
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
	Port        string
	VaultURL    string
	ClientID    string
	RedirectURI string
	Scopes      []string
}

func loadConfig() (config, error) {
	cfg := config{
		Port:        envOr("PORT", "8090"),
		VaultURL:    strings.TrimRight(envOr("VAULT_URL", "http://localhost:8080"), "/"),
		ClientID:    envOr("CLIENT_ID", "delivery"),
		RedirectURI: envOr("REDIRECT_URI", "http://localhost:8090/callback"),
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
	return cfg.VaultURL + "/oauth/authorize?" + q.Encode()
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
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("delivery demo listening on :%s (vault: %s, client: %s)", cfg.Port, cfg.VaultURL, cfg.ClientID)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, mux))
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
	SyncSince         string
	Message           string
	NeedSync          bool
}

func (a *app) home(w http.ResponseWriter, r *http.Request) {
	data := pageData{}
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
	http.Redirect(w, r, authorizeURL(a.cfg, pkceChallenge(verifier), state), http.StatusSeeOther)
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

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><title>Доставка — demo-сервис</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; color: #111827; }
h1 { font-size: 1.6rem; }
.badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 999px; font-size: 0.8rem; }
.sync { background: #DBEAFE; color: #1E40AF; }
.read { background: #F3F4F6; color: #4B5563; }
.revoked { background: #FEE2E2; color: #991B1B; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
td, th { border: 1px solid #E5E7EB; padding: 0.5rem; text-align: left; }
.msg { padding: 0.75rem 1rem; border-radius: 8px; background: #FFFBEB; border: 1px solid #FDE68A; }
.btn { display: inline-block; margin-right: 0.5rem; padding: 0.5rem 1rem; border-radius: 6px; background: #047857; color: #fff; text-decoration: none; }
</style></head><body>
<h1>Доставка — demo-сервис</h1>
{{if .Message}}<div class="msg">{{.Message}}</div>{{end}}
{{if not .LoggedIn}}
  <p>Сервис получает ваши данные из Vault только с вашего согласия.</p>
  <a class="btn" href="/login">Войти через Vault</a>
{{else}}
  <p>Согласие: <span class="badge {{if eq .ConsentStatus "revoked"}}revoked{{else if eq .ConsentAccessType "sync"}}sync{{else}}read{{end}}">{{.ConsentStatus}}{{if ne .ConsentStatus "revoked"}} · {{if eq .ConsentAccessType "sync"}}Синхронизация{{else}}Только чтение{{end}}{{end}}</span></p>
  <p>Разрешённые поля: {{range .Scopes}}{{.}} {{end}}</p>
  <h2>Данные из Vault</h2>
  {{if .Fields}}
  <table><tr><th>Поле</th><th>Значение</th><th>Версия</th></tr>
  {{range .Fields}}<tr><td>{{.Label}}</td><td>{{.Value}}</td><td>{{.Version}}</td></tr>{{end}}
  </table>
  {{else}}<p>Данные пока не получены.</p>{{end}}
  {{if .SyncSince}}
  <h2>Синхронизация</h2>
  {{if .Changes}}
  <table><tr><th>Поле</th><th>Новое значение</th><th>Версия</th></tr>
  {{range .Changes}}<tr><td>{{.Label}}</td><td>{{.Value}}</td><td>{{.Version}}</td></tr>{{end}}
  </table>
  {{else}}<p>Изменений с последней синхронизации нет.</p>{{end}}
  {{end}}
  <p><a class="btn" href="/">Обновить и синхронизировать</a></p>
  <form method="post" action="/logout"><button class="btn" type="submit" style="background:#B91C1C">Выйти</button></form>
{{end}}
</body></html>`))

func renderPage(w http.ResponseWriter, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := pageTemplate.Execute(w, data); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
	}
}
