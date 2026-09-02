package app

import (
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/s-gor/sg-infosec/internal/web/auth"
	"github.com/s-gor/sg-infosec/internal/web/coreclient"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

const sessionCookieName = "sg_infosec_session"

type Config struct {
	BasePath   string
	SessionTTL time.Duration
}

type application struct {
	cfg   Config
	auth  *auth.Store
	core  coreclient.Service
	login string
	setup string
}

func New(cfg Config, authStore *auth.Store, core coreclient.Service) (http.Handler, error) {
	if cfg.BasePath == "/" || !strings.HasPrefix(cfg.BasePath, "/") || !strings.HasSuffix(cfg.BasePath, "/") || strings.Contains(cfg.BasePath, "//") || strings.Contains(cfg.BasePath, "..") {
		return nil, fmt.Errorf("base path must be a non-root absolute path ending in slash")
	}
	if cfg.SessionTTL <= 0 || cfg.SessionTTL > 24*time.Hour {
		return nil, fmt.Errorf("invalid session lifetime")
	}
	if authStore == nil {
		return nil, fmt.Errorf("auth store is required")
	}
	if core == nil {
		return nil, fmt.Errorf("core client is required")
	}
	return &application{
		cfg:   cfg,
		auth:  authStore,
		core:  core,
		login: cfg.BasePath + "login",
		setup: cfg.BasePath + "setup",
	}, nil
}

func (a *application) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	if !strings.HasPrefix(r.URL.Path, a.cfg.BasePath) {
		http.NotFound(w, r)
		return
	}
	relative := strings.TrimPrefix(r.URL.Path, a.cfg.BasePath)
	if strings.Contains(relative, "//") || strings.Contains(relative, "..") {
		http.NotFound(w, r)
		return
	}

	switch relative {
	case "setup":
		a.handleSetup(w, r)
		return
	case "login":
		a.handleLogin(w, r)
		return
	}

	session, csrf, ok := a.currentSession(r)
	if !ok {
		if !a.auth.AdminConfigured() {
			http.Redirect(w, r, a.setup, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, a.login, http.StatusSeeOther)
		return
	}

	switch relative {
	case "":
		a.dashboard(w, r, session.Username, csrf)
	case "logout":
		a.logout(w, r, session.Token, csrf)
	case "decisions":
		a.decisions(w, r, session.Username, csrf)
	case "decisions/add":
		a.addDecision(w, r, session.Token, csrf)
	case "decisions/revoke":
		a.revokeDecision(w, r, session.Token, csrf)
	case "allowlist":
		a.allowlist(w, r, session.Username, csrf)
	case "allowlist/add":
		a.addAllowlist(w, r, session.Token, csrf)
	case "allowlist/remove":
		a.removeAllowlist(w, r, session.Token, csrf)
	case "audit":
		a.audit(w, r, session.Username, csrf)
	default:
		http.NotFound(w, r)
	}
}

func (a *application) handleSetup(w http.ResponseWriter, r *http.Request) {
	if a.auth.AdminConfigured() {
		http.Redirect(w, r, a.login, http.StatusSeeOther)
		return
	}
	switch r.Method {
	case http.MethodGet:
		message := "Введите одноразовый setup-code, полученный при установке SG InfoSec."
		if !a.auth.SetupPending() {
			message = "Setup-code отсутствует или истёк. Выпустите новый локальной командой администратора."
		}
		a.renderPublic(w, "Первичная настройка", `<section class="auth-card"><h1>Первичная настройка</h1><p>`+html.EscapeString(message)+`</p><form method="post"><label>Setup-code<input name="setup_code" autocomplete="one-time-code" required></label><label>Логин администратора<input name="username" autocomplete="username" minlength="3" maxlength="64" required></label><label>Пароль<input type="password" name="password" autocomplete="new-password" minlength="12" required></label><button type="submit">Создать администратора</button></form></section>`)
	case http.MethodPost:
		if err := parseSmallForm(r); err != nil {
			http.Error(w, "Некорректная форма", http.StatusBadRequest)
			return
		}
		err := a.auth.ConsumeSetup(r.FormValue("setup_code"), r.FormValue("username"), r.FormValue("password"))
		if err != nil {
			a.renderPublicStatus(w, "Первичная настройка", `<section class="auth-card"><h1>Первичная настройка</h1><div class="error">Setup-code или параметры администратора отклонены.</div><a class="button secondary" href="`+a.setup+`">Повторить</a></section>`, http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, a.login, http.StatusSeeOther)
	default:
		methodNotAllowed(w)
	}
}

func (a *application) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !a.auth.AdminConfigured() {
		http.Redirect(w, r, a.setup, http.StatusSeeOther)
		return
	}
	if _, _, ok := a.currentSession(r); ok {
		http.Redirect(w, r, a.cfg.BasePath, http.StatusSeeOther)
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.renderPublic(w, "Вход", `<section class="auth-card"><h1>SG InfoSec</h1><p>Автономная панель управления защитой.</p><form method="post"><label>Логин<input name="username" autocomplete="username" required></label><label>Пароль<input type="password" name="password" autocomplete="current-password" required></label><button type="submit">Войти</button></form></section>`)
	case http.MethodPost:
		if err := parseSmallForm(r); err != nil {
			http.Error(w, "Некорректная форма", http.StatusBadRequest)
			return
		}
		username := r.FormValue("username")
		err := a.auth.Authenticate(username, r.FormValue("password"), remoteKey(r))
		if err != nil {
			status := http.StatusUnauthorized
			message := "Неверный логин или пароль."
			if errors.Is(err, auth.ErrRateLimited) {
				status = http.StatusTooManyRequests
				message = "Слишком много неудачных попыток. Повторите позже."
			}
			a.renderPublicStatus(w, "Вход", `<section class="auth-card"><h1>Вход</h1><div class="error">`+html.EscapeString(message)+`</div><a class="button secondary" href="`+a.login+`">Вернуться</a></section>`, status)
			return
		}
		session, err := a.auth.NewSession(username, a.cfg.SessionTTL)
		if err != nil {
			http.Error(w, "Не удалось создать сессию", http.StatusInternalServerError)
			return
		}
		a.setSessionCookie(w, session)
		http.Redirect(w, r, a.cfg.BasePath, http.StatusSeeOther)
	default:
		methodNotAllowed(w)
	}
}

func (a *application) dashboard(w http.ResponseWriter, r *http.Request, username, csrf string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	health, err := a.core.Health(r.Context())
	status := "Недоступно"
	database := "—"
	active := "—"
	badge := "bad"
	if err == nil {
		status = health.Status
		database = health.Database
		active = strconv.FormatInt(health.ActiveDecisions, 10)
		badge = "good"
	}
	content := `<div class="hero"><div><div class="eyebrow">Standalone security control</div><h1>Состояние защиты</h1><p>SG InfoSec работает независимо от панели SG-Gateway.</p></div><span class="status ` + badge + `">` + html.EscapeString(status) + `</span></div>` +
		`<div class="metrics"><div class="metric"><span>Ядро</span><strong>` + html.EscapeString(status) + `</strong></div><div class="metric"><span>База</span><strong>` + html.EscapeString(database) + `</strong></div><div class="metric"><span>Активные блокировки</span><strong>` + active + `</strong></div></div>` +
		`<div class="grid"><a class="panel link-panel" href="` + a.cfg.BasePath + `decisions"><h2>Блокировки</h2><p>Активные решения, ручные блокировки и отзыв.</p></a><a class="panel link-panel" href="` + a.cfg.BasePath + `allowlist"><h2>Белый список</h2><p>Разрешённые адреса и подсети.</p></a><a class="panel link-panel" href="` + a.cfg.BasePath + `audit"><h2>Аудит</h2><p>Журнал административных действий.</p></a></div>`
	a.renderPrivate(w, "Состояние", username, csrf, content, http.StatusOK)
}

func (a *application) decisions(w http.ResponseWriter, r *http.Request, username, csrf string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	response, err := a.core.ListDecisions(r.Context(), coreclient.ListOptions{Limit: 100, State: "active"})
	if err != nil {
		a.renderPrivate(w, "Блокировки", username, csrf, `<div class="error">Не удалось получить блокировки: `+html.EscapeString(err.Error())+`</div>`, http.StatusBadGateway)
		return
	}
	var rows strings.Builder
	for _, item := range response.Items {
		rows.WriteString(`<tr><td><code>` + html.EscapeString(item.IP) + `</code></td><td>` + html.EscapeString(item.Scope) + `</td><td>` + html.EscapeString(item.ReasonCode) + `</td><td>` + html.EscapeString(item.ExpiresAt.UTC().Format(time.RFC3339)) + `</td><td><form method="post" action="` + a.cfg.BasePath + `decisions/revoke"><input type="hidden" name="csrf" value="` + html.EscapeString(csrf) + `"><input type="hidden" name="id" value="` + html.EscapeString(item.ID) + `"><button class="danger small" type="submit">Отозвать</button></form></td></tr>`)
	}
	if rows.Len() == 0 {
		rows.WriteString(`<tr><td colspan="5" class="muted">Активных блокировок нет.</td></tr>`)
	}
	content := `<div class="page-head"><div><h1>Блокировки</h1><p>Решения SG InfoSec, применённые ядром защиты.</p></div></div><section class="panel"><h2>Добавить вручную</h2><form class="form-grid" method="post" action="` + a.cfg.BasePath + `decisions/add"><input type="hidden" name="csrf" value="` + html.EscapeString(csrf) + `"><input type="hidden" name="source" value="local-admin"><input type="hidden" name="backend" value="nftables"><label>IP<input name="ip" placeholder="203.0.113.10" required></label><label>Область<input name="scope" value="ssh" required></label><label>Длительность<input name="duration" value="1h" required></label><label class="wide">Причина<input name="reason" value="manual-web" required></label><button type="submit">Заблокировать</button></form></section><section class="panel table-wrap"><table><thead><tr><th>IP</th><th>Область</th><th>Причина</th><th>До</th><th></th></tr></thead><tbody>` + rows.String() + `</tbody></table></section>`
	a.renderPrivate(w, "Блокировки", username, csrf, content, http.StatusOK)
}

func (a *application) addDecision(w http.ResponseWriter, r *http.Request, sessionToken, csrf string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !a.requireCSRF(w, r, sessionToken, csrf) {
		return
	}
	if err := parseSmallForm(r); err != nil {
		http.Error(w, "Некорректная форма", http.StatusBadRequest)
		return
	}
	_, err := a.core.AddDecision(r.Context(), protocol.ManualDecisionRequest{SourceID: r.FormValue("source"), Scope: r.FormValue("scope"), Backend: r.FormValue("backend"), IP: r.FormValue("ip"), Duration: r.FormValue("duration"), Reason: r.FormValue("reason")})
	if err != nil {
		http.Error(w, "Блокировка отклонена: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, a.cfg.BasePath+"decisions", http.StatusSeeOther)
}

func (a *application) revokeDecision(w http.ResponseWriter, r *http.Request, sessionToken, csrf string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !a.requireCSRF(w, r, sessionToken, csrf) {
		return
	}
	if err := parseSmallForm(r); err != nil {
		http.Error(w, "Некорректная форма", http.StatusBadRequest)
		return
	}
	if _, err := a.core.RevokeDecision(r.Context(), r.FormValue("id")); err != nil {
		http.Error(w, "Не удалось отозвать блокировку: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, a.cfg.BasePath+"decisions", http.StatusSeeOther)
}

func (a *application) allowlist(w http.ResponseWriter, r *http.Request, username, csrf string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	response, err := a.core.ListAllowlist(r.Context(), coreclient.ListOptions{Limit: 100})
	if err != nil {
		a.renderPrivate(w, "Белый список", username, csrf, `<div class="error">Не удалось получить белый список: `+html.EscapeString(err.Error())+`</div>`, http.StatusBadGateway)
		return
	}
	var rows strings.Builder
	for _, item := range response.Items {
		expires := "без срока"
		if item.ExpiresAt != nil {
			expires = item.ExpiresAt.UTC().Format(time.RFC3339)
		}
		rows.WriteString(`<tr><td><code>` + html.EscapeString(item.Prefix) + `</code></td><td>` + html.EscapeString(item.Scope) + `</td><td>` + html.EscapeString(item.Description) + `</td><td>` + html.EscapeString(expires) + `</td><td><form method="post" action="` + a.cfg.BasePath + `allowlist/remove"><input type="hidden" name="csrf" value="` + html.EscapeString(csrf) + `"><input type="hidden" name="id" value="` + html.EscapeString(item.ID) + `"><button class="danger small" type="submit">Удалить</button></form></td></tr>`)
	}
	if rows.Len() == 0 {
		rows.WriteString(`<tr><td colspan="5" class="muted">Белый список пуст.</td></tr>`)
	}
	content := `<div class="page-head"><div><h1>Белый список</h1><p>Исключения из автоматических и ручных блокировок.</p></div></div><section class="panel"><h2>Добавить исключение</h2><form class="form-grid" method="post" action="` + a.cfg.BasePath + `allowlist/add"><input type="hidden" name="csrf" value="` + html.EscapeString(csrf) + `"><label>IP / CIDR<input name="prefix" placeholder="203.0.113.10/32" required></label><label>Область<input name="scope" placeholder="ssh"></label><label class="wide">Описание<input name="description" value="manual-web" required></label><button type="submit">Добавить</button></form></section><section class="panel table-wrap"><table><thead><tr><th>Адрес</th><th>Область</th><th>Описание</th><th>Срок</th><th></th></tr></thead><tbody>` + rows.String() + `</tbody></table></section>`
	a.renderPrivate(w, "Белый список", username, csrf, content, http.StatusOK)
}

func (a *application) addAllowlist(w http.ResponseWriter, r *http.Request, sessionToken, csrf string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !a.requireCSRF(w, r, sessionToken, csrf) {
		return
	}
	if err := parseSmallForm(r); err != nil {
		http.Error(w, "Некорректная форма", http.StatusBadRequest)
		return
	}
	_, err := a.core.AddAllowlist(r.Context(), protocol.AllowlistCreateRequest{Prefix: r.FormValue("prefix"), Scope: r.FormValue("scope"), Description: r.FormValue("description")})
	if err != nil {
		http.Error(w, "Исключение отклонено: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, a.cfg.BasePath+"allowlist", http.StatusSeeOther)
}

func (a *application) removeAllowlist(w http.ResponseWriter, r *http.Request, sessionToken, csrf string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !a.requireCSRF(w, r, sessionToken, csrf) {
		return
	}
	if err := parseSmallForm(r); err != nil {
		http.Error(w, "Некорректная форма", http.StatusBadRequest)
		return
	}
	if _, err := a.core.RemoveAllowlist(r.Context(), r.FormValue("id")); err != nil {
		http.Error(w, "Не удалось удалить исключение: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, a.cfg.BasePath+"allowlist", http.StatusSeeOther)
}

func (a *application) audit(w http.ResponseWriter, r *http.Request, username, csrf string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	response, err := a.core.ListAudit(r.Context(), coreclient.ListOptions{Limit: 100})
	if err != nil {
		a.renderPrivate(w, "Аудит", username, csrf, `<div class="error">Не удалось получить аудит: `+html.EscapeString(err.Error())+`</div>`, http.StatusBadGateway)
		return
	}
	var rows strings.Builder
	for _, item := range response.Items {
		rows.WriteString(`<tr><td>` + html.EscapeString(item.OccurredAt.UTC().Format(time.RFC3339)) + `</td><td>` + html.EscapeString(item.Actor) + `</td><td>` + html.EscapeString(item.Action) + `</td><td>` + html.EscapeString(item.TargetType) + `</td><td><code>` + html.EscapeString(item.TargetID) + `</code></td><td>` + html.EscapeString(item.Result) + `</td></tr>`)
	}
	if rows.Len() == 0 {
		rows.WriteString(`<tr><td colspan="6" class="muted">Записей аудита нет.</td></tr>`)
	}
	content := `<div class="page-head"><div><h1>Аудит</h1><p>Последние административные действия SG InfoSec.</p></div></div><section class="panel table-wrap"><table><thead><tr><th>Время</th><th>Актор</th><th>Действие</th><th>Тип</th><th>Объект</th><th>Результат</th></tr></thead><tbody>` + rows.String() + `</tbody></table></section>`
	a.renderPrivate(w, "Аудит", username, csrf, content, http.StatusOK)
}

func (a *application) logout(w http.ResponseWriter, r *http.Request, sessionToken, csrf string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !a.requireCSRF(w, r, sessionToken, csrf) {
		return
	}
	_ = a.auth.DeleteSession(sessionToken)
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: a.cfg.BasePath, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
	http.Redirect(w, r, a.login, http.StatusSeeOther)
}

func (a *application) currentSession(r *http.Request) (auth.Session, string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return auth.Session{}, "", false
	}
	parts := strings.SplitN(cookie.Value, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return auth.Session{}, "", false
	}
	session, ok := a.auth.Session(parts[0])
	if !ok || !a.auth.ValidateCSRF(parts[0], parts[1]) {
		return auth.Session{}, "", false
	}
	return session, parts[1], true
}

func (a *application) requireCSRF(w http.ResponseWriter, r *http.Request, sessionToken, cookieCSRF string) bool {
	if err := parseSmallForm(r); err != nil {
		http.Error(w, "Некорректная форма", http.StatusBadRequest)
		return false
	}
	formCSRF := r.FormValue("csrf")
	if formCSRF == "" || formCSRF != cookieCSRF || !a.auth.ValidateCSRF(sessionToken, formCSRF) {
		http.Error(w, "CSRF validation failed", http.StatusForbidden)
		return false
	}
	return true
}

func (a *application) setSessionCookie(w http.ResponseWriter, session auth.Session) {
	maxAge := int(time.Until(session.ExpiresAt).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: session.Token + "." + session.CSRFToken, Path: a.cfg.BasePath, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: maxAge, Expires: session.ExpiresAt})
}

func (a *application) renderPrivate(w http.ResponseWriter, title, username, csrf, content string, status int) {
	nav := `<header><a class="brand" href="` + a.cfg.BasePath + `"><span class="shield">SG</span><span>SG InfoSec</span></a><nav><a href="` + a.cfg.BasePath + `">Состояние</a><a href="` + a.cfg.BasePath + `decisions">Блокировки</a><a href="` + a.cfg.BasePath + `allowlist">Белый список</a><a href="` + a.cfg.BasePath + `audit">Аудит</a></nav><div class="account"><span>` + html.EscapeString(username) + `</span><form method="post" action="` + a.cfg.BasePath + `logout"><input type="hidden" name="csrf" value="` + html.EscapeString(csrf) + `"><button class="ghost small" type="submit">Выйти</button></form></div></header>`
	a.renderDocument(w, title, nav+`<main>`+content+`</main>`, status)
}

func (a *application) renderPublic(w http.ResponseWriter, title, content string) {
	a.renderPublicStatus(w, title, content, http.StatusOK)
}

func (a *application) renderPublicStatus(w http.ResponseWriter, title, content string, status int) {
	a.renderDocument(w, title, `<main class="public">`+content+`</main>`, status)
}

func (a *application) renderDocument(w http.ResponseWriter, title, content string, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s — SG InfoSec</title><style>%s</style></head><body>%s</body></html>`, html.EscapeString(title), stylesheet, content)
}

func parseSmallForm(r *http.Request) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 32<<10)
	return r.ParseForm()
}

func remoteKey(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(value) != nil {
		return value
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && net.ParseIP(host) != nil {
		return host
	}
	return r.RemoteAddr
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}

func methodNotAllowed(w http.ResponseWriter) {
	w.Header().Set("Allow", "GET, POST")
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

const stylesheet = `
:root{color-scheme:dark;--bg:#0a0f16;--panel:#111925;--panel2:#162131;--line:#243348;--text:#e8eef7;--muted:#8ea0b8;--accent:#5ad0a5;--danger:#ff7373;--shadow:0 18px 48px rgba(0,0,0,.28)}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% -10%,#173149 0,transparent 35%),var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;min-height:100vh}a{color:inherit;text-decoration:none}header{height:68px;border-bottom:1px solid var(--line);display:flex;align-items:center;padding:0 26px;gap:34px;background:rgba(10,15,22,.92);position:sticky;top:0;backdrop-filter:blur(16px);z-index:2}.brand{display:flex;align-items:center;gap:10px;font-weight:750;white-space:nowrap}.shield{display:grid;place-items:center;width:34px;height:34px;border-radius:10px;background:linear-gradient(145deg,#245f58,#183c54);color:#caffed;font-size:12px;letter-spacing:.5px}nav{display:flex;gap:6px;flex:1}nav a{padding:8px 11px;border-radius:9px;color:var(--muted)}nav a:hover{background:var(--panel);color:var(--text)}.account{display:flex;align-items:center;gap:12px;color:var(--muted)}main{max-width:1180px;margin:0 auto;padding:42px 28px 64px}.public{min-height:100vh;display:grid;place-items:center;padding:24px}.auth-card{width:min(430px,100%);background:rgba(17,25,37,.96);border:1px solid var(--line);border-radius:20px;padding:30px;box-shadow:var(--shadow)}h1{font-size:30px;line-height:1.15;margin:0 0 10px}h2{font-size:18px;margin:0 0 12px}p{color:var(--muted);margin:0 0 20px}.hero{display:flex;justify-content:space-between;gap:20px;align-items:flex-start;margin-bottom:24px}.eyebrow{text-transform:uppercase;letter-spacing:.13em;color:var(--accent);font-size:11px;font-weight:800;margin-bottom:8px}.status{border:1px solid var(--line);padding:8px 12px;border-radius:999px;font-weight:700}.status.good{color:var(--accent);border-color:#285c4d;background:#102b24}.status.bad{color:var(--danger);border-color:#673838;background:#2a1518}.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:14px}.metric,.panel{background:linear-gradient(160deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow)}.metric{padding:19px}.metric span{display:block;color:var(--muted);font-size:12px;margin-bottom:5px}.metric strong{font-size:24px}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.panel{padding:20px;margin-bottom:14px}.link-panel{transition:transform .15s,border-color .15s}.link-panel:hover{transform:translateY(-2px);border-color:#37506e}.page-head{display:flex;justify-content:space-between;margin-bottom:22px}.page-head p{margin:0}form{margin:0}label{display:flex;flex-direction:column;gap:7px;color:var(--muted);font-size:13px;margin:14px 0}input{width:100%;background:#0b121c;border:1px solid var(--line);border-radius:10px;color:var(--text);padding:11px 12px;outline:none}input:focus{border-color:#3d7d72;box-shadow:0 0 0 3px rgba(90,208,165,.09)}button,.button{display:inline-flex;align-items:center;justify-content:center;border:0;border-radius:10px;padding:11px 15px;background:var(--accent);color:#07120e;font-weight:800;cursor:pointer}.button.secondary,button.ghost{background:#1a2839;color:var(--text);border:1px solid var(--line)}button.danger{background:#382126;color:#ffb3b3;border:1px solid #66383f}.small{padding:7px 10px;font-size:12px}.form-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;align-items:end}.form-grid label{margin:0}.form-grid .wide{grid-column:span 2}.error{border:1px solid #60343c;background:#2a171b;color:#ffb0b0;border-radius:11px;padding:12px 14px;margin:14px 0}.muted{color:var(--muted)}.table-wrap{overflow:auto;padding:0}table{border-collapse:collapse;width:100%;min-width:760px}th,td{text-align:left;padding:13px 15px;border-bottom:1px solid var(--line);vertical-align:middle}th{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}tr:last-child td{border-bottom:0}code{font:12px ui-monospace,SFMono-Regular,Consolas,monospace;color:#bbd6ef}
@media(max-width:850px){header{height:auto;min-height:64px;flex-wrap:wrap;padding:13px 16px;gap:10px}nav{order:3;width:100%;overflow:auto}.account{margin-left:auto}main{padding:28px 16px}.metrics,.grid{grid-template-columns:1fr}.form-grid{grid-template-columns:1fr}.form-grid .wide{grid-column:auto}.hero{flex-direction:column}}
`